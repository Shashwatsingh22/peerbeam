package transport

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/discovery"
)

// AttemptRecord is one rung of the ladder that did not hold: the Transport that
// was tried and why it failed. Reason is never empty, because Req 2.5 wants the
// failure report to name a reason per Transport, not just a list of names.
type AttemptRecord struct {
	TransportName string
	Reason        string
}

// String renders one attempt for a failure report.
func (a AttemptRecord) String() string {
	return a.TransportName + ": " + a.Reason
}

// ConnectedResult is the successful branch of a ladder: the live connection plus
// the Transport that produced it. The Transport comes back too because the caller
// needs its chunk size (Req 7.10) and its expected goodput (the switch rule table
// in Req 2.8 compares against the active Transport's figure).
type ConnectedResult struct {
	Connection TransportConnection
	Transport  Transport
}

// LadderResult is a tagged result: exactly one of Connected / AllFailed /
// NoCandidate holds. Go has no sealed sum type, so the invariant is stated rather
// than enforced. Callers MUST check NoCandidate and AllFailed before reading
// Connected.
//
// The three branches map one-to-one onto three requirement outcomes:
//
//	Connected   -> a Session proceeds to the handshake
//	AllFailed   -> Req 2.5: no Session, report naming every attempt in order
//	NoCandidate -> Req 2.6: no Session, report that no Transport is available
//
// AllFailed and NoCandidate are kept apart rather than collapsed into an empty
// attempt list because the two produce different operator-facing reports, and a
// caller that had to distinguish them by `len(AllFailed) == 0` would be one
// refactor away from conflating them.
type LadderResult struct {
	Connected   *ConnectedResult
	AllFailed   []AttemptRecord // in attempt order, one entry per candidate (Req 2.5)
	NoCandidate bool            // Req 2.6
}

// Summary renders the failure branches for a report. It returns "" for a
// successful ladder, so a caller can log unconditionally.
func (r LadderResult) Summary() string {
	switch {
	case r.Connected != nil:
		return ""
	case r.NoCandidate:
		return "no transport available for peer"
	default:
		parts := make([]string, 0, len(r.AllFailed))
		for _, a := range r.AllFailed {
			parts = append(parts, a.String())
		}
		return "all transports failed: " + strings.Join(parts, "; ")
	}
}

// EndpointLookup resolves the address to dial for one Transport. It returns false
// when the Peer has no endpoint on that Transport's medium, which the ladder
// records as an attempt with a reason rather than silently skipping, so the
// report in Req 2.5 accounts for every candidate.
//
// It is a function rather than a map so the caller can read straight out of
// discovery.PeerRegistry without first materialising a per-Transport map.
type EndpointLookup func(Transport) (discovery.PeerEndpoint, bool)

// ConnectLadder walks ranked candidates in order and returns on the first
// success. It is the whole of Requirements 2.3 through 2.6 and, with a longer
// perAttemptTimeout, of Req 3.8:
//
//   - highest ranked candidate first, since `ranked` is already ordered (Req 2.3)
//   - exactly one attempt open at a time, guaranteed by the sequential loop and
//     the fact that nothing here spawns a goroutine (Req 2.3)
//   - one attempt per candidate, bounded by perAttemptTimeout, and no retry of an
//     already attempted Transport, guaranteed by a single pass over `ranked`
//     (Req 2.4)
//   - on total failure, an AttemptRecord per candidate in attempt order (Req 2.5)
//   - on an empty candidate list, the NoCandidate branch (Req 2.6)
//
// perAttemptTimeout is a parameter rather than a constant because the same ladder
// serves first connection at ConnectAttemptTimeout (3 s, Req 2.4) and rebind at
// RebindAttemptTimeout (5 s, Req 3.8). A non-positive value is treated as
// ConnectAttemptTimeout rather than as "no timeout", since an unbounded attempt
// would violate Req 2.4 outright.
//
// The timeout is applied twice on purpose: once as a context deadline and once as
// the explicit timeout argument. Transport implementations differ in which one
// they can honour (a raw socket dial takes a duration, a shim call watches the
// context), so both are supplied and whichever fires first ends the attempt.
//
// If ctx is already done, every candidate still gets an attempt and a record.
// That is deliberate: a well-behaved Connect returns the context error
// immediately, so the caller gets a complete, honest report instead of a
// truncated one.
func ConnectLadder(
	ctx context.Context,
	ranked []Transport,
	endpointFor EndpointLookup,
	perAttemptTimeout time.Duration,
) LadderResult {
	if len(ranked) == 0 {
		return LadderResult{NoCandidate: true} // Req 2.6
	}
	if perAttemptTimeout <= 0 {
		perAttemptTimeout = ConnectAttemptTimeout
	}
	if endpointFor == nil {
		// No way to resolve any endpoint. Report it per candidate rather than
		// panicking, so the caller still gets the Req 2.5 shaped report.
		endpointFor = func(Transport) (discovery.PeerEndpoint, bool) {
			return discovery.PeerEndpoint{}, false
		}
	}

	attempts := make([]AttemptRecord, 0, len(ranked))
	for _, t := range ranked {
		if t == nil {
			continue // wiring bug, not a candidate; nothing to name in a report
		}
		endpoint, ok := endpointFor(t)
		if !ok {
			attempts = append(attempts, AttemptRecord{t.Name(), "no endpoint for peer on this medium"})
			continue
		}

		// Fresh deadline per attempt. cancel is called before the next iteration
		// rather than deferred, so at most one attempt context is live at a time
		// and none of them outlive the loop.
		attemptCtx, cancel := context.WithTimeout(ctx, perAttemptTimeout)
		conn, err := t.Connect(attemptCtx, endpoint, perAttemptTimeout)
		cancel()

		switch {
		case err != nil:
			attempts = append(attempts, AttemptRecord{t.Name(), describeConnectError(err, perAttemptTimeout)})
		case conn == nil:
			// A Transport that reports success without a connection is broken.
			// Treated as a failed rung so the ladder never returns a Connected
			// branch holding a nil connection.
			attempts = append(attempts, AttemptRecord{t.Name(), "transport returned no connection and no error"})
		default:
			return LadderResult{Connected: &ConnectedResult{Connection: conn, Transport: t}}
		}
	}
	return LadderResult{AllFailed: attempts} // Req 2.5
}

// describeConnectError turns a Connect error into the non-empty reason Req 2.5
// requires. A deadline overrun is named as the timeout it exceeded, because
// "context deadline exceeded" tells an operator nothing about which bound was hit.
func describeConnectError(err error, perAttemptTimeout time.Duration) string {
	switch {
	case err == nil:
		return "unknown failure"
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Sprintf("did not connect within %s", perAttemptTimeout)
	case errors.Is(err, context.Canceled):
		return "attempt cancelled"
	}
	if msg := strings.TrimSpace(err.Error()); msg != "" {
		return msg
	}
	return "unknown failure"
}
