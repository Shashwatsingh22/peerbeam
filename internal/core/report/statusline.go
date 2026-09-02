package report

import (
	"fmt"
	"time"
)

// StatusRefreshInterval is how often the status display redraws (Req 13.1, 13.2).
const StatusRefreshInterval = time.Second

// ReadyStatus is the four values Req 13.1 requires a Session's status row to show.
type ReadyStatus struct {
	PeerDisplayName       string
	ActiveTransportName   string
	GoodputBytesPerSecond int64
	RoundTripMillis       int64
}

func (s ReadyStatus) String() string {
	return fmt.Sprintf("%s\t%s\t%d B/s\t%d ms",
		s.PeerDisplayName, s.ActiveTransportName, s.GoodputBytesPerSecond, s.RoundTripMillis)
}

// StatusLine is a tagged result: exactly one of Ready / Pending is set (Req 13.1, 13.2).
//
// Pending carries only the Session id, and that is the whole design. Req 13.2 says a Session
// missing any one of the four values shows a pending state "in place of all four values",
// so the pending branch must have nowhere to keep a partial figure. A struct with four
// optional fields would let a caller render three of them by accident.
type StatusLine struct {
	Ready   *ReadyStatus
	Pending *string // the Session id
}

// StatusKind names the branch a status line took.
type StatusKind uint8

const (
	StatusReady StatusKind = iota
	StatusPending
	// StatusInvalid means no branch was set. BuildStatusLine never returns it.
	StatusInvalid
)

func (k StatusKind) String() string {
	switch k {
	case StatusReady:
		return "ready"
	case StatusPending:
		return "pending"
	default:
		return "invalid"
	}
}

// Kind reports which single branch of the status line holds.
func (s StatusLine) Kind() StatusKind {
	switch {
	case s.Ready != nil:
		return StatusReady
	case s.Pending != nil:
		return StatusPending
	default:
		return StatusInvalid
	}
}

// String renders the row. A pending Session shows its id and the word pending, so the row
// exists in the table without claiming any measurement.
func (s StatusLine) String() string {
	switch s.Kind() {
	case StatusReady:
		return s.Ready.String()
	case StatusPending:
		return fmt.Sprintf("%s\tpending", *s.Pending)
	default:
		return "invalid status line"
	}
}

// BuildStatusLine renders a Session's status row all-or-nothing (Req 13.1, 13.2).
//
// The four values arrive as pointers because each is genuinely absent until it exists: a
// Session that has not yet sampled its goodput has no goodput, and zero is a real
// measurement rather than a stand-in for "unknown". Passing plain int64s would make the two
// indistinguishable, and the row would show 0 B/s for a Session that had simply not measured
// yet.
//
// An empty peer display name or transport name counts as absent for the same reason: a blank
// column is not a value.
func BuildStatusLine(
	sessionId string,
	peerDisplayName, activeTransportName *string,
	goodputBytesPerSecond, roundTripMillis *int64,
) StatusLine {
	havePeer := peerDisplayName != nil && *peerDisplayName != ""
	haveTransport := activeTransportName != nil && *activeTransportName != ""
	haveGoodput := goodputBytesPerSecond != nil
	haveRTT := roundTripMillis != nil

	if havePeer && haveTransport && haveGoodput && haveRTT {
		return StatusLine{Ready: &ReadyStatus{
			PeerDisplayName:       *peerDisplayName,
			ActiveTransportName:   *activeTransportName,
			GoodputBytesPerSecond: *goodputBytesPerSecond,
			RoundTripMillis:       *roundTripMillis,
		}}
	}

	id := sessionId
	return StatusLine{Pending: &id}
}

// Missing lists which of the four values were unavailable, for a caller that wants to say
// why a row is pending. It is not part of the rendered row: Req 13.2 shows a pending state,
// not a list of gaps.
func Missing(
	peerDisplayName, activeTransportName *string,
	goodputBytesPerSecond, roundTripMillis *int64,
) []string {
	var missing []string
	if peerDisplayName == nil || *peerDisplayName == "" {
		missing = append(missing, "peer display name")
	}
	if activeTransportName == nil || *activeTransportName == "" {
		missing = append(missing, "active transport name")
	}
	if goodputBytesPerSecond == nil {
		missing = append(missing, "measured goodput")
	}
	if roundTripMillis == nil {
		missing = append(missing, "measured round-trip time")
	}
	return missing
}
