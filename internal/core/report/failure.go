package report

import (
	"fmt"
	"strings"
)

// Failure is the shape every user-visible failure takes (Req 13.4). All four fields are
// required, and Complete is what checks that.
//
// Remediation is the field that makes this type worth having. A report that says what broke
// without saying what to do about it leaves the user to guess, so Req 13.4 asks for one
// remediation step naming a user action, and Describe below is the single place that
// guarantees every failure kind has one.
type Failure struct {
	Operation       string
	PeerDisplayName string
	Reason          string
	Remediation     string
}

// Complete reports whether all four fields are non-empty (Req 13.4).
func (f Failure) Complete() bool {
	return strings.TrimSpace(f.Operation) != "" &&
		strings.TrimSpace(f.PeerDisplayName) != "" &&
		strings.TrimSpace(f.Reason) != "" &&
		strings.TrimSpace(f.Remediation) != ""
}

// Missing lists the empty fields, so a caller that built an incomplete Failure is told
// which ones rather than just that it failed.
func (f Failure) Missing() []string {
	var missing []string
	if strings.TrimSpace(f.Operation) == "" {
		missing = append(missing, "operation")
	}
	if strings.TrimSpace(f.PeerDisplayName) == "" {
		missing = append(missing, "peer display name")
	}
	if strings.TrimSpace(f.Reason) == "" {
		missing = append(missing, "reason")
	}
	if strings.TrimSpace(f.Remediation) == "" {
		missing = append(missing, "remediation")
	}
	return missing
}

func (f Failure) String() string {
	return fmt.Sprintf("%s failed for %s: %s\n  try: %s",
		f.Operation, f.PeerDisplayName, f.Reason, f.Remediation)
}

// UnknownPeer is the display name used when a failure happens before the Peer's name is
// known. Req 13.4 requires the report to name the affected Peer, and a blank there would
// make the report incomplete; this at least says the name was unavailable rather than
// leaving an empty column.
const UnknownPeer = "unknown peer"

// PeerName falls back through display name, fingerprint, and UnknownPeer, so a report is
// never anonymous.
func PeerName(displayName, fingerprint string) string {
	if displayName != "" {
		return displayName
	}
	if fingerprint != "" {
		return fingerprint
	}
	return UnknownPeer
}

// TransportChangeReason is the closed set of reasons a Session may change Transport
// (Req 13.3). Exactly three, nothing vaguer.
//
// The point of a closed set is that a user reading "transport changed" learns something.
// An open string field would fill up with variations of "network problem", which is what
// Req 13.3 is written to prevent.
type TransportChangeReason uint8

const (
	// ReasonPreviousUnavailable is a rebind after keepalive struck the old Transport out
	// (Req 3.2, 3.3).
	ReasonPreviousUnavailable TransportChangeReason = iota
	// ReasonHigherRankedAvailable is a rank-based upgrade (Req 2.8).
	ReasonHigherRankedAvailable
	// ReasonUserPinned is a change the user asked for (Req 2.10).
	ReasonUserPinned
)

func (r TransportChangeReason) String() string {
	switch r {
	case ReasonPreviousUnavailable:
		return "the previous transport was marked unavailable"
	case ReasonHigherRankedAvailable:
		return "a higher ranked transport became available"
	case ReasonUserPinned:
		return "the user pinned the session to a named transport"
	default:
		return ""
	}
}

// Valid reports whether the reason is one of the three defined values. A decoded or
// hand-built value outside the set is rejected rather than rendered as a number.
func (r TransportChangeReason) Valid() bool {
	return r <= ReasonUserPinned
}

// TransportChangeReasons is the closed set, for iterating in tests and in the CLI help.
func TransportChangeReasons() []TransportChangeReason {
	return []TransportChangeReason{
		ReasonPreviousUnavailable,
		ReasonHigherRankedAvailable,
		ReasonUserPinned,
	}
}

// TransportChange is the Req 13.3 report: which Transport the Session left, which it
// joined, and why.
type TransportChange struct {
	SessionId         string
	PeerDisplayName   string
	PreviousTransport string
	NewTransport      string
	Reason            TransportChangeReason
}

// Complete reports whether the change names both Transports and carries a valid reason.
func (c TransportChange) Complete() bool {
	return c.PreviousTransport != "" && c.NewTransport != "" && c.Reason.Valid()
}

func (c TransportChange) String() string {
	return fmt.Sprintf("session %s with %s moved from %s to %s: %s",
		c.SessionId, PeerName(c.PeerDisplayName, ""), c.PreviousTransport,
		c.NewTransport, c.Reason)
}

// StallIndication is the Req 13.6 report: a Transfer whose acknowledged byte count has not
// moved for ten seconds. It names all four values the requirement lists.
type StallIndication struct {
	TransferId            string
	ActiveTransportName   string
	GoodputBytesPerSecond int64
	RoundTripMillis       int64
}

func (s StallIndication) String() string {
	return fmt.Sprintf("transfer %s stalled on %s: last measured %d B/s, %d ms round trip",
		s.TransferId, s.ActiveTransportName, s.GoodputBytesPerSecond, s.RoundTripMillis)
}

// DegradedThroughput is the Req 11.8 report: measured goodput stayed under the active
// Transport's target for a continuous ten-second window.
type DegradedThroughput struct {
	ActiveTransportName    string
	MeasuredBytesPerSecond int64
	TargetBytesPerSecond   int64
}

func (d DegradedThroughput) String() string {
	return fmt.Sprintf("throughput on %s degraded: measured %d B/s against a target of %d B/s",
		d.ActiveTransportName, d.MeasuredBytesPerSecond, d.TargetBytesPerSecond)
}

// AsFailure renders degraded throughput as a Failure. Req 11.9 requires the Transfer to
// continue and the Session to stay active, so this is a report and not a termination: there
// is nothing here that could stop either.
func (d DegradedThroughput) AsFailure(peerDisplayName string) Failure {
	return Failure{
		Operation:       "transfer file",
		PeerDisplayName: PeerName(peerDisplayName, ""),
		Reason:          d.String(),
		Remediation: "move the machines closer together, or check for other traffic on the " +
			"network; the transfer continues in the meantime",
	}
}
