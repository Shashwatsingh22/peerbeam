package session

import (
	"bytes"
	"fmt"

	"github.com/peerbeam/peerbeam/internal/core/clock"
)

// InboundChannelDepth and OutboundChannelDepth size the per-Session queues that
// Req 4.2 requires. They are buffered so a momentary stall on one Session does not
// block the reader that feeds it, and small so a stalled Session applies
// backpressure instead of growing without bound: the disconnected-state retention
// budget in OutboundQueue is where bulk buffering belongs, not here.
const (
	InboundChannelDepth  = 32
	OutboundChannelDepth = 32
)

// KeyMaterial is the opaque per-Session key bytes. This package never interprets
// it; internal/core/crypto derives it from the handshake and the registry only
// needs it to be present and distinct per Session, which is half of what Req 4.1
// means by each Session holding its own negotiated keys.
type KeyMaterial []byte

// Equal compares key material in the obvious way. It exists so isolation checks
// read clearly, not as a security primitive: nothing here is constant-time,
// because nothing here compares a secret against attacker-supplied input.
func (k KeyMaterial) Equal(other KeyMaterial) bool { return bytes.Equal(k, other) }

// State is where a Session sits in its lifecycle. Only these three exist: the
// Connecting and Handshaking phases belong to establishment, which happens before
// the registry holds a Session at all.
type State uint8

const (
	// StateActive is a Session with a live Transport binding (Req 4.1).
	StateActive State = iota
	// StateDisconnected is a Session with no candidate Transport, retaining
	// queued outbound payload for 10 minutes (Req 3.6).
	StateDisconnected
	// StateClosed is terminal. A closed Session is removed from the registry and
	// never reused; a later request from the same Peer gets a new SessionId.
	StateClosed
)

func (s State) String() string {
	switch s {
	case StateActive:
		return "active"
	case StateDisconnected:
		return "disconnected"
	case StateClosed:
		return "closed"
	default:
		return fmt.Sprintf("State(%d)", uint8(s))
	}
}

// Message is one item on a Session's inbound or outbound channel. It carries the
// wire type code and the already-framed payload, so a Session moves bytes without
// knowing what they mean: text, clipboard, and transfer all use the same path.
type Message struct {
	Type     uint8
	Sequence uint64
	Payload  []byte
	// Control marks a Message that must overtake bulk traffic. Req 4.6 needs a
	// text Message to stay responsive while a Transfer saturates the same
	// Session, which the writer implements by preferring this channel.
	Control bool
}

// Session is everything one peer relationship owns. Req 4.1 lists the four things
// that must be per-Session, and they are the four fields at the top: identifier,
// negotiated keys, Message sequence state, and active Transport.
//
// Nothing in this struct is shared with another Session. That is the whole point:
// Req 4.2 and 4.3 require one Session to send, stall, rebind, or disconnect
// without touching any other, and the only shared state in the package is the
// registry map, which is touched on admit and close and never on the message path.
//
// A Session is not safe for concurrent mutation. One owning goroutine per Session
// drives it, which is how the design avoids a lock on the hot path.
type Session struct {
	// Id is fixed for the life of the Session and survives every Transport
	// change (Req 3.4).
	Id SessionId
	// Keys is the negotiated key material, distinct per Session (Req 4.1).
	Keys KeyMaterial
	// Sequence is this Session's own outbound counter and inbound duplicate set
	// (Req 4.1, 5.1, 5.10).
	Sequence *SequenceTracker
	// ActiveTransportName is the Transport the Session is bound to right now. It
	// changes on a rebind while everything else above stays put (Req 3.4).
	ActiveTransportName string

	// Peer identity. Fingerprint is the key the registry indexes on; DisplayName
	// is what a report shows (Req 4.5, 4.7 both name the Peer).
	Fingerprint string
	DisplayName string

	// Inbound and Outbound are this Session's own queues (Req 4.2). Control is
	// separate from Outbound so the writer can prefer it (Req 4.6).
	Inbound  chan Message
	Outbound chan Message
	Control  chan Message

	// Queue retains outbound payload while the Session is disconnected
	// (Req 3.6, 3.7, 3.9, 3.10).
	Queue *OutboundQueue

	state State
}

// newSession builds an active Session with its own channels, sequence state, and
// retention queue. It is unexported because a Session only ever comes from
// SessionRegistry.Admit, which is what enforces the concurrency limit.
func newSession(id SessionId, fingerprint, displayName string, keys KeyMaterial, clk clock.Clock) *Session {
	return &Session{
		Id:          id,
		Keys:        keys,
		Sequence:    NewSequenceTracker(),
		Fingerprint: fingerprint,
		DisplayName: displayName,
		Inbound:     make(chan Message, InboundChannelDepth),
		Outbound:    make(chan Message, OutboundChannelDepth),
		Control:     make(chan Message, OutboundChannelDepth),
		Queue:       NewOutboundQueue(clk),
		state:       StateActive,
	}
}

// State reports the Session's lifecycle state.
func (s *Session) State() State { return s.state }

// IsActive reports whether the Session currently holds a live Transport binding.
func (s *Session) IsActive() bool { return s.state == StateActive }

// MarkDisconnected moves an active Session to the disconnected state (Req 3.6).
// It is a no-op on a closed Session, so a late failover decision cannot resurrect
// one.
func (s *Session) MarkDisconnected() {
	if s.state == StateClosed {
		return
	}
	s.state = StateDisconnected
	s.ActiveTransportName = ""
}

// MarkReconnected moves a disconnected Session back to active on the named
// Transport (Req 3.7). The sequence state and keys are untouched, which is what
// lets the retained queue flush in order onto the new binding.
func (s *Session) MarkReconnected(transportName string) {
	if s.state == StateClosed {
		return
	}
	s.state = StateActive
	s.ActiveTransportName = transportName
}

// Rebind points the Session at another Transport (Req 3.3). Everything Req 3.4
// promises to preserve is deliberately left alone here: only the Transport name
// moves.
func (s *Session) Rebind(transportName string) {
	if s.state == StateClosed {
		return
	}
	s.state = StateActive
	s.ActiveTransportName = transportName
}

// close marks the Session terminal and releases its channels. Closing the channels
// is what unblocks the Session's own goroutines; the registry has already dropped
// the entry by the time this runs, so no other Session is affected (Req 4.3).
func (s *Session) close() {
	if s.state == StateClosed {
		return
	}
	s.state = StateClosed
	s.ActiveTransportName = ""
	close(s.Inbound)
	close(s.Outbound)
	close(s.Control)
}
