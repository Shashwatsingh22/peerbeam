package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Group send bounds, fixed by Requirements 4.4, 4.5, and 4.7.
const (
	// GroupSendLimit is the largest selectable group (Req 4.4), which matches the
	// concurrent Session ceiling: a group cannot usefully exceed the number of
	// Sessions that can exist.
	GroupSendLimit = MaxConcurrentSessions
	// GroupSendTimeout bounds the whole fan-out, not each peer (Req 4.5, 4.7).
	GroupSendTimeout = 10 * time.Second
)

// ErrSessionNotActive tells SendToGroup that a selected Peer has no active Session,
// which Req 4.8 turns into: report not delivered, and queue the Message on that
// Session.
var ErrSessionNotActive = errors.New("session not active")

// GroupTarget is one selected Peer. DisplayName is carried because Req 4.5 and 4.7
// both require the outcome to name the Peer, and a fingerprint is not a name.
type GroupTarget struct {
	Fingerprint string
	DisplayName string
}

// name is what an outcome reports for this target, falling back to the fingerprint
// so an outcome is never anonymous.
func (t GroupTarget) name() string {
	if t.DisplayName != "" {
		return t.DisplayName
	}
	if t.Fingerprint != "" {
		return t.Fingerprint
	}
	return "unknown peer"
}

// GroupDispatcher is everything SendToGroup needs from the rest of the node. It is
// an interface so the fan-out is testable with no Transport: the concurrency rules
// in Req 4.5 and 4.7 are about outcomes and deadlines, not about sockets.
type GroupDispatcher interface {
	// Send delivers payload on the active Session for fingerprint and returns the
	// sequence number that Session consumed. It returns ErrSessionNotActive when
	// the Peer has no active Session, and honours ctx as the delivery deadline.
	//
	// Implementations must draw the sequence number from that Session's own
	// tracker (Req 4.4), which is why the number comes back rather than going in.
	Send(ctx context.Context, fingerprint string, payload []byte) (uint64, error)
	// Queue retains payload on the Session of an inactive Peer (Req 4.8).
	Queue(fingerprint string, payload []byte) QueueResult
}

// DeliveryOutcome is a tagged result: exactly one of Delivered / NotDelivered is
// set. Every selected Peer gets exactly one of these (Req 4.7).
type DeliveryOutcome struct {
	Delivered    *DeliveredOutcome
	NotDelivered *NotDeliveredOutcome
}

// DeliveredOutcome names the Peer and the sequence number its Session consumed.
type DeliveredOutcome struct {
	Peer     string
	Sequence uint64
}

// NotDeliveredOutcome names the Peer and why delivery did not happen (Req 4.5, 4.8).
// Reason is never empty.
type NotDeliveredOutcome struct {
	Peer   string
	Reason string
	// Queued reports whether the Message was retained for a later flush, which is
	// what Req 4.8 requires for an inactive Session. It is false for a Peer whose
	// Session was active but did not acknowledge.
	Queued bool
}

// String renders one outcome for the report Req 4.7 asks for.
func (o DeliveryOutcome) String() string {
	switch {
	case o.Delivered != nil:
		return fmt.Sprintf("%s: delivered as sequence %d", o.Delivered.Peer, o.Delivered.Sequence)
	case o.NotDelivered != nil:
		return fmt.Sprintf("%s: not delivered (%s)", o.NotDelivered.Peer, o.NotDelivered.Reason)
	default:
		return "invalid outcome"
	}
}

// Peer names the Peer this outcome is about.
func (o DeliveryOutcome) Peer() string {
	switch {
	case o.Delivered != nil:
		return o.Delivered.Peer
	case o.NotDelivered != nil:
		return o.NotDelivered.Peer
	default:
		return ""
	}
}

// SendToGroup fans a Message out to the selected Peers and returns exactly one
// outcome per Peer, in the order the Peers were selected, within GroupSendTimeout
// (Req 4.4, 4.5, 4.7, 4.8).
//
// One goroutine per Peer under a single shared deadline. The deadline is shared
// rather than per-Peer because Req 4.7 bounds the *report*: one slow Peer must not
// push the whole report past 10 seconds, and giving each Peer its own 10-second
// window would allow exactly that if they were serialised. Nothing here serialises
// them, but a shared deadline makes the bound hold by construction rather than by
// argument.
//
// Each goroutine writes to its own slice element, so the fan-in needs no mutex: the
// WaitGroup is the only synchronisation, and it happens-after every write.
//
// A Peer whose Session is not active is reported not delivered and has its Message
// queued (Req 4.8), while the active Peers' deliveries carry on regardless (Req 4.5).
func SendToGroup(
	ctx context.Context,
	targets []GroupTarget,
	payload []byte,
	dispatcher GroupDispatcher,
) []DeliveryOutcome {
	outcomes := make([]DeliveryOutcome, len(targets))
	if len(targets) == 0 {
		return outcomes
	}
	if dispatcher == nil {
		// Still one outcome per Peer: a wiring failure must not produce a report
		// with Peers missing from it.
		for i, t := range targets {
			outcomes[i] = notDelivered(t, "no dispatcher configured", false)
		}
		return outcomes
	}

	sendCtx, cancel := context.WithTimeout(ctx, GroupSendTimeout)
	defer cancel()

	var wg sync.WaitGroup
	for i, target := range targets {
		// Req 4.4 selects "up to 8" Peers. Anything past the limit is reported
		// rather than silently dropped, so the outcome count still matches the
		// selection exactly.
		if i >= GroupSendLimit {
			outcomes[i] = notDelivered(target,
				fmt.Sprintf("group exceeds the limit of %d peers", GroupSendLimit), false)
			continue
		}
		if target.Fingerprint == "" {
			outcomes[i] = notDelivered(target, "peer has no fingerprint", false)
			continue
		}

		wg.Add(1)
		go func(slot int, t GroupTarget) {
			defer wg.Done()
			outcomes[slot] = deliverOne(sendCtx, t, payload, dispatcher)
		}(i, target)
	}
	wg.Wait()

	return outcomes
}

// deliverOne is one Peer's share of the fan-out. It is separate so the outcome
// mapping is readable in one screen and so a panic in a dispatcher affects one
// goroutine's stack rather than a nested closure.
func deliverOne(
	ctx context.Context,
	target GroupTarget,
	payload []byte,
	dispatcher GroupDispatcher,
) DeliveryOutcome {
	sequence, err := dispatcher.Send(ctx, target.Fingerprint, payload)
	if err == nil {
		return DeliveryOutcome{Delivered: &DeliveredOutcome{
			Peer:     target.name(),
			Sequence: sequence,
		}}
	}

	switch {
	case errors.Is(err, ErrSessionNotActive):
		// Req 4.8: retain the Message on that Session and report not delivered.
		result := dispatcher.Queue(target.Fingerprint, payload)
		if result.Queued {
			return notDelivered(target, "session not active; message queued", true)
		}
		reason := result.Reason()
		if reason == "" {
			reason = "session not active; message not queued"
		} else {
			reason = "session not active; " + reason
		}
		return notDelivered(target, reason, false)

	case errors.Is(err, context.DeadlineExceeded):
		// Req 4.5: the 10-second acknowledgement window elapsed.
		return notDelivered(target,
			fmt.Sprintf("no acknowledgement within %s", GroupSendTimeout), false)

	case errors.Is(err, context.Canceled):
		return notDelivered(target, "send cancelled", false)

	default:
		return notDelivered(target, err.Error(), false)
	}
}

func notDelivered(target GroupTarget, reason string, queued bool) DeliveryOutcome {
	if reason == "" {
		reason = "unknown failure"
	}
	return DeliveryOutcome{NotDelivered: &NotDeliveredOutcome{
		Peer:   target.name(),
		Reason: reason,
		Queued: queued,
	}}
}
