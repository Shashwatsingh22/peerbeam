package session

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"pgregory.net/rapid"
)

// peerBehaviour is one selected Peer's acknowledgement schedule in Property 19.
type peerBehaviour uint8

const (
	// peerAcks has an active Session that acknowledges, consuming a sequence
	// number from that Session's own tracker (Req 4.4).
	peerAcks peerBehaviour = iota
	// peerSilent has an active Session that never acknowledges inside the
	// 10-second window (Req 4.5).
	peerSilent
	// peerInactive has a Session that is not active, so its Message is queued
	// (Req 4.8).
	peerInactive
	// peerUnknown has no Session at all, which is also not-active as far as the
	// dispatcher is concerned.
	peerUnknown
)

func (b peerBehaviour) String() string {
	switch b {
	case peerAcks:
		return "acks"
	case peerSilent:
		return "silent"
	case peerInactive:
		return "inactive"
	default:
		return "unknown"
	}
}

// fakeDispatcher is a GroupDispatcher backed by a real SessionRegistry, so the
// per-Session sequence and queue assertions in Property 19 are made against the
// real types rather than a model of them.
//
// The timeout branch is simulated by returning a wrapped context.DeadlineExceeded
// instead of blocking: GroupSendTimeout is a fixed 10 seconds, and a test that
// actually waited it out would take 10 seconds per case. What is under test is the
// mapping from a missed acknowledgement to an outcome, which the wrapped error
// exercises exactly.
type fakeDispatcher struct {
	registry *SessionRegistry
	schedule map[string]peerBehaviour

	mu        sync.Mutex
	sendCalls map[string]int
	queued    map[string][][]byte
}

func newFakeDispatcher(r *SessionRegistry, schedule map[string]peerBehaviour) *fakeDispatcher {
	return &fakeDispatcher{
		registry:  r,
		schedule:  schedule,
		sendCalls: map[string]int{},
		queued:    map[string][][]byte{},
	}
}

func (d *fakeDispatcher) Send(ctx context.Context, fingerprint string, _ []byte) (uint64, error) {
	d.mu.Lock()
	d.sendCalls[fingerprint]++
	behaviour := d.schedule[fingerprint]
	d.mu.Unlock()

	s := d.registry.FindActive(fingerprint)
	if s == nil {
		return 0, ErrSessionNotActive
	}
	if behaviour == peerSilent {
		// No sequence number is consumed: Req 5.1 assigns one when the Message is
		// sent, and a Message that was never acknowledged still went out, so this
		// models the acknowledgement timing out after the send.
		return 0, fmt.Errorf("%w: %v", context.DeadlineExceeded, errNoAcknowledgement)
	}

	// The registry hands out distinct Sessions per fingerprint, so each goroutine
	// touches its own tracker. The mutex is here so the race detector has nothing
	// to complain about if a caller ever selects the same Peer twice.
	d.mu.Lock()
	defer d.mu.Unlock()
	return s.Sequence.NextSequence(), nil
}

func (d *fakeDispatcher) Queue(fingerprint string, payload []byte) QueueResult {
	d.mu.Lock()
	d.queued[fingerprint] = append(d.queued[fingerprint], payload)
	d.mu.Unlock()

	s := d.registry.Find(fingerprint)
	if s == nil {
		// No Session exists, so there is nowhere to retain the Message. Reported
		// honestly rather than pretending it was queued.
		return QueueResult{}
	}
	return s.Queue.Submit(QueuedMessage{Sequence: s.Sequence.NextSequence(), Payload: payload})
}

func (d *fakeDispatcher) queuedFor(fingerprint string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.queued[fingerprint])
}

// TestProperty19GroupSendProducesExactlyOneOutcomePerSelectedPeer covers
// Property 19: A group send produces exactly one outcome per selected Peer.
//
// Validates: Requirements 4.4, 4.5, 4.7, 4.8
func TestProperty19GroupSendProducesExactlyOneOutcomePerSelectedPeer(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		r := NewSessionRegistry(newManualClock())

		groupSize := rapid.IntRange(0, GroupSendLimit).Draw(rt, "groupSize")
		schedule := map[string]peerBehaviour{}
		targets := make([]GroupTarget, 0, groupSize)

		for i := 0; i < groupSize; i++ {
			fp := fmt.Sprintf("fp%02d", i)
			behaviour := rapid.SampledFrom([]peerBehaviour{
				peerAcks, peerSilent, peerInactive, peerUnknown,
			}).Draw(rt, "behaviour"+string(rune('a'+i)))
			schedule[fp] = behaviour
			targets = append(targets, GroupTarget{Fingerprint: fp, DisplayName: "peer-" + fp})

			switch behaviour {
			case peerAcks, peerSilent:
				mustAdmit(rt, r, fp)
			case peerInactive:
				mustAdmit(rt, r, fp)
				r.Find(fp).MarkDisconnected()
			case peerUnknown:
				// no Session at all
			}
		}

		// Sessions that are not in the group at all: Req 4.4 must leave their
		// counters alone.
		bystanders := map[string]uint64{}
		for i := groupSize; i < GroupSendLimit; i++ {
			fp := fmt.Sprintf("bystander%02d", i)
			mustAdmit(rt, r, fp)
			bystanders[fp] = r.Find(fp).Sequence.PeekNextSequence()
		}

		// Record each in-group Session's counter before the send.
		counterBefore := map[string]uint64{}
		for fp := range schedule {
			if s := r.Find(fp); s != nil {
				counterBefore[fp] = s.Sequence.PeekNextSequence()
			}
		}

		dispatcher := newFakeDispatcher(r, schedule)
		outcomes := SendToGroup(context.Background(), targets, []byte("hello"), dispatcher)

		// Req 4.7: exactly one outcome per selected Peer, and no others.
		if len(outcomes) != len(targets) {
			rt.Fatalf("%d outcomes for %d selected peers", len(outcomes), len(targets))
		}

		for i, outcome := range outcomes {
			target := targets[i]
			behaviour := schedule[target.Fingerprint]

			// Exactly one branch, always naming the Peer.
			if (outcome.Delivered == nil) == (outcome.NotDelivered == nil) {
				rt.Fatalf("peer %s: outcome sets %v/%v, want exactly one",
					target.Fingerprint, outcome.Delivered, outcome.NotDelivered)
			}
			if outcome.Peer() != target.DisplayName {
				rt.Fatalf("outcome %d names %q, want %q", i, outcome.Peer(), target.DisplayName)
			}

			switch behaviour {
			case peerAcks:
				if outcome.Delivered == nil {
					rt.Fatalf("peer %s acknowledged but was reported %q",
						target.Fingerprint, outcome.NotDelivered.Reason)
				}
				// Req 4.4: the Session's own next sequence number was consumed.
				want := counterBefore[target.Fingerprint]
				if outcome.Delivered.Sequence != want {
					rt.Fatalf("peer %s delivered as sequence %d, want its own next %d",
						target.Fingerprint, outcome.Delivered.Sequence, want)
				}
				if now := r.Find(target.Fingerprint).Sequence.PeekNextSequence(); now != want+1 {
					rt.Fatalf("peer %s counter is %d, want %d", target.Fingerprint, now, want+1)
				}

			case peerSilent:
				// Req 4.5: not delivered, with a reason naming the failure.
				if outcome.NotDelivered == nil {
					rt.Fatalf("silent peer %s was reported delivered", target.Fingerprint)
				}
				if !strings.Contains(outcome.NotDelivered.Reason, "acknowledgement") {
					rt.Fatalf("silent peer %s reason %q does not name the missed acknowledgement",
						target.Fingerprint, outcome.NotDelivered.Reason)
				}

			case peerInactive:
				// Req 4.8: not delivered, and the Message retained on that Session.
				if outcome.NotDelivered == nil {
					rt.Fatalf("inactive peer %s was reported delivered", target.Fingerprint)
				}
				if !outcome.NotDelivered.Queued {
					rt.Fatalf("inactive peer %s: message was not queued (%q)",
						target.Fingerprint, outcome.NotDelivered.Reason)
				}
				if q := r.Find(target.Fingerprint).Queue; q.Len() != 1 {
					rt.Fatalf("inactive peer %s holds %d queued messages, want 1",
						target.Fingerprint, q.Len())
				}
				if dispatcher.queuedFor(target.Fingerprint) != 1 {
					rt.Fatalf("inactive peer %s: queue was called %d times, want 1",
						target.Fingerprint, dispatcher.queuedFor(target.Fingerprint))
				}

			case peerUnknown:
				if outcome.NotDelivered == nil {
					rt.Fatalf("peer %s has no session but was reported delivered",
						target.Fingerprint)
				}
			}

			if outcome.NotDelivered != nil &&
				strings.TrimSpace(outcome.NotDelivered.Reason) == "" {
				rt.Fatalf("peer %s: not-delivered outcome carries no reason", target.Fingerprint)
			}
		}

		// Req 4.4: Sessions outside the group are untouched.
		for fp, want := range bystanders {
			if got := r.Find(fp).Sequence.PeekNextSequence(); got != want {
				rt.Fatalf("bystander %s counter moved %d -> %d", fp, want, got)
			}
			if r.Find(fp).Queue.Len() != 0 {
				rt.Fatalf("bystander %s had a message queued", fp)
			}
		}

		// A silent Peer's Session is still active afterwards: Req 4.5 continues
		// delivery to the rest rather than tearing anything down.
		for fp, behaviour := range schedule {
			if behaviour == peerSilent && r.FindActive(fp) == nil {
				rt.Fatalf("silent peer %s lost its active session", fp)
			}
		}
	})
}

// TestSendToGroupReportsPeersBeyondTheLimit checks that a selection larger than
// Req 4.4 allows still yields one outcome per Peer, with the excess named rather
// than silently dropped.
//
// Requirements: 4.4, 4.7
func TestSendToGroupReportsPeersBeyondTheLimit(t *testing.T) {
	r := NewSessionRegistry(newManualClock())
	schedule := map[string]peerBehaviour{}
	var targets []GroupTarget
	for i := 0; i < GroupSendLimit+3; i++ {
		fp := fmt.Sprintf("fp%02d", i)
		schedule[fp] = peerAcks
		targets = append(targets, GroupTarget{Fingerprint: fp, DisplayName: "peer-" + fp})
		if i < GroupSendLimit {
			mustAdmit(t, r, fp)
		}
	}

	outcomes := SendToGroup(context.Background(), targets, []byte("hi"), newFakeDispatcher(r, schedule))
	if len(outcomes) != len(targets) {
		t.Fatalf("%d outcomes for %d peers", len(outcomes), len(targets))
	}
	for i := GroupSendLimit; i < len(outcomes); i++ {
		if outcomes[i].NotDelivered == nil {
			t.Fatalf("peer %d beyond the limit was reported delivered", i)
		}
		if !strings.Contains(outcomes[i].NotDelivered.Reason, "limit of 8") {
			t.Fatalf("peer %d reason %q does not name the limit", i, outcomes[i].NotDelivered.Reason)
		}
	}
}

// TestSendToGroupWithNoTargetsOrNoDispatcher covers the two degenerate inputs. Both
// must still satisfy Req 4.7's one-outcome-per-Peer count.
//
// Requirements: 4.7
func TestSendToGroupWithNoTargetsOrNoDispatcher(t *testing.T) {
	if got := SendToGroup(context.Background(), nil, []byte("hi"), nil); len(got) != 0 {
		t.Fatalf("empty selection produced %d outcomes", len(got))
	}

	targets := []GroupTarget{
		{Fingerprint: "a", DisplayName: "peer-a"},
		{Fingerprint: "b", DisplayName: "peer-b"},
	}
	got := SendToGroup(context.Background(), targets, []byte("hi"), nil)
	if len(got) != 2 {
		t.Fatalf("%d outcomes for 2 peers", len(got))
	}
	for i, o := range got {
		if o.NotDelivered == nil {
			t.Fatalf("outcome %d reported delivered with no dispatcher", i)
		}
		if o.Peer() != targets[i].DisplayName {
			t.Fatalf("outcome %d names %q, want %q", i, o.Peer(), targets[i].DisplayName)
		}
	}
}

// TestSendToGroupOutcomeNamesTheFingerprintWhenNoDisplayNameIsKnown checks that an
// outcome is never anonymous, which Req 4.5 and 4.7 both depend on.
//
// Requirements: 4.5, 4.7
func TestSendToGroupOutcomeNamesTheFingerprintWhenNoDisplayNameIsKnown(t *testing.T) {
	r := NewSessionRegistry(newManualClock())
	mustAdmit(t, r, "abc123")
	schedule := map[string]peerBehaviour{"abc123": peerAcks}

	got := SendToGroup(context.Background(),
		[]GroupTarget{{Fingerprint: "abc123"}}, []byte("hi"), newFakeDispatcher(r, schedule))

	if got[0].Peer() != "abc123" {
		t.Fatalf("outcome names %q, want the fingerprint", got[0].Peer())
	}
	if !strings.Contains(got[0].String(), "abc123") {
		t.Fatalf("rendered outcome %q does not name the peer", got[0].String())
	}
}

// TestSendToGroupQueueRejectionIsReportedNotHidden covers the case where an inactive
// Peer's retention queue is already full: Req 4.8 wants the Message retained, and
// when it cannot be, the outcome must say so rather than claim it was queued.
//
// Requirements: 4.8, 3.10
func TestSendToGroupQueueRejectionIsReportedNotHidden(t *testing.T) {
	r := NewSessionRegistry(newManualClock())
	mustAdmit(t, r, "full")
	s := r.Find("full")
	s.MarkDisconnected()
	// Shrink the budget so a small payload overflows it.
	s.Queue = newOutboundQueueWithLimit(newManualClock(), 1)

	got := SendToGroup(context.Background(),
		[]GroupTarget{{Fingerprint: "full", DisplayName: "peer-full"}},
		[]byte("more than one byte"),
		newFakeDispatcher(r, map[string]peerBehaviour{"full": peerInactive}))

	if got[0].NotDelivered == nil {
		t.Fatal("reported delivered on a full queue")
	}
	if got[0].NotDelivered.Queued {
		t.Fatal("reported queued when the queue rejected the message")
	}
	if !strings.Contains(got[0].NotDelivered.Reason, "retention limit") {
		t.Fatalf("reason %q does not name the retention limit", got[0].NotDelivered.Reason)
	}
}
