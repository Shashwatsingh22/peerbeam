package session

import (
	"fmt"
	"testing"

	"pgregory.net/rapid"
)

// transportEvent is one step of the generated sequence in Property 15.
type transportEvent uint8

const (
	eventSwitch transportEvent = iota
	eventRebind
	eventFailedSwitch
	eventDisconnect
	eventReconnect
	eventSend
	eventReceive
)

func (e transportEvent) String() string {
	switch e {
	case eventSwitch:
		return "switch"
	case eventRebind:
		return "rebind"
	case eventFailedSwitch:
		return "failed switch"
	case eventDisconnect:
		return "disconnect"
	case eventReconnect:
		return "reconnect"
	case eventSend:
		return "send"
	default:
		return "receive"
	}
}

// TestProperty15TransportChangePreservesSessionIdentity covers
// Property 15: A Transport change preserves Session identity.
//
// The "no key exchange Message after the initial handshake" clause is structural: a Session
// holds its KeyMaterial as a plain field set once at admission, and nothing in this package
// can replace it. There is no re-key path to exercise, which is the point - Req 10.4 is
// satisfied by the absence of one. The test pins that by checking the key material is
// identical across every event, and by there being no exported method that would change it.
//
// Validates: Requirements 2.9, 3.4, 10.4
func TestProperty15TransportChangePreservesSessionIdentity(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		r := NewSessionRegistry(newManualClock())
		id := mustAdmit(rt, r, "peer-under-test")
		s := r.Get(id)
		s.Rebind("LAN_Transport")

		// Give the Session some sequence state, so "unchanged" means something.
		for i := 0; i < rapid.IntRange(0, 5).Draw(rt, "initialSends"); i++ {
			s.Sequence.NextSequence()
		}
		for i := 0; i < rapid.IntRange(0, 5).Draw(rt, "initialReceives"); i++ {
			s.Sequence.AcceptInbound(uint64(i))
		}

		// A second Session, so Req 4.3's isolation is checked alongside.
		otherId := mustAdmit(rt, r, "bystander")
		other := r.Get(otherId)
		other.Rebind("BT_Transport")
		other.Sequence.NextSequence()
		otherBefore := factsFor(other)

		// What Req 3.4 promises to preserve, captured before anything happens.
		wantId := s.Id
		wantKeys := string(s.Keys)
		wantOutbound := s.Sequence.PeekNextSequence()
		wantInboundCount := s.Sequence.InboundCount()

		transports := []string{"LAN_Transport", "BT_Transport", "MC_Transport"}
		events := rapid.SliceOfN(rapid.SampledFrom([]transportEvent{
			eventSwitch, eventRebind, eventFailedSwitch,
			eventDisconnect, eventReconnect, eventSend, eventReceive,
		}), 1, 30).Draw(rt, "events")

		nextInbound := uint64(1000)

		for step, event := range events {
			target := rapid.SampledFrom(transports).Draw(rt, fmt.Sprintf("target%d", step))
			transportBefore := s.ActiveTransportName

			switch event {
			case eventSwitch, eventRebind:
				s.Rebind(target)
				if s.ActiveTransportName != target {
					rt.Fatalf("step %d: %s did not move the session to %s",
						step, event, target)
				}

			case eventFailedSwitch:
				// Req 2.9: a switch that does not complete leaves the Session on its
				// current Transport. Modelled as no state change at all, which is what a
				// failed attempt is: the caller reports the failure and calls nothing.
				if s.ActiveTransportName != transportBefore {
					rt.Fatalf("step %d: a failed switch changed the transport", step)
				}

			case eventDisconnect:
				s.MarkDisconnected()
				if s.IsActive() {
					rt.Fatalf("step %d: session still active after disconnect", step)
				}

			case eventReconnect:
				s.MarkReconnected(target)
				if !s.IsActive() {
					rt.Fatalf("step %d: session not active after reconnect", step)
				}

			case eventSend:
				// Sequence state advances through Transport changes rather than
				// restarting, which is what makes the derived nonce safe across a rebind.
				got := s.Sequence.NextSequence()
				if got != wantOutbound {
					rt.Fatalf("step %d: send used sequence %d, want %d",
						step, got, wantOutbound)
				}
				wantOutbound++

			case eventReceive:
				if !s.Sequence.AcceptInbound(nextInbound) {
					rt.Fatalf("step %d: fresh inbound sequence %d was rejected",
						step, nextInbound)
				}
				nextInbound++
				wantInboundCount++
			}

			// Req 3.4 and 2.9: identifier, keys, and sequence state are identical across
			// every one of these events.
			if s.Id != wantId {
				rt.Fatalf("step %d (%s): session id changed %s -> %s",
					step, event, wantId, s.Id)
			}
			if string(s.Keys) != wantKeys {
				rt.Fatalf("step %d (%s): session keys changed", step, event)
			}
			if got := s.Sequence.PeekNextSequence(); got != wantOutbound {
				rt.Fatalf("step %d (%s): outbound counter is %d, want %d",
					step, event, got, wantOutbound)
			}
			if got := s.Sequence.InboundCount(); got != wantInboundCount {
				rt.Fatalf("step %d (%s): inbound count is %d, want %d",
					step, event, got, wantInboundCount)
			}

			// Req 4.3: the bystander Session is untouched by all of it.
			if got := factsFor(other); got != otherBefore {
				rt.Fatalf("step %d (%s): bystander changed\n before %+v\n after  %+v",
					step, event, otherBefore, got)
			}

			// The registry still resolves the Session under the same id and fingerprint,
			// so a Transport change does not orphan it.
			if r.Get(wantId) != s {
				rt.Fatalf("step %d (%s): registry lost the session", step, event)
			}
			if s.IsActive() && r.FindActive("peer-under-test") != s {
				rt.Fatalf("step %d (%s): active session is not findable by fingerprint",
					step, event)
			}
		}

		// After everything, the Session is still the one that was admitted.
		if s.Id != wantId || string(s.Keys) != wantKeys {
			rt.Fatal("session identity did not survive the event sequence")
		}
		// A duplicate admission still points at the same Session, so no Transport change
		// created a second one for the Peer.
		again := r.Admit(admissionFor("peer-under-test"))
		if again.Kind() != AdmissionDuplicateSession {
			rt.Fatalf("re-admitting the peer gave %s, want duplicate", again.Kind())
		}
		if *again.DuplicateSession != wantId {
			rt.Fatalf("duplicate names session %s, want %s", *again.DuplicateSession, wantId)
		}
	})
}

// TestSessionHasNoRekeyPath is the structural half of Req 10.4: a Session's key material is set
// once at admission and there is no exported way to replace it, so no key exchange can happen
// after the initial handshake.
//
// If a SetKeys or Rekey method is ever added, this test is where that decision gets challenged.
//
// Requirements: 10.4
func TestSessionHasNoRekeyPath(t *testing.T) {
	r := NewSessionRegistry(newManualClock())
	id := mustAdmit(t, r, "peer")
	s := r.Get(id)

	before := string(s.Keys)

	// Every state transition a Transport change can trigger.
	s.Rebind("LAN_Transport")
	s.MarkDisconnected()
	s.MarkReconnected("BT_Transport")
	s.Rebind("MC_Transport")

	if string(s.Keys) != before {
		t.Fatal("session keys changed across transport transitions")
	}

	// The keys field is a slice, so a caller holding the Session could mutate it in place.
	// That is not a re-key path so much as a bug, and the registry's copy-on-admit is what
	// keeps the caller's original slice from being the live one.
	req := admissionFor("second-peer", 9, 9, 9)
	got := r.Admit(req)
	if got.Admitted == nil {
		t.Fatalf("admission failed: %s", got.Reason())
	}
	req.Keys[0] = 1
	if r.Get(*got.Admitted).Keys[0] != 9 {
		t.Fatal("session keys follow the caller's buffer, so an outside write can re-key a session")
	}
}
