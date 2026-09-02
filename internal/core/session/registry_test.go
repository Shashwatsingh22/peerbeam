package session

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// registryOp is one step of the generated lifecycle sequence in Property 18.
type registryOp uint8

const (
	opAdmit registryOp = iota
	opDisconnect
	opClose
	opReadmit
)

// TestProperty18SessionsAreBoundedAndMutuallyIsolated covers
// Property 18: Sessions are bounded and mutually isolated.
//
// Validates: Requirements 4.1, 4.2, 4.3, 4.9
func TestProperty18SessionsAreBoundedAndMutuallyIsolated(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		clk := newManualClock()
		r := NewSessionRegistry(clk)

		// A pool of fingerprints larger than the limit, so the generated sequence
		// reaches the Req 4.9 rejection without being steered there.
		fingerprints := make([]string, 0, 12)
		for i := 0; i < 12; i++ {
			fingerprints = append(fingerprints, fmt.Sprintf("fp%02d", i))
		}

		ops := rapid.SliceOfN(rapid.SampledFrom([]registryOp{
			opAdmit, opAdmit, opAdmit, opDisconnect, opClose, opReadmit,
		}), 1, 40).Draw(rt, "ops")

		// Ids and key material seen across the whole run, including Sessions that
		// have since closed: reusing either would be an isolation failure even
		// after the fact.
		seenIds := map[SessionId]struct{}{}

		for step, op := range ops {
			fp := rapid.SampledFrom(fingerprints).Draw(rt, fmt.Sprintf("fp%d", step))

			// Snapshot every other Session, so Req 4.3 can be checked against the
			// operation that follows.
			before := map[SessionId]sessionFacts{}
			for _, s := range r.All() {
				before[s.Id] = factsFor(s)
			}

			switch op {
			case opAdmit, opReadmit:
				countBefore := r.Len()
				got := r.Admit(admissionFor(fp))

				switch got.Kind() {
				case AdmissionAdmitted:
					if countBefore >= MaxConcurrentSessions {
						rt.Fatalf("step %d: admitted while %d sessions were active",
							step, countBefore)
					}
					if _, reused := seenIds[*got.Admitted]; reused {
						rt.Fatalf("step %d: session id %s reused", step, *got.Admitted)
					}
					seenIds[*got.Admitted] = struct{}{}
					delete(before, *got.Admitted) // the new Session has no "before"

				case AdmissionLimitReached:
					// Req 4.9: the limit of 8 is named, and nothing changed.
					if *got.LimitReached != MaxConcurrentSessions {
						rt.Fatalf("step %d: limit reported as %d, want %d",
							step, *got.LimitReached, MaxConcurrentSessions)
					}
					if !strings.Contains(got.Reason(), "8") {
						rt.Fatalf("step %d: reason %q does not name the limit",
							step, got.Reason())
					}
					if r.Len() != countBefore {
						rt.Fatalf("step %d: rejection changed the session count %d -> %d",
							step, countBefore, r.Len())
					}

				case AdmissionDuplicateSession:
					// Req 4.1: Sessions are held with distinct Peers.
					if r.Find(fp) == nil {
						rt.Fatalf("step %d: duplicate reported for unknown peer %s", step, fp)
					}
					if r.Len() != countBefore {
						rt.Fatalf("step %d: duplicate rejection changed the count", step)
					}

				default:
					rt.Fatalf("step %d: unexpected admission %s: %s",
						step, got.Kind(), got.Reason())
				}

			case opDisconnect:
				s := r.Find(fp)
				if s == nil {
					continue
				}
				s.MarkDisconnected()
				delete(before, s.Id)
				// Req 3.6: a disconnected Session keeps its slot, since it still
				// holds an identifier, keys, and a retention queue.
				if r.Get(s.Id) == nil {
					rt.Fatalf("step %d: disconnect removed the session from the registry", step)
				}
				if r.FindActive(fp) != nil {
					rt.Fatalf("step %d: disconnected session still reported active", step)
				}

			case opClose:
				s := r.Find(fp)
				if s == nil {
					continue
				}
				id := s.Id
				delete(before, id)
				if !r.Close(id, "test") {
					rt.Fatalf("step %d: closing known session %s reported not found", step, id)
				}
				if r.Get(id) != nil {
					rt.Fatalf("step %d: closed session %s still in the registry", step, id)
				}
				if s.State() != StateClosed {
					rt.Fatalf("step %d: closed session is in state %s", step, s.State())
				}
				// A second close is detectable rather than silent.
				if r.Close(id, "test") {
					rt.Fatalf("step %d: closing %s twice reported success", step, id)
				}
			}

			// Req 4.1 and 4.9: the ceiling is never exceeded, whatever happened.
			if r.Len() > MaxConcurrentSessions {
				rt.Fatalf("step %d: %d concurrent sessions, limit is %d",
					step, r.Len(), MaxConcurrentSessions)
			}

			// Req 4.3: every Session other than the one operated on is untouched.
			for id, was := range before {
				s := r.Get(id)
				if s == nil {
					rt.Fatalf("step %d: unrelated session %s disappeared", step, id)
				}
				if now := factsFor(s); now != was {
					rt.Fatalf("step %d: unrelated session %s changed\n before %+v\n after  %+v",
						step, id, was, now)
				}
			}

			// Req 4.1 and 4.2: distinct ids, distinct key material, own channels.
			assertMutualIsolation(rt, r)
		}
	})
}

// assertMutualIsolation checks the structural half of Property 18 over the current
// registry contents.
func assertMutualIsolation(t rapid.TB, r *SessionRegistry) {
	t.Helper()

	ids := map[SessionId]struct{}{}
	keys := map[string]struct{}{}
	inbound := map[chan Message]struct{}{}
	outbound := map[chan Message]struct{}{}

	for _, s := range r.All() {
		if _, dup := ids[s.Id]; dup {
			t.Fatalf("two sessions share id %s", s.Id)
		}
		ids[s.Id] = struct{}{}

		if len(s.Keys) == 0 {
			t.Fatalf("session %s holds no key material", s.Id)
		}
		if _, dup := keys[string(s.Keys)]; dup {
			t.Fatalf("two sessions share key material")
		}
		keys[string(s.Keys)] = struct{}{}

		if s.Inbound == nil || s.Outbound == nil || s.Control == nil {
			t.Fatalf("session %s is missing a channel", s.Id)
		}
		if _, dup := inbound[s.Inbound]; dup {
			t.Fatalf("two sessions share an inbound channel")
		}
		inbound[s.Inbound] = struct{}{}
		if _, dup := outbound[s.Outbound]; dup {
			t.Fatalf("two sessions share an outbound channel")
		}
		outbound[s.Outbound] = struct{}{}

		if s.Sequence == nil || s.Queue == nil {
			t.Fatalf("session %s is missing sequence state or a queue", s.Id)
		}
	}
}

// TestAdmitRejectsTheNinthSession pins Req 4.9 with fixed input: the eight existing
// Sessions keep their state, and the error names the limit.
//
// Requirements: 4.1, 4.9
func TestAdmitRejectsTheNinthSession(t *testing.T) {
	r := NewSessionRegistry(newManualClock())

	before := make([]sessionFacts, 0, MaxConcurrentSessions)
	for i := 0; i < MaxConcurrentSessions; i++ {
		id := mustAdmit(t, r, fmt.Sprintf("peer%d", i))
		before = append(before, factsFor(r.Get(id)))
	}

	got := r.Admit(admissionFor("peer-nine"))
	if got.Kind() != AdmissionLimitReached {
		t.Fatalf("ninth session got %s, want limit reached", got.Kind())
	}
	if *got.LimitReached != 8 {
		t.Fatalf("limit reported as %d, want 8", *got.LimitReached)
	}
	if !strings.Contains(got.Reason(), "limit of 8") {
		t.Fatalf("reason %q does not name the limit of 8", got.Reason())
	}
	if r.Len() != MaxConcurrentSessions {
		t.Fatalf("registry holds %d sessions after rejection, want 8", r.Len())
	}
	for i, was := range before {
		if now := factsFor(r.Get(was.id)); now != was {
			t.Fatalf("session %d changed on rejection\n before %+v\n after  %+v", i, was, now)
		}
	}
	// The rejected Peer has no Session at all.
	if r.Find("peer-nine") != nil {
		t.Fatal("rejected peer holds a session")
	}
}

// TestAdmitRequiresTrustedByteIdenticalKeys pins the two trust branches (Req 9.6,
// 9.7) and the precedence of trust over capacity.
//
// Requirements: 9.6, 9.7
func TestAdmitRequiresTrustedByteIdenticalKeys(t *testing.T) {
	r := NewSessionRegistry(newManualClock())

	untrusted := admissionFor("stranger")
	untrusted.StoredKey = nil
	got := r.Admit(untrusted)
	if got.Kind() != AdmissionPeerNotTrusted || got.PeerNotTrusted != "stranger" {
		t.Fatalf("untrusted peer got %s (%q)", got.Kind(), got.Reason())
	}
	if r.Len() != 0 {
		t.Fatal("untrusted peer created a session")
	}

	mismatch := admissionFor("impostor")
	mismatch.PresentedKey = []byte("a-different-key")
	got = r.Admit(mismatch)
	if got.Kind() != AdmissionKeyMismatch || got.KeyMismatch != "impostor" {
		t.Fatalf("key mismatch got %s (%q)", got.Kind(), got.Reason())
	}
	if r.Len() != 0 {
		t.Fatal("key mismatch created a session")
	}

	// Trust is decided before capacity: a full registry plus an untrusted peer
	// reports the trust problem, which is the actionable one.
	for i := 0; i < MaxConcurrentSessions; i++ {
		mustAdmit(t, r, fmt.Sprintf("peer%d", i))
	}
	got = r.Admit(untrusted)
	if got.Kind() != AdmissionPeerNotTrusted {
		t.Fatalf("full registry plus untrusted peer got %s, want peer not trusted", got.Kind())
	}
}

// TestAdmitRejectsASecondSessionForOnePeer pins the Req 4.1 reading that the eight
// Sessions are held with distinct Peers.
//
// Requirements: 4.1
func TestAdmitRejectsASecondSessionForOnePeer(t *testing.T) {
	r := NewSessionRegistry(newManualClock())
	first := mustAdmit(t, r, "peer")

	got := r.Admit(admissionFor("peer"))
	if got.Kind() != AdmissionDuplicateSession {
		t.Fatalf("second session for one peer got %s, want duplicate", got.Kind())
	}
	if *got.DuplicateSession != first {
		t.Fatalf("duplicate names %s, want the existing %s", *got.DuplicateSession, first)
	}
	if r.Len() != 1 {
		t.Fatalf("registry holds %d sessions, want 1", r.Len())
	}

	// Closing frees the Peer for a new, differently identified Session.
	r.Close(first, "test")
	second := mustAdmit(t, r, "peer")
	if second == first {
		t.Fatal("re-admitted peer reused the closed session id")
	}
}

// TestAdmitRejectsMalformedRequests covers the wiring-failure branch, which must
// never create a half-built Session.
//
// Requirements: 4.1
func TestAdmitRejectsMalformedRequests(t *testing.T) {
	r := NewSessionRegistry(newManualClock())

	cases := map[string]func(*AdmissionRequest){
		"no fingerprint":   func(a *AdmissionRequest) { a.Fingerprint = "" },
		"no presented key": func(a *AdmissionRequest) { a.PresentedKey = nil },
		"no key material":  func(a *AdmissionRequest) { a.Keys = nil },
	}
	for name, mangle := range cases {
		t.Run(name, func(t *testing.T) {
			req := admissionFor("peer")
			mangle(&req)
			got := r.Admit(req)
			if got.Kind() != AdmissionFailed {
				t.Fatalf("got %s, want failed", got.Kind())
			}
			if strings.TrimSpace(got.Reason()) == "" {
				t.Fatal("failure carries no reason")
			}
			if r.Len() != 0 {
				t.Fatal("malformed request created a session")
			}
		})
	}
}

// TestAdmitCopiesKeyMaterial checks that a caller reusing its key buffer cannot
// mutate a live Session's keys.
//
// Requirements: 4.1
func TestAdmitCopiesKeyMaterial(t *testing.T) {
	r := NewSessionRegistry(newManualClock())
	req := admissionFor("peer", 1, 2, 3, 4)
	got := r.Admit(req)
	if got.Admitted == nil {
		t.Fatalf("admission failed: %s", got.Reason())
	}
	req.Keys[0] = 0xff

	s := r.Get(*got.Admitted)
	if s.Keys[0] != 1 {
		t.Fatalf("session key material follows the caller's buffer: %v", s.Keys)
	}
}

// TestAdmitReportsAnEntropyFailure checks that a failing id source stops Session
// creation rather than producing a weak or empty id.
//
// Requirements: 4.1
func TestAdmitReportsAnEntropyFailure(t *testing.T) {
	r := NewSessionRegistry(newManualClock())
	r.newId = func() (SessionId, error) { return "", errors.New("entropy source unavailable") }

	got := r.Admit(admissionFor("peer"))
	if got.Kind() != AdmissionFailed {
		t.Fatalf("got %s, want failed", got.Kind())
	}
	if !strings.Contains(got.Reason(), "entropy") {
		t.Fatalf("reason %q does not name the cause", got.Reason())
	}
	if r.Len() != 0 {
		t.Fatal("failed admission left a session behind")
	}
}

// TestNewSessionIdIsDistinctAndHex pins the identifier shape: 128 bits of hex, and
// no repeats across a run.
//
// Requirements: 4.1
func TestNewSessionIdIsDistinctAndHex(t *testing.T) {
	seen := map[SessionId]struct{}{}
	for i := 0; i < 256; i++ {
		id, err := NewSessionId()
		if err != nil {
			t.Fatalf("NewSessionId: %v", err)
		}
		if len(id) != SessionIdBytes*2 {
			t.Fatalf("id %q is %d chars, want %d", id, len(id), SessionIdBytes*2)
		}
		if strings.Trim(string(id), "0123456789abcdef") != "" {
			t.Fatalf("id %q is not lowercase hex", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("id %q generated twice in 256 draws", id)
		}
		seen[id] = struct{}{}
	}
}

// TestRebindPreservesEverythingReq34Names is the session-level half of Req 3.4: a
// Transport change moves the Transport name and nothing else.
//
// Requirements: 3.4
func TestRebindPreservesEverythingReq34Names(t *testing.T) {
	r := NewSessionRegistry(newManualClock())
	id := mustAdmit(t, r, "peer")
	s := r.Get(id)
	s.Rebind("LAN_Transport")

	// Give the Session some sequence state to lose.
	first := s.Sequence.NextSequence()
	s.Sequence.AcceptInbound(7)
	before := factsFor(s)

	s.MarkDisconnected()
	s.MarkReconnected("BT_Transport")
	s.Rebind("BT_Transport")

	after := factsFor(s)
	if after.id != before.id {
		t.Fatalf("session id changed %s -> %s", before.id, after.id)
	}
	if after.keys != before.keys {
		t.Fatal("session keys changed across a rebind")
	}
	if after.nextOutbound != before.nextOutbound {
		t.Fatalf("outbound counter changed %d -> %d", before.nextOutbound, after.nextOutbound)
	}
	if after.inboundCount != before.inboundCount {
		t.Fatal("inbound sequence state changed across a rebind")
	}
	if s.ActiveTransportName != "BT_Transport" {
		t.Fatalf("active transport is %q, want BT_Transport", s.ActiveTransportName)
	}
	if next := s.Sequence.NextSequence(); next != first+1 {
		t.Fatalf("next sequence after rebind is %d, want %d", next, first+1)
	}
}
