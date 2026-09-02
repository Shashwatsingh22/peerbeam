package transport

import (
	"testing"

	"pgregory.net/rapid"
)

// TestProperty16KeepaliveMarksUnavailableOnExactlyTheThirdConsecutiveMiss covers
// Property 16: Keepalive marks a Transport unavailable on exactly the third
// consecutive miss.
//
// Validates: Requirements 3.1, 3.2
func TestProperty16KeepaliveMarksUnavailableOnExactlyTheThirdConsecutiveMiss(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		k := NewKeepaliveTracker()
		if k.Threshold() != KeepaliveStrikeThreshold {
			rt.Fatalf("threshold %d, want %d", k.Threshold(), KeepaliveStrikeThreshold)
		}
		if k.Misses() != 0 || k.Unavailable() {
			rt.Fatalf("fresh tracker is not healthy: misses=%d unavailable=%v",
				k.Misses(), k.Unavailable())
		}

		// true = keepalive answered inside the 2-second window, false = missed.
		outcomes := rapid.SliceOfN(rapid.Bool(), 0, 30).Draw(rt, "keepaliveOutcomes")

		// The oracle counts consecutive misses without a cap, so the assertions
		// below cannot be satisfied by the implementation's own capping.
		consecutive := 0
		for step, answered := range outcomes {
			if answered {
				k.OnResponse()
				consecutive = 0
				// A response always clears the slate, even after two misses.
				if k.Misses() != 0 {
					rt.Fatalf("step %d: response left %d misses", step, k.Misses())
				}
				if k.Unavailable() {
					rt.Fatalf("step %d: unavailable after a response", step)
				}
				continue
			}

			consecutive++
			gotUnavailable := k.OnTimeout()
			wantUnavailable := consecutive >= KeepaliveStrikeThreshold

			if gotUnavailable != wantUnavailable {
				rt.Fatalf("step %d: %d consecutive misses reported unavailable=%v, want %v",
					step, consecutive, gotUnavailable, wantUnavailable)
			}
			if k.Unavailable() != wantUnavailable {
				rt.Fatalf("step %d: Unavailable() disagrees with OnTimeout()", step)
			}

			wantMisses := consecutive
			if wantMisses > KeepaliveStrikeThreshold {
				wantMisses = KeepaliveStrikeThreshold
			}
			if k.Misses() != wantMisses {
				rt.Fatalf("step %d: misses=%d, want %d", step, k.Misses(), wantMisses)
			}
		}

		// Reset returns the tracker to the state a fresh binding starts in, which
		// is what a rebind needs (Req 3.4 keeps the Session, not the strike count).
		k.Reset()
		if k.Misses() != 0 || k.Unavailable() {
			rt.Fatalf("after reset: misses=%d unavailable=%v", k.Misses(), k.Unavailable())
		}
	})
}

// TestKeepaliveTwoMissesThenResponseIsNotFatal is the case Req 3.2 turns on: the
// counter is consecutive, so a lossy link that still answers never gets marked
// unavailable.
//
// Requirements: 3.2
func TestKeepaliveTwoMissesThenResponseIsNotFatal(t *testing.T) {
	k := NewKeepaliveTracker()
	for round := 0; round < 5; round++ {
		if k.OnTimeout() {
			t.Fatalf("round %d: unavailable after 1 miss", round)
		}
		if k.OnTimeout() {
			t.Fatalf("round %d: unavailable after 2 misses", round)
		}
		k.OnResponse()
		if k.Misses() != 0 {
			t.Fatalf("round %d: response left %d misses", round, k.Misses())
		}
	}
	// The third *consecutive* miss is what marks it, and only then.
	k.OnTimeout()
	k.OnTimeout()
	if k.Unavailable() {
		t.Fatal("unavailable before the third consecutive miss")
	}
	if !k.OnTimeout() {
		t.Fatal("third consecutive miss did not mark the transport unavailable")
	}
}
