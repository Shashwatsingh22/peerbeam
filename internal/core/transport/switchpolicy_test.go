package transport

import (
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// baseTime anchors every generated timestamp. A fixed instant keeps failures
// reproducible and makes the offsets below readable as "N seconds ago".
var baseTime = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

// offsetChoices straddles both thresholds in Req 2.8 from either side, including
// the exact boundary values, since >= against > is precisely the kind of mistake
// a purely random generator would take thousands of runs to find.
var offsetChoices = []time.Duration{
	0,
	1 * time.Second,
	UpgradeStability - time.Nanosecond,
	UpgradeStability,
	UpgradeStability + time.Second,
	UpgradeCooldown - time.Nanosecond,
	UpgradeCooldown,
	UpgradeCooldown + time.Second,
	5 * time.Minute,
}

// candidateNameChoices includes "" for "no candidate remains" and a third name so
// the rule table is not accidentally satisfied by there being only two Transports.
var candidateNameChoices = []string{"", NameLAN, NameBT, "MC_Transport"}

// countSetFields reports how many branches of a decision are set. The tagged
// result promises exactly one.
func countSetFields(d SwitchDecision) int {
	n := 0
	if d.Stay {
		n++
	}
	if d.Upgrade != "" {
		n++
	}
	if d.Rebind != "" {
		n++
	}
	if d.GoDisconnected != "" {
		n++
	}
	return n
}

// TestProperty14SwitchDecisionFollowsExactlyOneRuleTable covers
// Property 14: The switch decision follows exactly one rule table.
//
// The check is decomposed into the clauses Property 14 states rather than run
// against a reimplementation of DecideSwitch, so a bug copied into an oracle
// cannot pass unnoticed.
//
// Validates: Requirements 2.8, 2.10, 2.11, 3.3
func TestProperty14SwitchDecisionFollowsExactlyOneRuleTable(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		var availableSince *time.Time
		if rapid.Bool().Draw(rt, "candidateHasAvailabilityRecord") {
			since := baseTime.Add(-rapid.SampledFrom(offsetChoices).Draw(rt, "availableFor"))
			availableSince = &since
		}

		in := SwitchInputs{
			ActiveTransportName:         rapid.SampledFrom([]string{NameLAN, NameBT}).Draw(rt, "activeName"),
			ActiveExpectedGoodput:       rapid.SampledFrom(goodputChoices).Draw(rt, "activeGoodput"),
			BestCandidateName:           rapid.SampledFrom(candidateNameChoices).Draw(rt, "bestName"),
			BestCandidateGoodput:        rapid.SampledFrom(goodputChoices).Draw(rt, "bestGoodput"),
			BestCandidateAvailableSince: availableSince,
			LastTransportChangeAt:       baseTime.Add(-rapid.SampledFrom(offsetChoices).Draw(rt, "sinceLastChange")),
			PinnedTransportName:         rapid.SampledFrom(candidateNameChoices).Draw(rt, "pin"),
			ActiveIsAvailable:           rapid.Bool().Draw(rt, "activeIsAvailable"),
			ActiveUnavailableReason:     rapid.SampledFrom([]string{"", "keepalive missed 3 times"}).Draw(rt, "unavailableReason"),
			Now:                         baseTime,
		}

		d := DecideSwitch(in)

		// The result is a tagged union: exactly one branch, always a known kind.
		if got := countSetFields(d); got != 1 {
			rt.Fatalf("%d branches set in %+v, want exactly 1", got, d)
		}
		if d.Kind() == DecisionInvalid {
			rt.Fatalf("decision %+v has no kind", d)
		}
		if d.Kind() == DecisionGoDisconnected && strings.TrimSpace(d.GoDisconnected) == "" {
			rt.Fatalf("disconnect decision carries a blank reason")
		}

		// Same snapshot, same decision. DecideSwitch reads no clock and no state.
		if again := DecideSwitch(in); again != d {
			rt.Fatalf("not deterministic: %+v then %+v", d, again)
		}

		pinned := in.PinnedTransportName != ""
		switch {
		case pinned:
			// Req 2.10: a pinned Session is never upgraded and never rebound.
			if k := d.Kind(); k != DecisionStay && k != DecisionGoDisconnected {
				rt.Fatalf("pinned session got %s, want stay or disconnect", k)
			}
			if in.ActiveIsAvailable {
				if d.Kind() != DecisionStay {
					rt.Fatalf("pinned and available got %s, want stay", d.Kind())
				}
			} else {
				// Req 2.11: name the pinned Transport and why it went away.
				if d.Kind() != DecisionGoDisconnected {
					rt.Fatalf("pinned and unavailable got %s, want disconnect", d.Kind())
				}
				if !strings.Contains(d.GoDisconnected, in.PinnedTransportName) {
					rt.Fatalf("reason %q does not name pinned transport %q",
						d.GoDisconnected, in.PinnedTransportName)
				}
				if in.ActiveUnavailableReason != "" &&
					!strings.Contains(d.GoDisconnected, in.ActiveUnavailableReason) {
					rt.Fatalf("reason %q does not carry the cause %q",
						d.GoDisconnected, in.ActiveUnavailableReason)
				}
			}

		case !in.ActiveIsAvailable:
			// Req 3.3 and 3.6.
			if in.BestCandidateName != "" {
				if d.Kind() != DecisionRebind {
					rt.Fatalf("unavailable with candidate %q got %s, want rebind",
						in.BestCandidateName, d.Kind())
				}
				if d.Rebind != in.BestCandidateName {
					rt.Fatalf("rebound to %q, want the best candidate %q",
						d.Rebind, in.BestCandidateName)
				}
			} else if d.Kind() != DecisionGoDisconnected {
				rt.Fatalf("unavailable with no candidate got %s, want disconnect", d.Kind())
			}

		default:
			// Healthy and unpinned: upgrade exactly when all three conditions hold
			// together (Req 2.8).
			hasCandidate := in.BestCandidateName != "" && in.BestCandidateAvailableSince != nil
			strictlyFaster := in.BestCandidateGoodput > in.ActiveExpectedGoodput
			stable := hasCandidate &&
				in.Now.Sub(*in.BestCandidateAvailableSince) >= UpgradeStability
			cooledDown := in.Now.Sub(in.LastTransportChangeAt) >= UpgradeCooldown
			wantUpgrade := hasCandidate && strictlyFaster && stable && cooledDown

			if wantUpgrade {
				if d.Kind() != DecisionUpgrade {
					rt.Fatalf("qualifying candidate %q got %s, want upgrade",
						in.BestCandidateName, d.Kind())
				}
				if d.Upgrade != in.BestCandidateName {
					rt.Fatalf("upgraded to %q, want %q", d.Upgrade, in.BestCandidateName)
				}
			} else if d.Kind() != DecisionStay {
				rt.Fatalf("non-qualifying candidate got %s, want stay "+
					"(candidate=%v faster=%v stable=%v cooled=%v)",
					d.Kind(), hasCandidate, strictlyFaster, stable, cooledDown)
			}
		}

		// Target agrees with the branch on every path.
		switch d.Kind() {
		case DecisionUpgrade, DecisionRebind:
			if d.Target() == "" {
				rt.Fatalf("%s decision has no target", d.Kind())
			}
		default:
			if d.Target() != "" {
				rt.Fatalf("%s decision names target %q", d.Kind(), d.Target())
			}
		}
	})
}

// TestDecideSwitchEqualGoodputDoesNotUpgrade pins the strict-inequality reading of
// Req 2.8: a candidate that merely matches the active Transport is not "ranked
// above" it, so a Session on LAN never moves to another LAN-speed Transport.
//
// Requirements: 2.8
func TestDecideSwitchEqualGoodputDoesNotUpgrade(t *testing.T) {
	since := baseTime.Add(-time.Hour)
	in := SwitchInputs{
		ActiveTransportName:         NameLAN,
		ActiveExpectedGoodput:       LANExpectedGoodput,
		BestCandidateName:           "MC_Transport",
		BestCandidateGoodput:        LANExpectedGoodput, // equal, not faster
		BestCandidateAvailableSince: &since,
		LastTransportChangeAt:       baseTime.Add(-time.Hour),
		ActiveIsAvailable:           true,
		Now:                         baseTime,
	}
	if got := DecideSwitch(in); !got.Stay {
		t.Fatalf("equal goodput produced %s, want stay", got.Kind())
	}

	// One byte per second faster is enough, once stability and cooldown are met.
	in.BestCandidateGoodput = LANExpectedGoodput + 1
	if got := DecideSwitch(in); got.Upgrade != "MC_Transport" {
		t.Fatalf("strictly faster candidate produced %s, want upgrade", got.Kind())
	}
}

// TestDecideSwitchBoundariesAreInclusive pins the two >= comparisons in Req 2.8:
// exactly 5 seconds of stability and exactly 30 seconds of cooldown qualify.
//
// Requirements: 2.8
func TestDecideSwitchBoundariesAreInclusive(t *testing.T) {
	qualifying := func(stability, cooldown time.Duration) SwitchDecision {
		since := baseTime.Add(-stability)
		return DecideSwitch(SwitchInputs{
			ActiveTransportName:         NameBT,
			ActiveExpectedGoodput:       BTExpectedGoodput,
			BestCandidateName:           NameLAN,
			BestCandidateGoodput:        LANExpectedGoodput,
			BestCandidateAvailableSince: &since,
			LastTransportChangeAt:       baseTime.Add(-cooldown),
			ActiveIsAvailable:           true,
			Now:                         baseTime,
		})
	}

	cases := []struct {
		name       string
		stability  time.Duration
		cooldown   time.Duration
		wantUpdate bool
	}{
		{"both exactly at the bound", UpgradeStability, UpgradeCooldown, true},
		{"stability one nanosecond short", UpgradeStability - 1, UpgradeCooldown, false},
		{"cooldown one nanosecond short", UpgradeStability, UpgradeCooldown - 1, false},
		{"both comfortably past", 2 * UpgradeStability, 2 * UpgradeCooldown, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := qualifying(c.stability, c.cooldown)
			if c.wantUpdate && got.Upgrade != NameLAN {
				t.Fatalf("got %s, want upgrade to %s", got.Kind(), NameLAN)
			}
			if !c.wantUpdate && !got.Stay {
				t.Fatalf("got %s, want stay", got.Kind())
			}
		})
	}
}

// TestDecideSwitchRebindPrefersTheBestRemainingCandidate walks the failover path
// of Req 3.3 with the real Transports: a Session on LAN whose LAN link died moves
// to Bluetooth, and disconnects when Bluetooth is gone too.
//
// Requirements: 3.3, 3.6
func TestDecideSwitchRebindPrefersTheBestRemainingCandidate(t *testing.T) {
	in := SwitchInputs{
		ActiveTransportName:     NameLAN,
		ActiveExpectedGoodput:   LANExpectedGoodput,
		BestCandidateName:       NameBT,
		BestCandidateGoodput:    BTExpectedGoodput,
		LastTransportChangeAt:   baseTime.Add(-time.Minute),
		ActiveIsAvailable:       false,
		ActiveUnavailableReason: "keepalive missed 3 times",
		Now:                     baseTime,
	}
	if got := DecideSwitch(in); got.Rebind != NameBT {
		t.Fatalf("got %s, want rebind to %s", got.Kind(), NameBT)
	}

	in.BestCandidateName = ""
	got := DecideSwitch(in)
	if got.Kind() != DecisionGoDisconnected {
		t.Fatalf("got %s, want disconnect", got.Kind())
	}
	if !strings.Contains(got.GoDisconnected, "no candidate") {
		t.Fatalf("reason %q does not say why", got.GoDisconnected)
	}
}
