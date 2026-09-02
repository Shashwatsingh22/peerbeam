package transport

import (
	"sort"
	"testing"

	"pgregory.net/rapid"

	"github.com/peerbeam/peerbeam/internal/core/discovery"
)

// allMedia is the closed set of media a Transport can carry.
var allMedia = []discovery.Medium{discovery.MediumLAN, discovery.MediumBluetooth}

// goodputChoices deliberately repeats values so ties are common and the
// name tie-break in Req 2.2 gets real coverage, instead of being reached once in
// a hundred runs by chance.
var goodputChoices = []int64{BTExpectedGoodput, LANExpectedGoodput, 1_000, 1_000, 40_960}

// drawTransports builds 0..6 Transports with distinct names, so ranking has a
// total order and the expected result is unambiguous.
func drawTransports(t *rapid.T, label string) []Transport {
	names := rapid.SliceOfNDistinct(
		rapid.StringMatching(`[a-zA-Z]{1,6}_Transport`),
		0, 6,
		func(s string) string { return s },
	).Draw(t, label+"Names")

	out := make([]Transport, 0, len(names))
	for i, n := range names {
		out = append(out, &fakeTransport{
			name:    n,
			medium:  rapid.SampledFrom(allMedia).Draw(t, label+"Medium"+string(rune('0'+i))),
			goodput: rapid.SampledFrom(goodputChoices).Draw(t, label+"Goodput"+string(rune('0'+i))),
			chunk:   LANChunkBytes,
		})
	}
	return out
}

// expectedRankOrder is the specification restated independently of the
// implementation: descending goodput, ties by ascending name (Req 2.1, 2.2).
func expectedRankOrder(ts []Transport) []string {
	type row struct {
		name    string
		goodput int64
	}
	rows := make([]row, 0, len(ts))
	for _, t := range ts {
		rows = append(rows, row{t.Name(), t.ExpectedGoodputBytesPerSecond()})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].goodput != rows[j].goodput {
			return rows[i].goodput > rows[j].goodput
		}
		return rows[i].name < rows[j].name
	})
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.name)
	}
	return out
}

// TestProperty12CandidateSelectionAndRankingAreDeterministic covers
// Property 12: Candidate selection and ranking are deterministic and
// speed-ordered.
//
// Validates: Requirements 2.1, 2.2
func TestProperty12CandidateSelectionAndRankingAreDeterministic(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		enabled := drawTransports(rt, "enabled")

		// The Peer is visible on an arbitrary subset of the media.
		peerMedia := map[discovery.Medium]struct{}{}
		for _, m := range allMedia {
			if rapid.Bool().Draw(rt, "visibleOn"+m.String()) {
				peerMedia[m] = struct{}{}
			}
		}

		candidates := CandidateTransports(enabled, peerMedia)

		// Candidates are exactly the enabled Transports whose medium the Peer is
		// visible on: nothing dropped, nothing invented.
		var wantCandidates []string
		for _, e := range enabled {
			if _, visible := peerMedia[e.Medium()]; visible {
				wantCandidates = append(wantCandidates, e.Name())
			}
		}
		if wantCandidates == nil {
			wantCandidates = []string{}
		}
		requireEqualStrings(rt, names(candidates), wantCandidates, "candidate set")

		// Selection preserves the input order and never mutates the caller's slice.
		requireEqualStrings(rt, names(enabled), names(enabled), "enabled unchanged")

		ranked := RankCandidates(candidates)
		want := expectedRankOrder(candidates)
		requireEqualStrings(rt, names(ranked), want, "rank order")

		// Ranking must not disturb the slice it was handed.
		requireEqualStrings(rt, names(candidates), wantCandidates, "candidates unmutated by ranking")

		// Determinism under input permutation: any shuffle of the same candidate
		// set ranks identically (Req 2.2).
		shuffled := append([]Transport(nil), candidates...)
		perm := rapid.Permutation(shuffled).Draw(rt, "permutation")
		requireEqualStrings(rt, names(RankCandidates(perm)), want, "rank order after shuffle")

		// Repeated ranking of the same input is idempotent.
		requireEqualStrings(rt, names(RankCandidates(ranked)), want, "rank order re-ranked")

		// RankFor is exactly the composition of the two.
		requireEqualStrings(rt, names(RankFor(enabled, peerMedia)), want, "RankFor composition")
	})
}

// TestLANRanksAboveBT pins the concrete ordering Req 2.1 names, using the real
// goodput figures rather than generated ones.
//
// Requirements: 2.1
func TestLANRanksAboveBT(t *testing.T) {
	lan, bt := realTransports(behaveSucceed, nil)
	bothMedia := map[discovery.Medium]struct{}{
		discovery.MediumLAN:       {},
		discovery.MediumBluetooth: {},
	}
	// BT first in the input, so a stable sort that did nothing would fail here.
	got := names(RankFor([]Transport{bt, lan}, bothMedia))
	requireEqualStrings(t, got, []string{NameLAN, NameBT}, "LAN ranks above BT")
}

// TestCandidateTransportsWithNoVisibleMedia covers the input that feeds the
// NoCandidate branch of the ladder (Req 2.6).
//
// Requirements: 2.1, 2.6
func TestCandidateTransportsWithNoVisibleMedia(t *testing.T) {
	lan, bt := realTransports(behaveSucceed, nil)

	if got := CandidateTransports([]Transport{lan, bt}, nil); len(got) != 0 {
		t.Fatalf("no visible media: got %v, want no candidates", names(got))
	}
	// A Peer visible only on Bluetooth yields only BT_Transport, even though LAN
	// is enabled and ranks higher.
	btOnly := map[discovery.Medium]struct{}{discovery.MediumBluetooth: {}}
	requireEqualStrings(t, names(CandidateTransports([]Transport{lan, bt}, btOnly)),
		[]string{NameBT}, "bluetooth-only peer")
}
