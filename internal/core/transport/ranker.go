package transport

import (
	"sort"

	"github.com/peerbeam/peerbeam/internal/core/discovery"
)

// CandidateTransports returns the Transports that may be attempted for one Peer:
// enabled on this Peer_Node AND carrying a medium the Peer is currently visible on
// (Req 2.1). Both halves of that conjunction matter. An enabled Transport whose
// medium the Peer was never seen on is not a candidate, and a medium the Peer is
// visible on whose Transport is disabled locally is not a candidate either.
//
// peerMedia is what discovery.PeerRegistry.MediaFor returns. A nil map means the
// Peer is visible on nothing, which yields an empty candidate list and, from
// there, the NoCandidate branch of the ladder (Req 2.6).
//
// The input order of `enabled` is preserved. Ordering is RankCandidates' job, and
// splitting the two keeps each independently testable.
func CandidateTransports(enabled []Transport, peerMedia map[discovery.Medium]struct{}) []Transport {
	// Non-nil empty slice rather than nil: callers range over it and length-check
	// it, and an empty candidate list is a normal outcome, not a missing one.
	out := make([]Transport, 0, len(enabled))
	for _, t := range enabled {
		if t == nil {
			continue // a nil entry is a wiring bug, not a candidate; skip rather than panic
		}
		if _, visible := peerMedia[t.Medium()]; visible {
			out = append(out, t)
		}
	}
	return out
}

// RankCandidates orders candidates fastest first, ties broken by ascending name
// (Req 2.1, 2.2). With the figures in Req 2.1 that puts LAN_Transport above
// BT_Transport by goodput alone; the name tie-break exists so that a future set
// of equal-goodput Transports still ranks identically on every call, which is
// what Req 2.2 asks for.
//
// The input slice is copied, so ranking never mutates the caller's enabled-set.
// sort.SliceStable is used over sort.Slice because the comparison is a total
// order only once the name tie-break is included: stability makes the outcome
// independent of the sort's internal pivot choices even if two entries somehow
// share both goodput and name.
func RankCandidates(candidates []Transport) []Transport {
	ranked := make([]Transport, 0, len(candidates))
	ranked = append(ranked, candidates...)
	sort.SliceStable(ranked, func(i, j int) bool {
		gi, gj := ranked[i].ExpectedGoodputBytesPerSecond(), ranked[j].ExpectedGoodputBytesPerSecond()
		if gi != gj {
			return gi > gj // descending expected goodput
		}
		return ranked[i].Name() < ranked[j].Name() // ascending name
	})
	return ranked
}

// RankFor is the composition the Transport_Manager actually calls: select, then
// rank. It exists so callers cannot accidentally rank an unfiltered set or
// attempt an unranked one.
func RankFor(enabled []Transport, peerMedia map[discovery.Medium]struct{}) []Transport {
	return RankCandidates(CandidateTransports(enabled, peerMedia))
}
