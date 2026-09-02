package transport

import (
	"context"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/peerbeam/peerbeam/internal/core/discovery"
)

// testAttemptTimeout stands in for the 3 s of Req 2.4 and the 5 s of Req 3.8.
// The ladder takes the timeout as a parameter precisely so a test can shrink it:
// behaveTimeout waits on the attempt context, so this value is what a timing-out
// rung actually costs, and a property doing 100 runs over up to 6 candidates
// stays well under a second.
const testAttemptTimeout = 2 * time.Millisecond

// ladderBehaviours is the closed set of per-candidate outcomes Property 13 ranges
// over: success, refusal, timeout, plus the two edge cases the implementation has
// to account for.
var ladderBehaviours = []behaviour{
	behaveSucceed, behaveRefuse, behaveTimeout, behaveNoEndpoint, behaveNilNil,
}

// TestProperty13ConnectLadderAttemptsEachCandidateAtMostOnce covers
// Property 13: The connection ladder attempts each candidate at most once and
// reports every attempt.
//
// Validates: Requirements 2.3, 2.4, 2.5, 2.6, 3.8
func TestProperty13ConnectLadderAttemptsEachCandidateAtMostOnce(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		p := &probe{}

		// Distinct names so an attempt log entry identifies exactly one rung.
		candidateNames := rapid.SliceOfNDistinct(
			rapid.StringMatching(`[a-zA-Z]{1,6}_Transport`),
			0, 6,
			func(s string) string { return s },
		).Draw(rt, "candidateNames")

		schedule := make(map[string]behaviour, len(candidateNames))
		candidates := make([]Transport, 0, len(candidateNames))
		for i, n := range candidateNames {
			b := rapid.SampledFrom(ladderBehaviours).Draw(rt, "behaviour"+string(rune('0'+i)))
			schedule[n] = b
			candidates = append(candidates, &fakeTransport{
				name:    n,
				medium:  rapid.SampledFrom(allMedia).Draw(rt, "medium"+string(rune('0'+i))),
				goodput: rapid.SampledFrom(goodputChoices).Draw(rt, "goodput"+string(rune('0'+i))),
				chunk:   LANChunkBytes,
				behave:  b,
				probe:   p,
			})
		}

		// The ladder consumes an already-ranked list, so rank first, exactly as
		// the Transport_Manager does.
		ranked := RankCandidates(candidates)
		rankedNames := names(ranked)

		// Either per-attempt bound exercises the same code path (Req 2.4, 3.8).
		timeout := rapid.SampledFrom([]time.Duration{testAttemptTimeout, 2 * testAttemptTimeout}).
			Draw(rt, "perAttemptTimeout")

		result := ConnectLadder(context.Background(), ranked, endpointLookupFor(schedule), timeout)

		// Req 2.6: an empty candidate list is NoCandidate, never AllFailed.
		if len(ranked) == 0 {
			if !result.NoCandidate || result.Connected != nil || result.AllFailed != nil {
				rt.Fatalf("empty candidate list: got %+v, want NoCandidate", result)
			}
			if len(p.log()) != 0 {
				rt.Fatalf("empty candidate list attempted %v", p.log())
			}
			return
		}
		if result.NoCandidate {
			rt.Fatalf("%d candidates but got NoCandidate", len(ranked))
		}

		// The specification, restated: the first rung that can succeed is the
		// first one whose behaviour is behaveSucceed.
		firstSuccess := -1
		for i, n := range rankedNames {
			if schedule[n] == behaveSucceed {
				firstSuccess = i
				break
			}
		}

		// Req 2.3: attempts run in rank order, and Connect is reached only for
		// rungs that resolved an endpoint. The ladder stops at the first success,
		// so nothing after it is attempted.
		lastAttemptable := len(rankedNames)
		if firstSuccess >= 0 {
			lastAttemptable = firstSuccess + 1
		}
		var wantConnectLog []string
		for _, n := range rankedNames[:lastAttemptable] {
			if schedule[n] != behaveNoEndpoint {
				wantConnectLog = append(wantConnectLog, n)
			}
		}
		if wantConnectLog == nil {
			wantConnectLog = []string{}
		}
		got := p.log()
		if got == nil {
			got = []string{}
		}
		requireEqualStrings(rt, got, wantConnectLog, "connect log in rank order")

		// Req 2.3: at most one attempt open at a time.
		if hw := p.highWater(); hw > 1 {
			rt.Fatalf("%d concurrent connection attempts, want at most 1", hw)
		}

		// Req 2.4: no Transport is attempted twice.
		seen := map[string]int{}
		for _, n := range got {
			seen[n]++
			if seen[n] > 1 {
				rt.Fatalf("transport %s attempted %d times, want at most 1", n, seen[n])
			}
		}

		if firstSuccess >= 0 {
			// Stops at the first success, and hands back a usable connection
			// paired with the Transport that produced it.
			if result.Connected == nil {
				rt.Fatalf("candidate %s was set to succeed but ladder returned %v",
					rankedNames[firstSuccess], result.Summary())
			}
			if result.AllFailed != nil {
				rt.Fatalf("Connected and AllFailed both set: %+v", result)
			}
			if result.Connected.Connection == nil || result.Connected.Transport == nil {
				rt.Fatalf("Connected branch holds nil: %+v", result.Connected)
			}
			wantName := rankedNames[firstSuccess]
			if result.Connected.Transport.Name() != wantName {
				rt.Fatalf("connected on %s, want the highest ranked succeeding candidate %s",
					result.Connected.Transport.Name(), wantName)
			}
			if result.Connected.Connection.TransportName() != wantName {
				rt.Fatalf("connection reports transport %s, want %s",
					result.Connected.Connection.TransportName(), wantName)
			}
			if result.Summary() != "" {
				rt.Fatalf("successful ladder produced summary %q", result.Summary())
			}
			return
		}

		// Total failure. Req 2.5: no connection, and one attempt record per
		// candidate in attempt order, each with a non-empty reason.
		if result.Connected != nil {
			rt.Fatalf("no candidate could succeed but ladder connected on %s",
				result.Connected.Transport.Name())
		}
		requireEqualStrings(rt, attemptNames(result.AllFailed), rankedNames, "attempt records in rank order")
		for _, a := range result.AllFailed {
			if strings.TrimSpace(a.Reason) == "" {
				rt.Fatalf("attempt record for %s has an empty reason", a.TransportName)
			}
		}
		if s := result.Summary(); !strings.Contains(s, "all transports failed") {
			rt.Fatalf("failure summary %q does not describe a total failure", s)
		}
	})
}

func attemptNames(records []AttemptRecord) []string {
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.TransportName)
	}
	return out
}

// TestConnectLadderNoCandidate pins the Req 2.6 branch on a nil list as well as
// an empty one.
//
// Requirements: 2.6
func TestConnectLadderNoCandidate(t *testing.T) {
	for _, ranked := range [][]Transport{nil, {}} {
		result := ConnectLadder(context.Background(), ranked,
			endpointLookupFor(nil), testAttemptTimeout)
		if !result.NoCandidate {
			t.Fatalf("ranked=%v: got %+v, want NoCandidate", ranked, result)
		}
		if result.Summary() != "no transport available for peer" {
			t.Fatalf("unexpected summary %q", result.Summary())
		}
	}
}

// TestConnectLadderTimeoutNamesTheBound checks that a rung ended by the deadline
// reports the bound it exceeded rather than a bare context error, so the Req 2.5
// report is useful to an operator. It also confirms the ladder falls through to
// the next ranked candidate after a timeout (Req 2.4, 3.8).
//
// Requirements: 2.4, 2.5, 3.8
func TestConnectLadderTimeoutNamesTheBound(t *testing.T) {
	p := &probe{}
	lan, bt := realTransports(behaveTimeout, p)
	bt.behave = behaveSucceed // LAN times out, Bluetooth answers

	schedule := map[string]behaviour{NameLAN: behaveTimeout, NameBT: behaveSucceed}
	ranked := RankCandidates([]Transport{bt, lan})

	result := ConnectLadder(context.Background(), ranked, endpointLookupFor(schedule), testAttemptTimeout)
	if result.Connected == nil || result.Connected.Transport.Name() != NameBT {
		t.Fatalf("got %+v, want a connection on %s after the LAN timeout", result, NameBT)
	}
	requireEqualStrings(t, p.log(), []string{NameLAN, NameBT}, "LAN tried first, then BT")

	// Now with both timing out, so the reasons are observable.
	p2 := &probe{}
	lan2, bt2 := realTransports(behaveTimeout, p2)
	both := map[string]behaviour{NameLAN: behaveTimeout, NameBT: behaveTimeout}
	result2 := ConnectLadder(context.Background(), RankCandidates([]Transport{lan2, bt2}),
		endpointLookupFor(both), testAttemptTimeout)
	if result2.Connected != nil {
		t.Fatalf("both candidates time out but ladder connected: %+v", result2.Connected)
	}
	requireEqualStrings(t, attemptNames(result2.AllFailed), []string{NameLAN, NameBT}, "both attempts reported")
	for _, a := range result2.AllFailed {
		want := "did not connect within " + testAttemptTimeout.String()
		if a.Reason != want {
			t.Fatalf("%s: reason %q, want %q", a.TransportName, a.Reason, want)
		}
	}
}

// TestConnectLadderMissingEndpointIsStillReported checks that a candidate the
// Peer is visible on but holds no address for still appears in the Req 2.5
// report, rather than vanishing from it.
//
// Requirements: 2.5
func TestConnectLadderMissingEndpointIsStillReported(t *testing.T) {
	p := &probe{}
	lan, bt := realTransports(behaveRefuse, p)
	schedule := map[string]behaviour{NameLAN: behaveNoEndpoint, NameBT: behaveRefuse}
	lan.behave = behaveNoEndpoint

	result := ConnectLadder(context.Background(), RankCandidates([]Transport{lan, bt}),
		endpointLookupFor(schedule), testAttemptTimeout)

	requireEqualStrings(t, attemptNames(result.AllFailed), []string{NameLAN, NameBT}, "both candidates reported")
	if !strings.Contains(result.AllFailed[0].Reason, "no endpoint") {
		t.Fatalf("LAN reason %q does not name the missing endpoint", result.AllFailed[0].Reason)
	}
	// Connect was never called for the endpoint-less rung.
	requireEqualStrings(t, p.log(), []string{NameBT}, "only BT reached Connect")
}

// TestConnectLadderBrokenTransportIsNotASuccess guards the Connected branch
// against a Transport that returns neither a connection nor an error.
//
// Requirements: 2.5
func TestConnectLadderBrokenTransportIsNotASuccess(t *testing.T) {
	broken := &fakeTransport{
		name: NameLAN, medium: discovery.MediumLAN,
		goodput: LANExpectedGoodput, chunk: LANChunkBytes, behave: behaveNilNil,
	}
	result := ConnectLadder(context.Background(), []Transport{broken},
		endpointLookupFor(map[string]behaviour{NameLAN: behaveNilNil}), testAttemptTimeout)

	if result.Connected != nil {
		t.Fatalf("nil connection reported as success: %+v", result.Connected)
	}
	if len(result.AllFailed) != 1 || strings.TrimSpace(result.AllFailed[0].Reason) == "" {
		t.Fatalf("got %+v, want one attempt record with a reason", result.AllFailed)
	}
}

// TestConnectLadderNonPositiveTimeoutFallsBackToTheRequirementBound checks that a
// zero timeout is treated as the Req 2.4 default rather than as no bound at all.
//
// Requirements: 2.4
func TestConnectLadderNonPositiveTimeoutFallsBackToTheRequirementBound(t *testing.T) {
	// A cancelled parent context makes the attempt end immediately, so this test
	// does not wait out the 3-second default.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	lan, _ := realTransports(behaveTimeout, nil)
	result := ConnectLadder(ctx, []Transport{lan},
		endpointLookupFor(map[string]behaviour{NameLAN: behaveTimeout}), 0)

	if result.Connected != nil || len(result.AllFailed) != 1 {
		t.Fatalf("got %+v, want a single failed attempt", result)
	}
	if result.AllFailed[0].Reason != "attempt cancelled" {
		t.Fatalf("reason %q, want the cancellation to be named", result.AllFailed[0].Reason)
	}
}
