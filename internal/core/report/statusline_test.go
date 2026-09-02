package report

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// TestProperty39SessionStatusIsRenderedAllOrNothing covers
// Property 39: Session status is rendered all-or-nothing.
//
// Validates: Requirements 13.1, 13.2
func TestProperty39SessionStatusIsRenderedAllOrNothing(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		sessionId := rapid.StringMatching(`[a-f0-9]{8}`).Draw(rt, "sessionId")

		// Each of the four values is present or absent. An empty string counts as absent
		// for the two names, because a blank column is not a value.
		peer := rapid.SampledFrom([]*string{nil, ptr(""), ptr("laptop")}).Draw(rt, "peer")
		transport := rapid.SampledFrom([]*string{nil, ptr(""), ptr("LAN_Transport")}).
			Draw(rt, "transport")
		// Zero is a real measurement, not a stand-in for unknown, so it is in the set.
		goodput := rapid.SampledFrom([]*int64{nil, ptr[int64](0), ptr[int64](41_943_040)}).
			Draw(rt, "goodput")
		rtt := rapid.SampledFrom([]*int64{nil, ptr[int64](0), ptr[int64](7)}).Draw(rt, "rtt")

		got := BuildStatusLine(sessionId, peer, transport, goodput, rtt)

		// Exactly one branch.
		if (got.Ready == nil) == (got.Pending == nil) {
			rt.Fatalf("status sets %v/%v, want exactly one", got.Ready, got.Pending)
		}
		if got.Kind() == StatusInvalid {
			rt.Fatalf("status %+v has no kind", got)
		}

		haveAll := peer != nil && *peer != "" &&
			transport != nil && *transport != "" &&
			goodput != nil && rtt != nil

		if got.Kind() == StatusReady != haveAll {
			rt.Fatalf("ready=%v but all four present=%v (peer=%v transport=%v goodput=%v rtt=%v)",
				got.Kind() == StatusReady, haveAll, peer, transport, goodput, rtt)
		}

		rendered := got.String()

		if haveAll {
			// All four values are shown, and they are the ones supplied.
			if got.Ready.PeerDisplayName != *peer {
				rt.Fatalf("row names peer %q, want %q", got.Ready.PeerDisplayName, *peer)
			}
			if got.Ready.ActiveTransportName != *transport {
				rt.Fatalf("row names transport %q, want %q",
					got.Ready.ActiveTransportName, *transport)
			}
			if got.Ready.GoodputBytesPerSecond != *goodput {
				rt.Fatalf("row shows %d B/s, want %d",
					got.Ready.GoodputBytesPerSecond, *goodput)
			}
			if got.Ready.RoundTripMillis != *rtt {
				rt.Fatalf("row shows %d ms, want %d", got.Ready.RoundTripMillis, *rtt)
			}
			for _, want := range []string{
				*peer, *transport,
				strconv.FormatInt(*goodput, 10), strconv.FormatInt(*rtt, 10),
			} {
				if !strings.Contains(rendered, want) {
					rt.Fatalf("rendered row omits %q:\n%s", want, rendered)
				}
			}
			if Missing(peer, transport, goodput, rtt) != nil {
				rt.Fatalf("all four present but Missing() reports %v",
					Missing(peer, transport, goodput, rtt))
			}
			return
		}

		// Req 13.2: the pending state carries none of the four values, so no partial row
		// can be produced. The pending branch holds only the Session id.
		if *got.Pending != sessionId {
			rt.Fatalf("pending row names session %q, want %q", *got.Pending, sessionId)
		}
		if !strings.Contains(rendered, "pending") {
			rt.Fatalf("pending row does not say pending:\n%s", rendered)
		}
		// None of the present values leak into the pending row. The Session id itself is
		// allowed and is checked above; everything else must be absent.
		if transport != nil && *transport != "" && strings.Contains(rendered, *transport) {
			rt.Fatalf("pending row shows the transport name:\n%s", rendered)
		}
		if peer != nil && *peer != "" && strings.Contains(rendered, *peer) {
			rt.Fatalf("pending row shows the peer name:\n%s", rendered)
		}
		if goodput != nil && strings.Contains(rendered, "B/s") {
			rt.Fatalf("pending row shows a goodput figure:\n%s", rendered)
		}
		if rtt != nil && strings.Contains(rendered, "ms") {
			rt.Fatalf("pending row shows a round-trip figure:\n%s", rendered)
		}

		// Missing() names exactly the absent values, for a caller that wants to explain the
		// pending state without putting it in the row.
		missing := Missing(peer, transport, goodput, rtt)
		if len(missing) == 0 {
			rt.Fatal("row is pending but Missing() reports nothing missing")
		}
	})
}

// TestBuildStatusLineTreatsZeroAsAMeasurement is the reason the four values arrive as
// pointers: a Session measuring 0 B/s on an idle link has a measurement, and showing it
// pending would be wrong.
//
// Requirements: 13.1, 13.2
func TestBuildStatusLineTreatsZeroAsAMeasurement(t *testing.T) {
	peer, transport := ptr("laptop"), ptr("LAN_Transport")
	zero := ptr[int64](0)

	got := BuildStatusLine("s1", peer, transport, zero, zero)
	if got.Kind() != StatusReady {
		t.Fatalf("a session measuring zero got %s, want ready", got.Kind())
	}
	if got.Ready.GoodputBytesPerSecond != 0 || got.Ready.RoundTripMillis != 0 {
		t.Fatalf("row shows %+v, want both zero", got.Ready)
	}
	if !strings.Contains(got.String(), "0 B/s") {
		t.Fatalf("row does not show the zero measurement:\n%s", got.String())
	}

	// Absent is a different thing entirely, and shows pending.
	if pending := BuildStatusLine("s1", peer, transport, nil, zero); pending.Kind() != StatusPending {
		t.Fatalf("a session with no goodput got %s, want pending", pending.Kind())
	}
}

// TestBuildStatusLinePendingCarriesOnlyTheSessionId pins Req 13.2's "in place of all four
// values": three of four present still shows nothing but pending.
//
// Requirements: 13.2
func TestBuildStatusLinePendingCarriesOnlyTheSessionId(t *testing.T) {
	cases := map[string]struct {
		peer, transport  *string
		goodput, rtt     *int64
		wantMissingCount int
	}{
		"nothing known":   {nil, nil, nil, nil, 4},
		"only the peer":   {ptr("laptop"), nil, nil, nil, 3},
		"missing rtt":     {ptr("laptop"), ptr("LAN_Transport"), ptr[int64](100), nil, 1},
		"blank transport": {ptr("laptop"), ptr(""), ptr[int64](100), ptr[int64](5), 1},
		"blank peer":      {ptr(""), ptr("LAN_Transport"), ptr[int64](100), ptr[int64](5), 1},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := BuildStatusLine("session-7", c.peer, c.transport, c.goodput, c.rtt)
			if got.Kind() != StatusPending {
				t.Fatalf("got %s, want pending", got.Kind())
			}
			if got.Ready != nil {
				t.Fatal("the pending branch also set Ready")
			}
			if *got.Pending != "session-7" {
				t.Fatalf("pending names session %q", *got.Pending)
			}
			if missing := Missing(c.peer, c.transport, c.goodput, c.rtt); len(missing) != c.wantMissingCount {
				t.Fatalf("Missing() reports %v, want %d entries", missing, c.wantMissingCount)
			}
		})
	}
}

// TestStatusRefreshIntervalMatchesTheRequirement pins the one-second refresh of Req 13.1
// and 13.2.
//
// Requirements: 13.1, 13.2
func TestStatusRefreshIntervalMatchesTheRequirement(t *testing.T) {
	if StatusRefreshInterval > time.Second {
		t.Fatalf("status refresh interval is %s, which is slower than the 1s bound",
			StatusRefreshInterval)
	}
}

func ptr[T any](v T) *T { return &v }
