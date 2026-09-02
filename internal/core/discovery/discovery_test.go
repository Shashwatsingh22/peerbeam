package discovery

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"pgregory.net/rapid"

	"github.com/peerbeam/peerbeam/internal/core/clock"
)

var baseTime = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

// manualClock is the injected time source, so the 30-second expiry of Req 1.5 is checked by advancing
// it rather than by waiting.
type manualClock struct{ now time.Time }

func newManualClock() *manualClock             { return &manualClock{now: baseTime} }
func (c *manualClock) Now() time.Time          { return c.now }
func (c *manualClock) advance(d time.Duration) { c.now = c.now.Add(d) }

var _ clock.Clock = (*manualClock)(nil)

// fingerprintFor builds a valid 64-character lowercase hex fingerprint from a seed.
func fingerprintFor(seed int) string {
	return strings.Repeat(fmt.Sprintf("%02x", seed%256), 32)
}

// drawValidAnnouncement produces an announcement that satisfies every bound in Req 1.1, including
// display names that are legal at 64 characters but far more than 64 bytes.
func drawValidAnnouncement(t *rapid.T, label string) Announcement {
	name := rapid.SampledFrom([]string{
		"laptop",
		"デスクトップ",
		"café-serveur",
		strings.Repeat("x", MaxDisplayNameChars),
		// 64 multi-byte characters: legal by Req 1.1's character count, 256 bytes on the wire.
		strings.Repeat("é", MaxDisplayNameChars),
		strings.Repeat("😀", MaxDisplayNameChars),
	}).Draw(t, label+"Name")

	return Announcement{
		DisplayName: name,
		Fingerprint: fingerprintFor(rapid.IntRange(0, 255).Draw(t, label+"Fingerprint")),
		// Req 1.2 keeps an unsupported version visible, so the generator covers both.
		ProtocolVersion: rapid.IntRange(1, 5).Draw(t, label+"Version"),
		Port:            rapid.IntRange(MinPort, MaxPort).Draw(t, label+"Port"),
	}
}

// TestProperty8AnnouncementValidationAndRoundTrip covers
// Property 8: Announcement validation and round trip.
//
// Validates: Requirements 1.1, 1.11
func TestProperty8AnnouncementValidationAndRoundTrip(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		valid := drawValidAnnouncement(rt, "valid")

		// A well-formed announcement is accepted and survives an encode and decode with all
		// four fields intact.
		check := CheckAnnouncement(&valid)
		if check.Malformed != nil {
			rt.Fatalf("a valid announcement was rejected: %v", check.Malformed)
		}
		if check.Valid == nil {
			rt.Fatal("an accepted announcement returned no value")
		}

		encoded, err := EncodeAnnouncement(valid)
		if err != nil {
			rt.Fatalf("encoding: %v", err)
		}
		round := DecodeAndCheckAnnouncement(encoded)
		if round.Malformed != nil {
			rt.Fatalf("a round-tripped announcement was rejected: %v", round.Malformed)
		}
		if *round.Valid != valid {
			rt.Fatalf("the round trip changed the announcement:\n sent %+v\n got  %+v",
				valid, *round.Valid)
		}

		// Now break exactly one field and check the rejection names it. The registry is
		// checked alongside, because Req 1.11 requires the visible Peer list to be unchanged.
		registry := NewPeerRegistry(1, newManualClock())
		before := len(registry.Visible())

		broken := valid
		var wantReason string
		switch rapid.SampledFrom([]string{
			"name", "longName", "fingerprint", "badFingerprint", "version", "port", "highPort",
		}).Draw(rt, "brokenField") {

		case "name":
			broken.DisplayName = ""
			wantReason = "displayName"
		case "longName":
			// One character past the limit, counted in characters rather than bytes.
			broken.DisplayName = strings.Repeat("é", MaxDisplayNameChars+1)
			wantReason = "displayName"
		case "fingerprint":
			broken.Fingerprint = ""
			wantReason = "fingerprint"
		case "badFingerprint":
			// A non-hex character, which is rejected rather than normalised: one canonical
			// spelling is what keeps a fingerprint a single map key (Req 1.8). The last
			// character is replaced rather than the whole string uppercased, because a
			// fingerprint of all digits uppercases to itself and the mutation would be a
			// no-op.
			broken.Fingerprint = valid.Fingerprint[:FingerprintHexChars-1] + "Z"
			wantReason = "fingerprint"
		case "version":
			broken.ProtocolVersion = 0
			wantReason = "protocolVersion"
		case "port":
			broken.Port = 0
			wantReason = "port"
		case "highPort":
			broken.Port = MaxPort + 1
			wantReason = "port"
		}

		got := CheckAnnouncement(&broken)
		if got.Malformed == nil {
			rt.Fatalf("a malformed announcement was accepted: %+v", broken)
		}
		if got.Valid != nil {
			rt.Fatal("a rejected announcement also returned a value")
		}
		// Req 1.11: the reason names the offending field.
		if !strings.Contains(strings.Join(got.Malformed, "; "), wantReason) {
			rt.Fatalf("reasons %v do not name %q", got.Malformed, wantReason)
		}

		// The list is unchanged: validation is pure and the registry rejects it too.
		outcome := registry.Observe(broken, MediumLAN, "192.0.2.1")
		if outcome.Malformed == nil {
			rt.Fatalf("the registry accepted a malformed announcement: %+v", broken)
		}
		if len(registry.Visible()) != before {
			rt.Fatal("a malformed announcement changed the visible peer list")
		}
	})
}

// TestDisplayNameLimitIsCharactersNotBytes guards against the Req 1.1 limit being read as a byte
// count. A 64-character multi-byte name is legal and is 256 bytes on the wire; rejecting it would make
// the node refuse perfectly valid peers.
//
// Requirements: 1.1, 1.11
func TestDisplayNameLimitIsCharactersNotBytes(t *testing.T) {
	legal := strings.Repeat("😀", MaxDisplayNameChars) // 64 characters, 256 bytes
	if utf8.RuneCountInString(legal) != MaxDisplayNameChars {
		t.Fatalf("the test input is %d characters", utf8.RuneCountInString(legal))
	}
	if len(legal) <= MaxDisplayNameChars {
		t.Fatal("the test input is not longer in bytes than in characters, so it proves nothing")
	}

	announcement := Announcement{
		DisplayName:     legal,
		Fingerprint:     fingerprintFor(1),
		ProtocolVersion: 1,
		Port:            45770,
	}
	if got := CheckAnnouncement(&announcement); got.Malformed != nil {
		t.Fatalf("a 64-character name was rejected: %v", got.Malformed)
	}

	// One character more is rejected.
	announcement.DisplayName = strings.Repeat("😀", MaxDisplayNameChars+1)
	got := CheckAnnouncement(&announcement)
	if got.Malformed == nil {
		t.Fatal("a 65-character name was accepted")
	}
	if !strings.Contains(strings.Join(got.Malformed, "; "), strconv.Itoa(MaxDisplayNameChars)) {
		t.Fatalf("the reason %v does not name the limit", got.Malformed)
	}
}

// TestProperty9VisiblePeerListIsABoundedFingerprintKeyedUpsert covers
// Property 9: The visible Peer list is a bounded, fingerprint-keyed upsert.
//
// Validates: Requirements 1.2, 1.6, 1.7, 1.8
func TestProperty9VisiblePeerListIsABoundedFingerprintKeyedUpsert(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		clk := newManualClock()
		registry := NewPeerRegistry(1, clk)

		// An independent model of what the list should hold, keyed by entry identity rather
		// than by fingerprint. A manual entry has no fingerprint until an announcement
		// promotes it - neither the name nor the key is knowable from an address - so it is
		// modelled under its host instead.
		type modelEndpoint struct {
			address string
			port    int
		}
		model := map[string]map[Medium]modelEndpoint{}
		wantManual := map[string]bool{}

		steps := rapid.IntRange(1, 40).Draw(rt, "steps")
		for step := 0; step < steps; step++ {
			switch rapid.SampledFrom([]string{"observe", "observe", "observe", "manual"}).
				Draw(rt, "op"+strconv.Itoa(step)) {

			case "observe":
				// A small fingerprint pool, so the same one recurs and the upsert is
				// genuinely exercised rather than only ever inserting.
				seed := rapid.IntRange(0, 5).Draw(rt, "seed"+strconv.Itoa(step))
				medium := rapid.SampledFrom([]Medium{MediumLAN, MediumBluetooth}).
					Draw(rt, "medium"+strconv.Itoa(step))
				address := rapid.SampledFrom([]string{
					"192.0.2.1", "192.0.2.2", "198.51.100.9", "device-a", "device-b",
				}).Draw(rt, "address"+strconv.Itoa(step))
				port := rapid.SampledFrom([]int{45770, 45771, 60000}).
					Draw(rt, "port"+strconv.Itoa(step))

				announcement := Announcement{
					DisplayName:     "peer" + strconv.Itoa(seed),
					Fingerprint:     fingerprintFor(seed),
					ProtocolVersion: 1,
					Port:            port,
				}

				outcome := registry.Observe(announcement, medium, address)
				if outcome.Malformed != nil {
					rt.Fatalf("step %d: a valid announcement was rejected: %v",
						step, outcome.Malformed)
				}
				if outcome.AtCapacity != nil {
					// Req 1.2: the list is bounded, and a new fingerprint is turned
					// away rather than evicting an existing one.
					if _, known := model[announcement.Fingerprint]; known {
						rt.Fatalf("step %d: a known fingerprint was turned away", step)
					}
					if len(model) < MaxVisiblePeers {
						rt.Fatalf("step %d: capacity reported with only %d entries",
							step, len(model))
					}
					continue
				}

				if model[announcement.Fingerprint] == nil {
					model[announcement.Fingerprint] = map[Medium]modelEndpoint{}
				}
				// Req 1.8: the most recently observed address and port per medium.
				model[announcement.Fingerprint][medium] = modelEndpoint{address, port}

			case "manual":
				host := rapid.SampledFrom([]string{"192.0.2.50", "203.0.113.7"}).
					Draw(rt, "host"+strconv.Itoa(step))
				port := rapid.SampledFrom([]int{45770, 45999}).
					Draw(rt, "manualPort"+strconv.Itoa(step))

				outcome := registry.AddManual(host, port)
				if outcome.Rejected != nil {
					rt.Fatalf("step %d: a valid manual entry was rejected: %s",
						step, outcome.Rejected.Error())
				}
				if outcome.AtCapacity != nil {
					continue
				}
				// Req 1.6: marked as manually supplied.
				if !outcome.Recorded.Peer.ManuallySupplied {
					rt.Fatalf("step %d: a manual entry is not marked manually supplied", step)
				}
				// The manual hosts are deliberately disjoint from the observed addresses,
				// so no manual entry is promoted mid-run and each keeps its own identity.
				// Promotion is covered separately by
				// TestManualEntryUpdatesInPlaceForAKnownPeer.
				identity := "manual:" + host
				wantManual[identity] = true
				if model[identity] == nil {
					model[identity] = map[Medium]modelEndpoint{}
				}
				// Req 1.7: the same host again updates the port in place.
				model[identity][MediumLAN] = modelEndpoint{host, port}
			}

			// Req 1.2: at most 64 entries, always.
			visible := registry.Visible()
			if len(visible) > MaxVisiblePeers {
				rt.Fatalf("step %d: the list holds %d entries, limit is %d",
					step, len(visible), MaxVisiblePeers)
			}
			if len(visible) != len(model) {
				rt.Fatalf("step %d: the list holds %d entries, the model says %d",
					step, len(visible), len(model))
			}

			// Req 1.8: exactly one entry per fingerprint, listing every medium it was seen
			// on, with the most recent address and port for each.
			seen := map[string]struct{}{}
			for _, peer := range visible {
				// A discovered entry is identified by its fingerprint; an unpromoted manual
				// one by its address, since it has no fingerprint yet.
				identity := peer.Fingerprint
				if identity == "" {
					identity = "manual:" + peer.Endpoints[MediumLAN].Address
				}

				if _, duplicate := seen[identity]; duplicate {
					rt.Fatalf("step %d: entry %s appears twice", step, identity)
				}
				seen[identity] = struct{}{}

				if peer.Fingerprint != "" && wantManual[identity] {
					rt.Fatalf("step %d: %s is both discovered and manual", step, identity)
				}
				if peer.Fingerprint == "" && !peer.ManuallySupplied {
					rt.Fatalf("step %d: an entry with no fingerprint is not manual", step)
				}

				wantEndpoints, known := model[identity]
				if !known {
					rt.Fatalf("step %d: the list holds an unmodelled entry %s",
						step, identity)
				}
				if len(peer.Endpoints) != len(wantEndpoints) {
					rt.Fatalf("step %d: %s lists %d media, the model says %d",
						step, identity, len(peer.Endpoints), len(wantEndpoints))
				}
				for medium, want := range wantEndpoints {
					got, found := peer.Endpoints[medium]
					if !found {
						rt.Fatalf("step %d: %s is missing medium %s", step, identity, medium)
					}
					if got.Address != want.address || got.Port != want.port {
						rt.Fatalf("step %d: %s on %s is %s:%d, want %s:%d",
							step, identity, medium,
							got.Address, got.Port, want.address, want.port)
					}
				}
			}
		}
	})
}

// TestProperty10PeersAreRemovedWhenEveryMediumHasGoneStale covers
// Property 10: Peers are removed exactly when every medium has gone stale.
//
// "Exactly" is the point: a peer still fresh on one medium stays, even if it went quiet on the other.
//
// Validates: Requirements 1.5
func TestProperty10PeersAreRemovedWhenEveryMediumHasGoneStale(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		clk := newManualClock()
		registry := NewPeerRegistry(1, clk)

		// Each peer is observed on one or both media, at generated times.
		type observation struct {
			fingerprint string
			media       map[Medium]time.Time
		}
		count := rapid.IntRange(1, 8).Draw(rt, "peerCount")
		peers := make([]observation, 0, count)

		for i := 0; i < count; i++ {
			fingerprint := fingerprintFor(i)
			media := map[Medium]time.Time{}

			for _, medium := range []Medium{MediumLAN, MediumBluetooth} {
				if !rapid.Bool().Draw(rt, fmt.Sprintf("seen%d%s", i, medium)) {
					continue
				}
				// Ages either side of the 30-second TTL.
				age := rapid.SampledFrom([]time.Duration{
					0, time.Second, DefaultPeerTTL - time.Nanosecond,
					DefaultPeerTTL, DefaultPeerTTL + time.Second, 2 * DefaultPeerTTL,
				}).Draw(rt, fmt.Sprintf("age%d%s", i, medium))

				// The observation happens at now-minus-age, so the clock is wound back and
				// forward around each one.
				observedAt := baseTime.Add(-age)
				clk.now = observedAt
				outcome := registry.Observe(Announcement{
					DisplayName:     "peer" + strconv.Itoa(i),
					Fingerprint:     fingerprint,
					ProtocolVersion: 1,
					Port:            45770,
				}, medium, "192.0.2.1")
				if outcome.Recorded == nil {
					rt.Fatalf("observing peer %d failed: %+v", i, outcome)
				}
				media[medium] = observedAt
			}

			if len(media) > 0 {
				peers = append(peers, observation{fingerprint, media})
			}
		}

		clk.now = baseTime
		removed := registry.Expire(DefaultPeerTTL)

		// The model: a peer goes exactly when its most recent observation on every medium is
		// at least the TTL old.
		wantRemoved := map[string]bool{}
		for _, peer := range peers {
			allStale := true
			for _, at := range peer.media {
				if baseTime.Sub(at) < DefaultPeerTTL {
					allStale = false
					break
				}
			}
			if allStale {
				wantRemoved[peer.fingerprint] = true
			}
		}

		gotRemoved := map[string]bool{}
		for _, fingerprint := range removed {
			gotRemoved[fingerprint] = true
		}
		for fingerprint := range wantRemoved {
			if !gotRemoved[fingerprint] {
				rt.Fatalf("%s is stale on every medium but was not removed", fingerprint)
			}
		}
		for fingerprint := range gotRemoved {
			if !wantRemoved[fingerprint] {
				rt.Fatalf("%s was removed but is still fresh on some medium", fingerprint)
			}
		}

		// And the list agrees with the removals.
		remaining := map[string]struct{}{}
		for _, peer := range registry.Visible() {
			remaining[peer.Fingerprint] = struct{}{}
		}
		for _, peer := range peers {
			_, present := remaining[peer.fingerprint]
			if wantRemoved[peer.fingerprint] && present {
				rt.Fatalf("%s should have expired but is still visible", peer.fingerprint)
			}
			if !wantRemoved[peer.fingerprint] && !present {
				rt.Fatalf("%s should still be visible but is gone", peer.fingerprint)
			}
		}
	})
}

// TestExpiryBoundaryIsExactlyThirtySeconds pins the TTL of Req 1.5 and the one-fresh-medium rule.
//
// Requirements: 1.5, 1.8
func TestExpiryBoundaryIsExactlyThirtySeconds(t *testing.T) {
	if DefaultPeerTTL != 30*time.Second {
		t.Fatalf("the peer TTL is %s, want 30s", DefaultPeerTTL)
	}

	clk := newManualClock()
	registry := NewPeerRegistry(1, clk)
	announcement := Announcement{
		DisplayName: "laptop", Fingerprint: fingerprintFor(1), ProtocolVersion: 1, Port: 45770,
	}
	registry.Observe(announcement, MediumLAN, "192.0.2.1")

	// One nanosecond inside the window, it stays.
	clk.advance(DefaultPeerTTL - time.Nanosecond)
	if removed := registry.Expire(DefaultPeerTTL); len(removed) != 0 {
		t.Fatalf("removed %v one nanosecond early", removed)
	}

	// At exactly the TTL it goes.
	clk.advance(time.Nanosecond)
	removed := registry.Expire(DefaultPeerTTL)
	if len(removed) != 1 || removed[0] != announcement.Fingerprint {
		t.Fatalf("removed %v, want %s", removed, announcement.Fingerprint)
	}

	// A peer seen on two media, one stale and one fresh, stays: Req 1.5 removes only when every
	// medium has gone quiet.
	clk.now = baseTime
	registry.Observe(announcement, MediumBluetooth, "device-a")
	clk.advance(DefaultPeerTTL + time.Second)
	registry.Observe(announcement, MediumLAN, "192.0.2.1") // fresh on LAN only

	if removed := registry.Expire(DefaultPeerTTL); len(removed) != 0 {
		t.Fatalf("removed %v despite a fresh medium", removed)
	}
	peer := registry.Visible()[0]
	if len(peer.Endpoints) != 2 {
		t.Fatalf("the peer lists %d media, want both retained", len(peer.Endpoints))
	}
}

// TestProperty11InvalidManualEntriesChangeNothing covers
// Property 11: Invalid manual entries change nothing.
//
// Validates: Requirements 1.10
func TestProperty11InvalidManualEntriesChangeNothing(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		clk := newManualClock()
		registry := NewPeerRegistry(1, clk)

		// Some existing entries, so the property checks that a rejection leaves them alone.
		existing := rapid.IntRange(0, 4).Draw(rt, "existing")
		for i := 0; i < existing; i++ {
			registry.Observe(Announcement{
				DisplayName:     "peer" + strconv.Itoa(i),
				Fingerprint:     fingerprintFor(i),
				ProtocolVersion: 1,
				Port:            45770,
			}, MediumLAN, "192.0.2."+strconv.Itoa(i+1))
		}
		before := snapshot(registry)

		host := rapid.SampledFrom([]string{
			"192.0.2.50",      // valid
			"",                // empty
			"not a host",      // spaces
			"999.999.999.999", // out of range octets
			"192.0.2.",        // trailing dot
			"[::1]",           // bracketed literal
		}).Draw(rt, "host")
		port := rapid.SampledFrom([]int{45770, 0, -1, MaxPort, MaxPort + 1, 999999}).
			Draw(rt, "port")

		outcome := registry.AddManual(host, port)

		portValid := port >= MinPort && port <= MaxPort
		switch {
		case outcome.Rejected != nil:
			// Req 1.10: the error names whether the address or the port was rejected, and
			// at least one reason is set.
			if !outcome.Rejected.RejectedAddress() && !outcome.Rejected.RejectedPort() {
				rt.Fatal("a rejection names neither the address nor the port")
			}
			if !portValid && !outcome.Rejected.RejectedPort() {
				rt.Fatalf("port %d is out of range but the rejection does not name it", port)
			}
			if portValid && outcome.Rejected.RejectedPort() {
				rt.Fatalf("port %d is in range but was rejected: %s",
					port, outcome.Rejected.PortReason)
			}
			message := outcome.Rejected.Error()
			if strings.TrimSpace(message) == "" {
				rt.Fatal("a rejection renders as empty")
			}
			if outcome.Rejected.RejectedPort() && !strings.Contains(message, strconv.Itoa(port)) {
				rt.Fatalf("the message %q does not name the port", message)
			}

			// The list is byte-identical before and after.
			if got := snapshot(registry); got != before {
				rt.Fatalf("a rejected manual entry changed the list:\n before %s\n after  %s",
					before, got)
			}

		case outcome.AtCapacity != nil:
			if got := snapshot(registry); got != before {
				rt.Fatal("a capacity rejection changed the list")
			}

		default:
			// Accepted, so both fields were valid.
			if !portValid {
				rt.Fatalf("port %d was accepted but is outside %d..%d", port, MinPort, MaxPort)
			}
			if outcome.Recorded == nil {
				rt.Fatal("an accepted entry returned no record")
			}
			if !outcome.Recorded.Peer.ManuallySupplied {
				rt.Fatal("an accepted manual entry is not marked manually supplied")
			}
		}
	})
}

// snapshot renders the visible Peer list as a stable string, for comparing it before and after an
// operation that must not change it.
func snapshot(registry *PeerRegistry) string {
	peers := registry.Visible()
	var parts []string
	for _, peer := range peers {
		media := make([]string, 0, len(peer.Endpoints))
		for medium, endpoint := range peer.Endpoints {
			media = append(media, fmt.Sprintf("%s=%s:%d@%s",
				medium, endpoint.Address, endpoint.Port, endpoint.LastSeen.Format(time.RFC3339Nano)))
		}
		sortStrings(media)
		parts = append(parts, fmt.Sprintf("%s|%s|v%d|supported=%v|manual=%v|%s",
			peer.Fingerprint, peer.DisplayName, peer.DeclaredProtocolVersion,
			peer.ProtocolSupported, peer.ManuallySupplied, strings.Join(media, ",")))
	}
	sortStrings(parts)
	return strings.Join(parts, "\n")
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// TestManualEntryUpdatesInPlaceForAKnownPeer covers Req 1.7: supplying an address for a peer already in
// the list updates that entry rather than adding a second one.
//
// Requirements: 1.6, 1.7
func TestManualEntryUpdatesInPlaceForAKnownPeer(t *testing.T) {
	clk := newManualClock()
	registry := NewPeerRegistry(1, clk)

	first := registry.AddManual("192.0.2.50", 45770)
	if first.Recorded == nil {
		t.Fatalf("the first manual entry was rejected: %+v", first)
	}
	if !first.Recorded.Added {
		t.Fatal("the first manual entry did not report itself as added")
	}

	// The same address again with a different port updates in place (Req 1.7).
	second := registry.AddManual("192.0.2.50", 45999)
	if second.Recorded == nil {
		t.Fatalf("the second manual entry was rejected: %+v", second)
	}
	if second.Recorded.Added {
		t.Fatal("re-adding the same address reported a new entry")
	}
	if len(registry.Visible()) != 1 {
		t.Fatalf("the list holds %d entries after two adds of one address", len(registry.Visible()))
	}
	endpoint := registry.Visible()[0].Endpoints[MediumLAN]
	if endpoint.Port != 45999 {
		t.Fatalf("the entry holds port %d, want the updated 45999", endpoint.Port)
	}
}

// TestVisibleListIsBoundedAtSixtyFour pins the Req 1.2 ceiling, and the choice to reject rather than
// evict: evicting would let a peer fabricating fingerprints push every genuine peer out one
// announcement at a time.
//
// Requirements: 1.2
func TestVisibleListIsBoundedAtSixtyFour(t *testing.T) {
	if MaxVisiblePeers != 64 {
		t.Fatalf("the visible peer limit is %d, want 64", MaxVisiblePeers)
	}

	clk := newManualClock()
	registry := NewPeerRegistry(1, clk)

	// Fill the list. Fingerprints have to be distinct, so they are built from a two-byte counter
	// rather than the single-byte helper.
	for i := 0; i < MaxVisiblePeers; i++ {
		fingerprint := strings.Repeat(fmt.Sprintf("%04x", i), 16)
		outcome := registry.Observe(Announcement{
			DisplayName:     "peer" + strconv.Itoa(i),
			Fingerprint:     fingerprint,
			ProtocolVersion: 1,
			Port:            45770,
		}, MediumLAN, "192.0.2.1")
		if outcome.Recorded == nil {
			t.Fatalf("peer %d was not recorded: %+v", i, outcome)
		}
	}
	if registry.Len() != MaxVisiblePeers {
		t.Fatalf("the list holds %d entries, want %d", registry.Len(), MaxVisiblePeers)
	}

	// A new fingerprint is turned away, naming the limit, and nothing is evicted.
	overflow := strings.Repeat("ff", 32)
	outcome := registry.Observe(Announcement{
		DisplayName: "one too many", Fingerprint: overflow, ProtocolVersion: 1, Port: 45770,
	}, MediumLAN, "192.0.2.99")
	if outcome.AtCapacity == nil {
		t.Fatalf("a 65th peer was accepted: %+v", outcome)
	}
	if outcome.AtCapacity.Limit != MaxVisiblePeers {
		t.Fatalf("the error names a limit of %d, want %d", outcome.AtCapacity.Limit, MaxVisiblePeers)
	}
	if !strings.Contains(outcome.AtCapacity.Error(), strconv.Itoa(MaxVisiblePeers)) {
		t.Fatalf("the error %q does not name the limit", outcome.AtCapacity.Error())
	}
	if registry.Len() != MaxVisiblePeers {
		t.Fatalf("the rejection changed the count to %d", registry.Len())
	}

	// A fingerprint already in the list still updates, so a full list keeps tracking what it
	// holds.
	known := strings.Repeat("0000", 16)
	update := registry.Observe(Announcement{
		DisplayName: "peer0 renamed", Fingerprint: known, ProtocolVersion: 1, Port: 45999,
	}, MediumBluetooth, "device-a")
	if update.Recorded == nil {
		t.Fatalf("a known fingerprint was turned away by a full list: %+v", update)
	}
	if update.Recorded.Added {
		t.Fatal("updating a known fingerprint reported a new entry")
	}
}

// TestProtocolSupportIsRecordedNotFiltered covers Req 1.2: a peer declaring a version this build does
// not speak stays visible, flagged as unsupported, because that is what tells a user to upgrade.
//
// Requirements: 1.2
func TestProtocolSupportIsRecordedNotFiltered(t *testing.T) {
	clk := newManualClock()
	registry := NewPeerRegistry(1, clk)

	for _, version := range []int{1, 2, 99} {
		fingerprint := fingerprintFor(version)
		outcome := registry.Observe(Announcement{
			DisplayName:     "peer",
			Fingerprint:     fingerprint,
			ProtocolVersion: version,
			Port:            45770,
		}, MediumLAN, "192.0.2.1")
		if outcome.Recorded == nil {
			t.Fatalf("version %d was rejected: %+v", version, outcome)
		}

		peer := outcome.Recorded.Peer
		if peer.DeclaredProtocolVersion != version {
			t.Fatalf("the entry declares version %d, want %d", peer.DeclaredProtocolVersion, version)
		}
		if want := version == 1; peer.ProtocolSupported != want {
			t.Fatalf("version %d reports supported=%v, want %v",
				version, peer.ProtocolSupported, want)
		}
	}
	if registry.Len() != 3 {
		t.Fatalf("the list holds %d entries, want all three including unsupported ones",
			registry.Len())
	}
}

// TestMediaForReportsEveryMediumAPeerWasSeenOn covers the input the transport ranker consumes (Req 2.1).
//
// Requirements: 1.8, 2.1
func TestMediaForReportsEveryMediumAPeerWasSeenOn(t *testing.T) {
	clk := newManualClock()
	registry := NewPeerRegistry(1, clk)
	fingerprint := fingerprintFor(7)
	announcement := Announcement{
		DisplayName: "laptop", Fingerprint: fingerprint, ProtocolVersion: 1, Port: 45770,
	}

	if got := registry.MediaFor(fingerprint); len(got) != 0 {
		t.Fatalf("an unknown peer reports %d media", len(got))
	}
	if got := registry.MediaFor(""); got != nil {
		t.Fatal("an empty fingerprint returned media")
	}

	registry.Observe(announcement, MediumLAN, "192.0.2.1")
	media := registry.MediaFor(fingerprint)
	if len(media) != 1 {
		t.Fatalf("a LAN-only peer reports %d media", len(media))
	}
	if _, found := media[MediumLAN]; !found {
		t.Fatal("a LAN-only peer does not report LAN")
	}

	registry.Observe(announcement, MediumBluetooth, "device-a")
	media = registry.MediaFor(fingerprint)
	if len(media) != 2 {
		t.Fatalf("a dual-medium peer reports %d media", len(media))
	}
}

// TestAnnouncementCodecRejectsMalformedJSON checks the decode path: a datagram that is not an
// announcement is a malformed announcement, not a crash.
//
// Requirements: 1.11
func TestAnnouncementCodecRejectsMalformedJSON(t *testing.T) {
	for _, payload := range []string{
		"", "{", "[]", "null", `{"displayName":123}`, `not json at all`,
	} {
		got := DecodeAndCheckAnnouncement([]byte(payload))
		if got.Malformed == nil {
			t.Fatalf("%q was accepted as an announcement", payload)
		}
		if len(got.Malformed) == 0 {
			t.Fatalf("%q was rejected with no reason", payload)
		}
	}

	// A nil announcement is handled rather than dereferenced.
	if got := CheckAnnouncement(nil); got.Malformed == nil {
		t.Fatal("a nil announcement was accepted")
	}
}
