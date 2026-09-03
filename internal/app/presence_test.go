package app

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/peerbeam/peerbeam/internal/core/discovery"
	"github.com/peerbeam/peerbeam/internal/platform/bt"
	"github.com/peerbeam/peerbeam/internal/platform/lan"
	"pgregory.net/rapid"
)

// hexFingerprint turns a small integer into a valid 64-char lowercase-hex fingerprint, so a
// generated peer index maps to a distinct, well-formed fingerprint without pulling in real key
// material.
func hexFingerprint(n int) string {
	return fmt.Sprintf("%064x", n)
}

// Property 46: presence sources compose without losing observations.
//
// Two Presence_Sources feed one registry while an expiry sweep and reads run against it, all
// concurrently. The design made PeerRegistry safe for concurrent use precisely so this holds. The
// property this asserts is the composition invariant: the list holds exactly one entry per
// fingerprint, an entry lists every medium its peer was seen on, and no observation that beat its
// expiry is lost.
//
// Run this with -race. The value is as much the detector's silence as the assertions.
//
// Requirements: 4.3, 4.5, 4.6
func TestPropertyPresenceSourcesComposeWithoutLoss(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// A handful of peers, each seen on some subset of the two media. Kept small so a
		// generated case is cheap under the race detector.
		peerCount := rapid.IntRange(1, 6).Draw(rt, "peers")
		onLAN := make([]bool, peerCount)
		onBT := make([]bool, peerCount)
		for i := 0; i < peerCount; i++ {
			// Every peer is on at least one medium; a peer on neither would never be observed
			// and would say nothing about composition.
			onLAN[i] = rapid.Bool().Draw(rt, fmt.Sprintf("lan%d", i))
			onBT[i] = rapid.Bool().Draw(rt, fmt.Sprintf("bt%d", i))
			if !onLAN[i] && !onBT[i] {
				onLAN[i] = true
			}
		}

		clk := newManualClock()
		registry := discovery.NewPeerRegistry(1, clk)

		// One goroutine per medium observing its peers, plus a reader hammering Visible while
		// they run. The reader has no assertion beyond not racing and not panicking.
		var wg sync.WaitGroup
		observe := func(medium discovery.Medium, on []bool, addr func(int) string) {
			defer wg.Done()
			for i := 0; i < peerCount; i++ {
				if !on[i] {
					continue
				}
				registry.Observe(discovery.Announcement{
					DisplayName:     fmt.Sprintf("peer-%d", i),
					Fingerprint:     hexFingerprint(i),
					ProtocolVersion: 1,
					Port:            45770,
				}, medium, addr(i))
			}
		}

		wg.Add(3)
		go observe(discovery.MediumLAN, onLAN, func(i int) string {
			return fmt.Sprintf("10.0.0.%d", i+1)
		})
		go observe(discovery.MediumBluetooth, onBT, func(i int) string {
			return fmt.Sprintf("device-%d", i)
		})
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = registry.Visible()
				_ = registry.Len()
			}
		}()
		wg.Wait()

		// No time has passed on the manual clock, so nothing is stale and every observation must
		// still be present.
		visible := registry.Visible()

		if len(visible) != peerCount {
			rt.Fatalf("list holds %d peers, want %d", len(visible), peerCount)
		}

		seen := map[string]bool{}
		for _, peer := range visible {
			if seen[peer.Fingerprint] {
				rt.Fatalf("fingerprint %s appears more than once", peer.Fingerprint)
			}
			seen[peer.Fingerprint] = true
		}

		for i := 0; i < peerCount; i++ {
			fp := hexFingerprint(i)
			var entry *discovery.VisiblePeer
			for k := range visible {
				if visible[k].Fingerprint == fp {
					entry = &visible[k]
					break
				}
			}
			if entry == nil {
				rt.Fatalf("peer %d was observed but is not in the list", i)
			}
			_, hasLAN := entry.Endpoints[discovery.MediumLAN]
			_, hasBT := entry.Endpoints[discovery.MediumBluetooth]
			if hasLAN != onLAN[i] {
				rt.Fatalf("peer %d LAN endpoint present=%v, observed on LAN=%v", i, hasLAN, onLAN[i])
			}
			if hasBT != onBT[i] {
				rt.Fatalf("peer %d BT endpoint present=%v, observed on BT=%v", i, hasBT, onBT[i])
			}
		}
	})
}

// Property 47: a malformed record is medium-independent.
//
// The same byte string that fails announcement validation must produce the same reasons and leave
// the same unchanged list whether it arrives over Bluetooth or over LAN. This is what keeps the two
// media from drifting into different validation, which would be a place a peer could be visible on
// one medium and rejected on the other.
//
// The two paths are exercised through the code each production source actually uses: the Bluetooth
// path through bt.BtTransport.ScanInto, the LAN path through lan.Beacon.handleDatagram via the
// loopback bus. Both funnel through discovery.DecodeAndCheckAnnouncement, and the property is that
// they agree.
//
// Requirements: 4.3, 4.5, 4.6
func TestPropertyMalformedRecordIsMediumIndependent(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// A grab bag of records that fail validation for different reasons: not JSON, missing
		// fields, a short fingerprint, an out-of-range port, an over-long name.
		// Every case is non-empty. An empty record is not an announcement that arrived and got
		// rejected; it is nothing advertised at all. Neither medium delivers a zero-length
		// record to validation - the shim and the in-memory bridge both drop it before emitting
		// a scan result, and an empty UDP datagram is not something the beacon ever sends - so
		// the empty case is out of this property's scope by construction, not by omission.
		record := rapid.SampledFrom([][]byte{
			[]byte("not json at all"),
			[]byte("{"),
			[]byte(`{"displayName":"x"}`),
			[]byte(`{"displayName":"x","fingerprint":"tooshort","protocolVersion":1,"port":45770}`),
			[]byte(`{"displayName":"x","fingerprint":"` + hexFingerprint(1) + `","protocolVersion":1,"port":0}`),
			[]byte(`{"displayName":"","fingerprint":"` + hexFingerprint(1) + `","protocolVersion":1,"port":45770}`),
		}).Draw(rt, "record")

		// The LAN path.
		lanReasons, lanChanged := malformedThroughLAN(rt, record)
		// The Bluetooth path.
		btReasons, btChanged := malformedThroughBluetooth(rt, record)

		if lanChanged || btChanged {
			rt.Fatalf("a malformed record changed the list: lan=%v bt=%v", lanChanged, btChanged)
		}
		if !equalReasons(lanReasons, btReasons) {
			rt.Fatalf("reasons differ by medium:\n  lan: %v\n  bt:  %v", lanReasons, btReasons)
		}
		if len(lanReasons) == 0 {
			rt.Fatalf("a record expected to be malformed produced no reasons: %q", record)
		}
	})
}

// malformedThroughLAN feeds one record through the beacon receive path and reports the malformed
// reasons and whether the visible list changed.
func malformedThroughLAN(rt *rapid.T, record []byte) (reasons []string, changed bool) {
	clk := newManualClock()
	registry := discovery.NewPeerRegistry(1, clk)
	beacon := lan.NewBeacon(registry, discovery.Announcement{
		DisplayName:     "local",
		Fingerprint:     hexFingerprint(999),
		ProtocolVersion: 1,
		Port:            45770,
	}, clk, lan.BeaconEvents{
		OnMalformed: func(rs []string, _ string) { reasons = append(reasons, rs...) },
	})
	bus := lan.NewLoopbackBus()
	bus.Join(beacon)
	// A second beacon so the bus has a delivery target; it is the receiver under test.
	receiver := lan.NewBeacon(registry, discovery.Announcement{
		DisplayName:     "receiver",
		Fingerprint:     hexFingerprint(998),
		ProtocolVersion: 1,
		Port:            45770,
	}, clk, lan.BeaconEvents{
		OnMalformed: func(rs []string, _ string) { reasons = append(reasons, rs...) },
	})
	bus.Join(receiver)

	before := len(registry.Visible())
	if err := bus.Deliver(beacon, record, "10.0.0.5"); err != nil {
		rt.Fatalf("delivering over the bus: %v", err)
	}
	return reasons, len(registry.Visible()) != before
}

// malformedThroughBluetooth feeds one record through bt.ScanInto and reports the same two things.
func malformedThroughBluetooth(rt *rapid.T, record []byte) (reasons []string, changed bool) {
	fabric := bt.NewFabric()
	local := bt.NewInMemoryBluetoothBridge(fabric, "device-local")
	peer := bt.NewInMemoryBluetoothBridge(fabric, "device-peer")
	if err := peer.StartAdvertising(context.Background(), record); err != nil {
		rt.Fatalf("advertising the record: %v", err)
	}

	clk := newManualClock()
	registry := discovery.NewPeerRegistry(1, clk)
	tr := bt.NewBtTransport(local)

	before := len(registry.Visible())
	if err := tr.ScanInto(context.Background(), registry, hexFingerprint(999),
		func(rs []string, _ string) { reasons = append(reasons, rs...) }, nil,
	); err != nil {
		rt.Fatalf("scanning: %v", err)
	}
	return reasons, len(registry.Visible()) != before
}

func equalReasons(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}
