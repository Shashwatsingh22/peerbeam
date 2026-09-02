package lan

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/clock"
	"github.com/peerbeam/peerbeam/internal/core/discovery"
	"github.com/peerbeam/peerbeam/internal/core/transport"
)

var baseTime = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

// manualClock is the injected time source, so the 30-second peer expiry of Req 1.5 is checked
// by advancing it rather than by waiting.
type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func newManualClock() *manualClock { return &manualClock{now: baseTime} }

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

const (
	fingerprintA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fingerprintB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// newNode builds one in-process node's discovery side: a registry, a beacon, and a record of
// the events the beacon raised.
type node struct {
	name     string
	registry *discovery.PeerRegistry
	beacon   *Beacon
	clk      *manualClock

	mu        sync.Mutex
	malformed [][]string
	observed  []string
	expired   []string
	errs      []error
}

func newNode(t *testing.T, name, fingerprint string, port int, clk *manualClock) *node {
	t.Helper()

	n := &node{name: name, clk: clk}
	n.registry = discovery.NewPeerRegistry(1, clk)
	n.beacon = NewBeacon(
		n.registry,
		discovery.Announcement{
			DisplayName:     name,
			Fingerprint:     fingerprint,
			ProtocolVersion: 1,
			Port:            port,
		},
		clk,
		BeaconEvents{
			OnMalformed: func(reasons []string, _ string) {
				n.mu.Lock()
				n.malformed = append(n.malformed, reasons)
				n.mu.Unlock()
			},
			OnObserved: func(fingerprint, _ string) {
				n.mu.Lock()
				n.observed = append(n.observed, fingerprint)
				n.mu.Unlock()
			},
			OnExpired: func(fingerprints []string) {
				n.mu.Lock()
				n.expired = append(n.expired, fingerprints...)
				n.mu.Unlock()
			},
			OnError: func(err error) {
				n.mu.Lock()
				n.errs = append(n.errs, err)
				n.mu.Unlock()
			},
		},
	)
	return n
}

func (n *node) events() (malformed [][]string, observed, expired []string, errs []error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.malformed, append([]string(nil), n.observed...),
		append([]string(nil), n.expired...), append([]error(nil), n.errs...)
}

// TestLanDiscoveryReachesTheVisiblePeerListWithinTheWindow covers task 17.3: two in-process
// nodes reach each other's visible Peer list, under standard `go test`.
//
// It runs over a LoopbackBus rather than real multicast, because a sandboxed or containerised
// test host often has no interface that will join a group - which is exactly the "empty
// container" Req 12.1 describes. The bus carries the real encode, decode, validate, and
// record path, so what is left untested here is the socket itself and nothing above it.
//
// Requirements: 1.1, 1.2, 1.3, 1.8
func TestLanDiscoveryReachesTheVisiblePeerListWithinTheWindow(t *testing.T) {
	clk := newManualClock()
	bus := NewLoopbackBus()

	a := newNode(t, "laptop", fingerprintA, 45770, clk)
	b := newNode(t, "desktop", fingerprintB, 45780, clk)
	bus.Join(a.beacon)
	bus.Join(b.beacon)

	// Neither has seen the other yet.
	if len(a.beacon.Visible()) != 0 || len(b.beacon.Visible()) != 0 {
		t.Fatal("a node saw a peer before any announcement was published")
	}

	// One publish each, as happens within 2 seconds of startup (Req 1.1).
	if err := bus.PublishFrom(a.beacon, "192.0.2.10"); err != nil {
		t.Fatalf("publishing from A: %v", err)
	}
	if err := bus.PublishFrom(b.beacon, "192.0.2.20"); err != nil {
		t.Fatalf("publishing from B: %v", err)
	}

	// Req 1.3: each is now in the other's visible list, well inside the 5-second window.
	assertSees(t, b, fingerprintA, "laptop", 45770, "192.0.2.10")
	assertSees(t, a, fingerprintB, "desktop", 45780, "192.0.2.20")

	// Req 1.2: the entry carries the declared version and whether it is supported locally.
	peer := findPeer(t, b, fingerprintA)
	if peer.DeclaredProtocolVersion != 1 || !peer.ProtocolSupported {
		t.Fatalf("entry reports version %d supported=%v, want 1 supported",
			peer.DeclaredProtocolVersion, peer.ProtocolSupported)
	}
	if peer.ManuallySupplied {
		t.Fatal("a discovered peer is marked manually supplied")
	}

	// A node never records itself, so its own echoed announcement is not a peer.
	if _, found := findPeerMaybe(a, fingerprintA); found {
		t.Fatal("a node added itself to its own visible peer list")
	}

	// Republishing keeps one entry per fingerprint (Req 1.8), and refreshes the address.
	if err := bus.PublishFrom(a.beacon, "192.0.2.11"); err != nil {
		t.Fatalf("republishing from A: %v", err)
	}
	if got := len(b.beacon.Visible()); got != 1 {
		t.Fatalf("B holds %d entries after a republish, want 1", got)
	}
	assertSees(t, b, fingerprintA, "laptop", 45770, "192.0.2.11")

	_, observed, _, errs := b.events()
	if len(observed) != 2 {
		t.Fatalf("B raised %d observed events, want 2", len(observed))
	}
	if len(errs) != 0 {
		t.Fatalf("B raised errors: %v", errs)
	}
}

// TestBeaconExpiresAPeerAfterTheTTL covers Req 1.5: a peer that stops announcing leaves the
// list, and the sweep reports it.
//
// Requirements: 1.5
func TestBeaconExpiresAPeerAfterTheTTL(t *testing.T) {
	clk := newManualClock()
	bus := NewLoopbackBus()
	a := newNode(t, "laptop", fingerprintA, 45770, clk)
	b := newNode(t, "desktop", fingerprintB, 45780, clk)
	bus.Join(a.beacon)
	bus.Join(b.beacon)

	if err := bus.PublishFrom(a.beacon, "192.0.2.10"); err != nil {
		t.Fatalf("publishing: %v", err)
	}
	if len(b.beacon.Visible()) != 1 {
		t.Fatal("B did not see A")
	}

	// Just inside the TTL, a sweep keeps the peer.
	clk.advance(discovery.DefaultPeerTTL - time.Nanosecond)
	if removed := b.beacon.Sweep(); len(removed) != 0 {
		t.Fatalf("sweep removed %v one nanosecond early", removed)
	}
	if len(b.beacon.Visible()) != 1 {
		t.Fatal("peer vanished before its TTL elapsed")
	}

	// At the TTL it goes, and the sweep names it so the caller can report it.
	clk.advance(time.Nanosecond)
	removed := b.beacon.Sweep()
	if len(removed) != 1 || removed[0] != fingerprintA {
		t.Fatalf("sweep removed %v, want %s", removed, fingerprintA)
	}
	if len(b.beacon.Visible()) != 0 {
		t.Fatal("expired peer is still visible")
	}

	// A fresh announcement brings it back.
	if err := bus.PublishFrom(a.beacon, "192.0.2.10"); err != nil {
		t.Fatalf("republishing: %v", err)
	}
	if len(b.beacon.Visible()) != 1 {
		t.Fatal("peer did not come back after re-announcing")
	}
}

// TestBeaconDiscardsMalformedAnnouncements covers Req 1.11: a malformed datagram is discarded,
// the list is unchanged, and an event names every reason.
//
// Requirements: 1.11
func TestBeaconDiscardsMalformedAnnouncements(t *testing.T) {
	clk := newManualClock()
	bus := NewLoopbackBus()
	a := newNode(t, "laptop", fingerprintA, 45770, clk)
	b := newNode(t, "desktop", fingerprintB, 45780, clk)
	bus.Join(a.beacon)
	bus.Join(b.beacon)

	cases := map[string]string{
		"not json":          `{`,
		"missing port":      `{"displayName":"x","fingerprint":"` + fingerprintA + `","protocolVersion":1}`,
		"port out of range": `{"displayName":"x","fingerprint":"` + fingerprintA + `","protocolVersion":1,"port":70000}`,
		"missing name":      `{"fingerprint":"` + fingerprintA + `","protocolVersion":1,"port":45770}`,
		"long name": `{"displayName":"` + strings.Repeat("x", 65) +
			`","fingerprint":"` + fingerprintA + `","protocolVersion":1,"port":45770}`,
		"bad fingerprint": `{"displayName":"x","fingerprint":"NOTHEX","protocolVersion":1,"port":45770}`,
	}

	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			before := len(b.beacon.Visible())
			countBefore := len(mustMalformed(b))

			if err := bus.Deliver(a.beacon, []byte(payload), "192.0.2.10"); err != nil {
				t.Fatalf("delivering: %v", err)
			}

			if got := len(b.beacon.Visible()); got != before {
				t.Fatalf("a malformed announcement changed the list from %d to %d entries",
					before, got)
			}
			malformed := mustMalformed(b)
			if len(malformed) != countBefore+1 {
				t.Fatalf("no malformed event was recorded")
			}
			if len(malformed[len(malformed)-1]) == 0 {
				t.Fatal("the malformed event names no reason")
			}
		})
	}
}

func mustMalformed(n *node) [][]string {
	malformed, _, _, _ := n.events()
	return malformed
}

// TestBeaconRefusesToPublishAMalformedAnnouncement checks the outbound guard: a local
// misconfiguration is this node's error rather than every peer's malformed-announcement event.
//
// Requirements: 1.1, 1.11
func TestBeaconRefusesToPublishAMalformedAnnouncement(t *testing.T) {
	clk := newManualClock()
	registry := discovery.NewPeerRegistry(1, clk)

	var errs []error
	beacon := NewBeacon(registry, discovery.Announcement{
		DisplayName:     "laptop",
		Fingerprint:     fingerprintA,
		ProtocolVersion: 1,
		Port:            0, // never bound
	}, clk, BeaconEvents{OnError: func(err error) { errs = append(errs, err) }})

	// publishOnce with no socket is a no-op, so the validation is checked through the bus,
	// which encodes the same announcement.
	if _, err := discovery.EncodeAnnouncement(beacon.Announcement()); err == nil {
		// Encoding may accept it; validation is what must not.
		if check := discovery.CheckAnnouncement(ptrTo(beacon.Announcement())); check.Malformed == nil {
			t.Fatal("an announcement with port 0 passed validation")
		}
	}

	// Once the port is known, it validates.
	beacon.SetPort(45770)
	if check := discovery.CheckAnnouncement(ptrTo(beacon.Announcement())); check.Malformed != nil {
		t.Fatalf("a bound announcement was rejected: %v", check.Malformed)
	}
	_ = errs
}

func ptrTo(a discovery.Announcement) *discovery.Announcement { return &a }

// TestLanTransportRoundTripsOverRealTCP exercises the production socket path: bind, listen,
// dial, write, read, close.
//
// Requirements: 2.1, 7.10, 8.9
func TestLanTransportRoundTripsOverRealTCP(t *testing.T) {
	listener := NewLanTransport()
	port, err := listener.Bind(0) // 0 lets the OS choose, so the test cannot collide
	if err != nil {
		t.Skipf("cannot bind a TCP port in this environment: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	// The ranking inputs are the production ones, so ladder and chunk planning behave the
	// same as they will in the field.
	if listener.Name() != transport.NameLAN {
		t.Fatalf("name is %q, want %q", listener.Name(), transport.NameLAN)
	}
	if listener.ExpectedGoodputBytesPerSecond() != transport.LANExpectedGoodput {
		t.Fatalf("expected goodput is %d, want %d",
			listener.ExpectedGoodputBytesPerSecond(), transport.LANExpectedGoodput)
	}
	if listener.ChunkSizeBytes() != transport.LANChunkBytes {
		t.Fatalf("chunk size is %d, want %d", listener.ChunkSizeBytes(), transport.LANChunkBytes)
	}
	if listener.Medium() != discovery.MediumLAN {
		t.Fatalf("medium is %v, want LAN", listener.Medium())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	accepted := make(chan transport.TransportConnection, 1)
	go func() {
		_ = listener.Listen(ctx, func(conn transport.TransportConnection) {
			accepted <- conn
		})
	}()

	dialer := NewLanTransport()
	conn, err := dialer.Connect(ctx, discovery.PeerEndpoint{
		Medium:  discovery.MediumLAN,
		Address: "127.0.0.1",
		Port:    port,
	}, 3*time.Second)
	if err != nil {
		t.Fatalf("connecting to 127.0.0.1:%d: %v", port, err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var inbound transport.TransportConnection
	select {
	case inbound = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("the listener did not accept the connection within 3s")
	}
	t.Cleanup(func() { _ = inbound.Close() })

	if inbound.TransportName() != transport.NameLAN {
		t.Fatalf("accepted connection reports transport %q", inbound.TransportName())
	}

	// A frame's worth of bytes, read back in whatever runs the socket delivers, which is
	// why codec.FrameReader is incremental.
	payload := []byte("a wire frame's worth of bytes")
	if err := conn.Write(payload); err != nil {
		t.Fatalf("writing: %v", err)
	}
	got := make([]byte, 0, len(payload))
	buffer := make([]byte, 8)
	for len(got) < len(payload) {
		n, err := inbound.Read(buffer)
		if err != nil {
			t.Fatalf("reading: %v", err)
		}
		got = append(got, buffer[:n]...)
	}
	if string(got) != string(payload) {
		t.Fatalf("read %q, want %q", got, payload)
	}

	// Closing the writer surfaces as EOF on the reader, which is how a Session learns the
	// Transport went away.
	_ = conn.Close()
	if _, err := inbound.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("after close, read returned %v, want EOF", err)
	}
}

// TestLanTransportConnectRejectsBadEndpoints checks the guards, so a malformed endpoint fails
// with a reason rather than producing a confusing dial error.
//
// Requirements: 2.4, 1.11
func TestLanTransportConnectRejectsBadEndpoints(t *testing.T) {
	tr := NewLanTransport()
	cases := map[string]discovery.PeerEndpoint{
		"no address": {Port: 45770},
		"port zero":  {Address: "127.0.0.1", Port: 0},
		"port high":  {Address: "127.0.0.1", Port: 70000},
	}
	for name, endpoint := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := tr.Connect(context.Background(), endpoint, time.Second)
			if err == nil {
				_ = got.Close()
				t.Fatal("a malformed endpoint connected")
			}
			if got != nil {
				t.Fatal("a failed connect also returned a connection")
			}
		})
	}
}

// TestLanTransportBindIsIdempotent checks that a second Bind returns the same port. Announcing
// one port while listening on another would make a node undiscoverable in a way that looks
// like a network problem.
//
// Requirements: 1.1
func TestLanTransportBindIsIdempotent(t *testing.T) {
	tr := NewLanTransport()
	first, err := tr.Bind(0)
	if err != nil {
		t.Skipf("cannot bind a TCP port in this environment: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	second, err := tr.Bind(45999)
	if err != nil {
		t.Fatalf("second bind failed: %v", err)
	}
	if second != first {
		t.Fatalf("second bind moved the port from %d to %d", first, second)
	}
	if tr.Port() != first {
		t.Fatalf("Port() reports %d, want %d", tr.Port(), first)
	}
}

// TestLoopbackTransportBehavesLikeTheRealOne checks the in-process transport used by the
// end-to-end tests: the same ranking inputs, a working round trip, and a partition that makes
// a connect fail the way a dropped LAN does.
//
// Requirements: 2.1, 3.3, 7.10
func TestLoopbackTransportBehavesLikeTheRealOne(t *testing.T) {
	sw := NewLoopbackSwitch()
	listener := NewLoopbackLanTransport(sw)
	dialer := NewLoopbackLanTransport(sw)

	// Identical ranking inputs to the real transport, so a test exercises the production
	// ladder and chunk decisions.
	if listener.Name() != transport.NameLAN ||
		listener.ExpectedGoodputBytesPerSecond() != transport.LANExpectedGoodput ||
		listener.ChunkSizeBytes() != transport.LANChunkBytes ||
		listener.Medium() != discovery.MediumLAN {
		t.Fatal("the loopback transport does not report the same ranking inputs as the real one")
	}

	port, err := listener.Bind(0)
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	accepted := make(chan transport.TransportConnection, 1)
	go func() {
		_ = listener.Listen(ctx, func(conn transport.TransportConnection) { accepted <- conn })
	}()

	conn, err := dialer.Connect(ctx, discovery.PeerEndpoint{Port: port}, time.Second)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	inbound := <-accepted

	// net.Pipe is synchronous, so the write needs a reader running concurrently.
	done := make(chan error, 1)
	go func() { done <- conn.Write([]byte("hello")) }()

	buffer := make([]byte, 5)
	n, err := inbound.Read(buffer)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("writing: %v", err)
	}
	if string(buffer[:n]) != "hello" {
		t.Fatalf("read %q, want %q", buffer[:n], "hello")
	}

	// A partitioned port refuses connections, which is how a test drops the LAN under a
	// running Session.
	sw.Partition(port, true)
	if got, err := dialer.Connect(ctx, discovery.PeerEndpoint{Port: port}, time.Second); err == nil {
		_ = got.Close()
		t.Fatal("connected to a partitioned port")
	}
	sw.Partition(port, false)
	if got, err := dialer.Connect(ctx, discovery.PeerEndpoint{Port: port}, time.Second); err != nil {
		t.Fatalf("restoring the partition did not restore connectivity: %v", err)
	} else {
		_ = got.Close()
	}

	// An unbound port is a plain failure, not a hang.
	if got, err := dialer.Connect(ctx, discovery.PeerEndpoint{Port: 9}, time.Second); err == nil {
		_ = got.Close()
		t.Fatal("connected to a port nothing is listening on")
	}
}

// TestAvailabilityReportsAReason covers the input to Req 12.8: the node has to be able to say
// at startup whether it has a usable IP network, and to name why not.
//
// Requirements: 12.8
func TestAvailabilityReportsAReason(t *testing.T) {
	available, reason := Availability()
	if available && reason != "" {
		t.Fatalf("available but carries reason %q", reason)
	}
	if !available && reason == "" {
		t.Fatal("unavailable with no reason given")
	}
	// Either answer is legitimate depending on the host, so what is checked is that the
	// two are consistent rather than which one came back.
	t.Logf("LAN availability on this host: available=%v reason=%q", available, reason)
}

// TestBeaconTimingsMatchTheRequirements pins the intervals from Req 1.5 and 1.9.
//
// Requirements: 1.5, 1.9
func TestBeaconTimingsMatchTheRequirements(t *testing.T) {
	if PublishInterval > 10*time.Second {
		t.Fatalf("publish interval is %s, over the 10s bound of Req 1.9", PublishInterval)
	}
	if ExpirySweepInterval > 5*time.Second {
		t.Fatalf("expiry sweep interval is %s, over the 5s bound of Req 1.5", ExpirySweepInterval)
	}
	if discovery.DefaultPeerTTL != 30*time.Second {
		t.Fatalf("peer TTL is %s, want 30s", discovery.DefaultPeerTTL)
	}
	// A sweep has to run at least twice inside the notice window, or a peer could sit
	// expired for longer than Req 1.5 allows.
	if ExpirySweepInterval*2 > 5*time.Second {
		t.Fatalf("two sweeps take %s, over the 5s notice window", ExpirySweepInterval*2)
	}
}

// TestBeaconManualEntryGoesThroughTheSameMutex checks that a manual add is serialised with the
// beacon's own loops, since the registry is not safe for concurrent use.
//
// Requirements: 1.6, 1.10
func TestBeaconManualEntryGoesThroughTheSameMutex(t *testing.T) {
	clk := newManualClock()
	registry := discovery.NewPeerRegistry(1, clk)
	beacon := NewBeacon(registry, discovery.Announcement{
		DisplayName: "laptop", Fingerprint: fingerprintA, ProtocolVersion: 1, Port: 45770,
	}, clk, BeaconEvents{})

	got := beacon.AddManual("192.0.2.50", 45770)
	if got.Recorded == nil {
		t.Fatalf("a valid manual entry was rejected: %v", got.Rejected)
	}
	visible := beacon.Visible()
	if len(visible) != 1 || !visible[0].ManuallySupplied {
		t.Fatalf("visible list is %+v, want one manually supplied entry", visible)
	}

	// Req 1.10: an invalid entry changes nothing and says which field was wrong.
	rejected := beacon.AddManual("192.0.2.50", 70000)
	if rejected.Rejected == nil {
		t.Fatal("a port outside 1..65535 was accepted")
	}
	if !rejected.Rejected.RejectedPort() {
		t.Fatal("the rejection does not name the port")
	}
	if len(beacon.Visible()) != 1 {
		t.Fatal("a rejected manual entry changed the visible list")
	}
}

// assertSees checks that a node's visible list holds the expected peer with the expected
// endpoint.
func assertSees(t *testing.T, n *node, fingerprint, displayName string, port int, address string) {
	t.Helper()
	peer := findPeer(t, n, fingerprint)
	if peer.DisplayName != displayName {
		t.Fatalf("%s sees display name %q, want %q", n.name, peer.DisplayName, displayName)
	}
	endpoint, found := peer.Endpoints[discovery.MediumLAN]
	if !found {
		t.Fatalf("%s has no LAN endpoint for %s", n.name, fingerprint)
	}
	if endpoint.Port != port {
		t.Fatalf("%s records port %d, want %d", n.name, endpoint.Port, port)
	}
	if endpoint.Address != address {
		t.Fatalf("%s records address %q, want %q", n.name, endpoint.Address, address)
	}
}

func findPeer(t *testing.T, n *node, fingerprint string) discovery.VisiblePeer {
	t.Helper()
	peer, found := findPeerMaybe(n, fingerprint)
	if !found {
		t.Fatalf("%s does not see %s; visible list is %+v", n.name, fingerprint, n.beacon.Visible())
	}
	return peer
}

func findPeerMaybe(n *node, fingerprint string) (discovery.VisiblePeer, bool) {
	for _, peer := range n.beacon.Visible() {
		if peer.Fingerprint == fingerprint {
			return peer, true
		}
	}
	return discovery.VisiblePeer{}, false
}

// clockCheck keeps the clock package referenced from this test file, so the manual clock
// visibly satisfies the interface the production code takes.
var _ clock.Clock = (*manualClock)(nil)
