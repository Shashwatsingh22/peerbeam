package bt

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/clock"
	"github.com/peerbeam/peerbeam/internal/core/discovery"
	"github.com/peerbeam/peerbeam/internal/core/transport"
)

var baseTime = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

type manualClock struct{ now time.Time }

func (c *manualClock) Now() time.Time { return c.now }

const (
	fingerprintA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fingerprintB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// TestBtTransportReportsTheRequirementFigures pins the two values this adapter exists to supply:
// the Req 2.1 goodput that puts Bluetooth below LAN, and the Req 7.10 chunk size.
//
// Requirements: 2.1, 7.10
func TestBtTransportReportsTheRequirementFigures(t *testing.T) {
	fabric := NewFabric()
	tr := NewBtTransport(NewInMemoryBluetoothBridge(fabric, "device-a"))

	if tr.Name() != transport.NameBT {
		t.Fatalf("name is %q, want %q", tr.Name(), transport.NameBT)
	}
	if tr.Medium() != discovery.MediumBluetooth {
		t.Fatalf("medium is %v, want Bluetooth", tr.Medium())
	}
	if got := tr.ExpectedGoodputBytesPerSecond(); got != transport.BTExpectedGoodput {
		t.Fatalf("expected goodput is %d, want %d", got, transport.BTExpectedGoodput)
	}
	if got := tr.ChunkSizeBytes(); got != transport.BTChunkBytes {
		t.Fatalf("chunk size is %d, want %d", got, transport.BTChunkBytes)
	}
	// The whole point of the figure: LAN outranks Bluetooth without consulting a measurement.
	if transport.BTExpectedGoodput >= transport.LANExpectedGoodput {
		t.Fatal("bluetooth does not rank below LAN, so the ladder would try it first")
	}
	// A chunk plus its frame header and AEAD tag has to fit one link write, which is what the
	// 512-byte chunk size is chosen for.
	if transport.BTChunkBytes+14+16 > RFCOMMMaxWriteBytes {
		t.Fatalf("a %d-byte chunk plus header and tag exceeds the %d-byte link write limit",
			transport.BTChunkBytes, RFCOMMMaxWriteBytes)
	}
}

// TestBluetoothUnavailableStartupCoversReq123 covers task 18.5: a host with no Bluetooth starts
// with LAN as its only candidate and says BT_Transport is unavailable.
//
// Requirements: 12.3
func TestBluetoothUnavailableStartupCoversReq123(t *testing.T) {
	// A nil bridge is the wiring mistake this guards: it must degrade to unavailable rather
	// than panic on first use.
	tr := NewBtTransport(nil)
	if tr.Available() {
		t.Fatal("a transport with no bridge reports itself available")
	}
	report, unavailable := tr.Unavailable()
	if !unavailable {
		t.Fatal("no unavailability report from a transport with no bridge")
	}
	if report.TransportName != transport.NameBT {
		t.Fatalf("report names %q, want %q", report.TransportName, transport.NameBT)
	}
	if strings.TrimSpace(report.Reason) == "" {
		t.Fatal("the report carries no reason")
	}
	if !strings.Contains(report.Error(), transport.NameBT) {
		t.Fatalf("rendered report %q does not name the transport", report.Error())
	}

	// Every operation fails with the sentinel, so a caller can tell "this host has no
	// Bluetooth" from "the Bluetooth we have just broke".
	ctx := context.Background()
	if _, err := tr.Connect(ctx, discovery.PeerEndpoint{Address: "device-b"}, time.Second); !errors.Is(err, ErrBluetoothUnavailable) {
		t.Fatalf("Connect returned %v, want ErrBluetoothUnavailable", err)
	}
	if err := tr.Listen(ctx, nil); !errors.Is(err, ErrBluetoothUnavailable) {
		t.Fatalf("Listen returned %v, want ErrBluetoothUnavailable", err)
	}
	if err := tr.StartAdvertising(ctx, []byte("record")); !errors.Is(err, ErrBluetoothUnavailable) {
		t.Fatalf("StartAdvertising returned %v, want ErrBluetoothUnavailable", err)
	}
	// Stopping something that never started is not an error worth reporting.
	if err := tr.StopAdvertising(ctx); err != nil {
		t.Fatalf("StopAdvertising on an unavailable bridge returned %v", err)
	}

	// The named reason survives into the report, so an operator learns why rather than only
	// that.
	named := NewBtTransport(NewUnavailableBridge("no bluetooth shim at ~/.peerbeam/bin"))
	report, _ = named.Unavailable()
	if !strings.Contains(report.Reason, "shim") {
		t.Fatalf("report reason %q lost the specific cause", report.Reason)
	}

	// And a candidate list built from an unavailable Bluetooth plus an available LAN medium
	// leaves only LAN, which is the Req 12.3 outcome.
	lanOnly := map[discovery.Medium]struct{}{discovery.MediumLAN: {}}
	candidates := transport.CandidateTransports([]transport.Transport{tr}, lanOnly)
	if len(candidates) != 0 {
		t.Fatalf("a bluetooth transport was a candidate for a LAN-only peer: %v", candidates)
	}
}

// TestInMemoryBridgeRoundTripsAStream checks the test double the end-to-end tests depend on: two
// bridges on one fabric connect, and bytes cross intact.
//
// Requirements: 2.1, 7.10
func TestInMemoryBridgeRoundTripsAStream(t *testing.T) {
	fabric := NewFabric()
	a := NewInMemoryBluetoothBridge(fabric, "device-a")
	b := NewInMemoryBluetoothBridge(fabric, "device-b")

	if !a.Available() || !b.Available() {
		t.Fatal("a fresh in-memory bridge reports itself unavailable")
	}
	if a.MaxWriteBytes() != RFCOMMMaxWriteBytes {
		t.Fatalf("max write is %d, want the RFCOMM limit %d", a.MaxWriteBytes(), RFCOMMMaxWriteBytes)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	accepted := make(chan transport.TransportConnection, 1)
	go func() {
		_ = b.Accept(ctx, func(conn transport.TransportConnection) { accepted <- conn })
	}()

	conn, err := a.Connect(ctx, "device-b", time.Second)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	inbound := <-accepted

	if conn.TransportName() != transport.NameBT || inbound.TransportName() != transport.NameBT {
		t.Fatal("a bluetooth connection does not report itself as BT_Transport")
	}

	// A payload larger than one link write, so the splitting in btConnection.Write is
	// exercised rather than bypassed.
	payload := make([]byte, RFCOMMMaxWriteBytes*2+7)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	// net.Pipe is synchronous, so the write needs a concurrent reader.
	writeDone := make(chan error, 1)
	go func() { writeDone <- conn.Write(payload) }()

	got := make([]byte, 0, len(payload))
	buffer := make([]byte, 300)
	for len(got) < len(payload) {
		n, err := inbound.Read(buffer)
		if err != nil {
			t.Fatalf("reading after %d of %d bytes: %v", len(got), len(payload), err)
		}
		got = append(got, buffer[:n]...)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("writing: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatal("the payload did not survive the link intact")
	}

	_ = conn.Close()
	_ = inbound.Close()
}

// TestInMemoryBridgeConnectFailures checks the paths a Session has to survive: an unknown device,
// a device out of range, and a device whose Bluetooth was turned off.
//
// Requirements: 2.4, 3.3, 12.3
func TestInMemoryBridgeConnectFailures(t *testing.T) {
	fabric := NewFabric()
	a := NewInMemoryBluetoothBridge(fabric, "device-a")
	b := NewInMemoryBluetoothBridge(fabric, "device-b")
	ctx := context.Background()

	// Nothing accepting yet is still a connect: the fabric buffers one.
	if _, err := a.Connect(ctx, "device-nowhere", time.Second); err == nil {
		t.Fatal("connected to a device that is not on the fabric")
	}

	// Out of range, which is how a test drops the Bluetooth link under a running Session.
	fabric.Partition("device-b", true)
	_, err := a.Connect(ctx, "device-b", time.Second)
	if err == nil {
		t.Fatal("connected to a partitioned device")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("error %q does not say the device was unreachable", err)
	}
	fabric.Partition("device-b", false)

	// The target's Bluetooth turned off.
	b.SetAvailable(false)
	if _, err := a.Connect(ctx, "device-b", time.Second); !errors.Is(err, ErrBluetoothUnavailable) {
		t.Fatalf("connecting to a device with bluetooth off returned %v", err)
	}
	b.SetAvailable(true)

	// Our own Bluetooth turned off.
	a.SetAvailable(false)
	if _, err := a.Connect(ctx, "device-b", time.Second); !errors.Is(err, ErrBluetoothUnavailable) {
		t.Fatalf("connecting with our own bluetooth off returned %v", err)
	}

	// A cancelled context fails immediately rather than blocking.
	a.SetAvailable(true)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Connect(cancelled, "device-b", time.Second); err == nil {
		t.Fatal("a cancelled connect succeeded")
	}
}

// TestScanIntoFeedsThePeerRegistry covers the Bluetooth half of discovery: a scanned record goes
// through the same validation as a LAN datagram and lands in the visible Peer list with the
// device id as its address.
//
// Requirements: 1.4, 1.8, 1.11
func TestScanIntoFeedsThePeerRegistry(t *testing.T) {
	fabric := NewFabric()
	local := NewInMemoryBluetoothBridge(fabric, "device-local")
	peer := NewInMemoryBluetoothBridge(fabric, "device-peer")

	announcement := discovery.Announcement{
		DisplayName:     "desktop",
		Fingerprint:     fingerprintB,
		ProtocolVersion: 1,
		Port:            45770,
	}
	record, err := discovery.EncodeAnnouncement(announcement)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if err := peer.StartAdvertising(context.Background(), record); err != nil {
		t.Fatalf("advertising: %v", err)
	}

	registry := discovery.NewPeerRegistry(1, &manualClock{now: baseTime})
	tr := NewBtTransport(local)

	var observed []string
	var malformed [][]string
	if err := tr.ScanInto(context.Background(), registry, fingerprintA,
		func(reasons []string, _ string) { malformed = append(malformed, reasons) },
		func(fingerprint, _ string) { observed = append(observed, fingerprint) },
	); err != nil {
		t.Fatalf("scanning: %v", err)
	}

	if len(malformed) != 0 {
		t.Fatalf("a well-formed record was reported malformed: %v", malformed)
	}
	if len(observed) != 1 || observed[0] != fingerprintB {
		t.Fatalf("observed %v, want just %s", observed, fingerprintB)
	}

	visible := registry.Visible()
	if len(visible) != 1 {
		t.Fatalf("registry holds %d peers, want 1", len(visible))
	}
	endpoint, found := visible[0].Endpoints[discovery.MediumBluetooth]
	if !found {
		t.Fatal("the peer has no bluetooth endpoint")
	}
	// Req 1.8: the address for this medium is the device id, which is what Connect dials.
	if endpoint.Address != "device-peer" {
		t.Fatalf("endpoint address is %q, want the device id", endpoint.Address)
	}

	// Req 1.11: a malformed record is discarded with a reason and changes nothing.
	if err := peer.StartAdvertising(context.Background(), []byte(`{"displayName":"x"}`)); err != nil {
		t.Fatalf("advertising a malformed record: %v", err)
	}
	before := len(registry.Visible())
	malformed = nil
	if err := tr.ScanInto(context.Background(), registry, fingerprintA,
		func(reasons []string, _ string) { malformed = append(malformed, reasons) }, nil,
	); err != nil {
		t.Fatalf("scanning: %v", err)
	}
	if len(malformed) != 1 || len(malformed[0]) == 0 {
		t.Fatalf("malformed events were %v, want one with reasons", malformed)
	}
	if len(registry.Visible()) != before {
		t.Fatal("a malformed record changed the visible peer list")
	}
}

// TestScanIntoSkipsOurOwnRecord checks that a node reflecting its own advertisement does not add
// itself as a peer.
//
// Requirements: 1.2
func TestScanIntoSkipsOurOwnRecord(t *testing.T) {
	fabric := NewFabric()
	local := NewInMemoryBluetoothBridge(fabric, "device-local")
	mirror := NewInMemoryBluetoothBridge(fabric, "device-mirror")

	own := discovery.Announcement{
		DisplayName: "laptop", Fingerprint: fingerprintA, ProtocolVersion: 1, Port: 45770,
	}
	record, _ := discovery.EncodeAnnouncement(own)
	_ = mirror.StartAdvertising(context.Background(), record)

	registry := discovery.NewPeerRegistry(1, &manualClock{now: baseTime})
	tr := NewBtTransport(local)

	var observed []string
	if err := tr.ScanInto(context.Background(), registry, fingerprintA, nil,
		func(fingerprint, _ string) { observed = append(observed, fingerprint) }); err != nil {
		t.Fatalf("scanning: %v", err)
	}
	if len(observed) != 0 {
		t.Fatalf("observed %v, want nothing: that record is our own", observed)
	}
	if len(registry.Visible()) != 0 {
		t.Fatal("the node added itself to its own visible peer list")
	}
}

// TestBtConnectionSplitsWritesAtTheLinkLimit is the difference that matters between the two
// transports: TCP takes an arbitrary buffer, an RFCOMM link has a maximum write.
//
// Requirements: 7.10
func TestBtConnectionSplitsWritesAtTheLinkLimit(t *testing.T) {
	recorder := &writeRecorder{}
	conn := NewConnection(recorder, 512)

	payload := make([]byte, 1300)
	if err := conn.Write(payload); err != nil {
		t.Fatalf("writing: %v", err)
	}

	if len(recorder.sizes) != 3 {
		t.Fatalf("wrote %d pieces (%v), want 3", len(recorder.sizes), recorder.sizes)
	}
	for i, size := range recorder.sizes {
		if size > 512 {
			t.Fatalf("piece %d is %d bytes, over the 512-byte link limit", i, size)
		}
	}
	if recorder.total != len(payload) {
		t.Fatalf("wrote %d bytes total, want %d", recorder.total, len(payload))
	}

	// A short write is looped over rather than reported as success.
	short := &writeRecorder{shortWrites: true}
	if err := NewConnection(short, 512).Write(make([]byte, 100)); err != nil {
		t.Fatalf("writing to a short-writing link: %v", err)
	}
	if short.total != 100 {
		t.Fatalf("a short-writing link received %d of 100 bytes", short.total)
	}

	// A link that accepts nothing is an error rather than an infinite loop.
	stuck := &writeRecorder{acceptNothing: true}
	if err := NewConnection(stuck, 512).Write([]byte("x")); err == nil {
		t.Fatal("a link that accepted no bytes reported success")
	}
}

type writeRecorder struct {
	mu            sync.Mutex
	sizes         []int
	total         int
	shortWrites   bool
	acceptNothing bool
}

func (w *writeRecorder) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.acceptNothing {
		return 0, nil
	}
	n := len(p)
	if w.shortWrites && n > 1 {
		n = 1
	}
	w.sizes = append(w.sizes, n)
	w.total += n
	return n, nil
}

func (w *writeRecorder) Read([]byte) (int, error) { return 0, nil }
func (w *writeRecorder) Close() error             { return nil }

// TestShimBridgeAvailabilityDoesNotLaunchAnything checks that Available is cheap and free of side
// effects. Startup calls it to decide whether BT_Transport is a candidate (Req 12.3), and paying
// for a process launch to find out would put a subprocess on the critical path of Req 12.1's
// five-second budget.
//
// Requirements: 12.1, 12.3
func TestShimBridgeAvailabilityDoesNotLaunchAnything(t *testing.T) {
	// A path that does not exist.
	bridge := NewShimBluetoothBridge(t.TempDir() + "/no-such-shim")
	if bridge.Available() {
		t.Fatal("a missing shim reports itself available")
	}
	if err := bridge.Start(context.Background()); !errors.Is(err, ErrBluetoothUnavailable) {
		t.Fatalf("starting a missing shim returned %v, want ErrBluetoothUnavailable", err)
	}

	// A path that exists but is a directory.
	bridge = NewShimBluetoothBridge(t.TempDir())
	if bridge.Available() {
		t.Fatal("a directory reports itself available as a shim")
	}

	// An empty path.
	if NewShimBluetoothBridge("").path == "" {
		t.Fatal("an empty path did not fall back to the default shim location")
	}

	// The shim protocol constants are what the helper is written against, so a change here is
	// a protocol change.
	if ShimFrameHeaderBytes != 9 {
		t.Fatalf("shim header is %d bytes, want 9", ShimFrameHeaderBytes)
	}
	if ShimMaxPayloadBytes < transport.BTChunkBytes {
		t.Fatalf("shim payload limit %d is under the bluetooth chunk size %d",
			ShimMaxPayloadBytes, transport.BTChunkBytes)
	}
}

// TestShimBridgeWriteFrameRejectsAnOversizePayload checks the bound that stops a corrupt length
// from being turned into an allocation.
//
// Requirements: 12.3
func TestShimBridgeWriteFrameRejectsAnOversizePayload(t *testing.T) {
	bridge := NewShimBluetoothBridge("/nonexistent")
	err := bridge.writeFrame(shimKindData, 1, make([]byte, ShimMaxPayloadBytes+1))
	if err == nil {
		t.Fatal("an oversize shim payload was accepted")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error %q does not name the limit", err)
	}

	// A payload inside the limit fails for the right reason instead: no process is running.
	err = bridge.writeFrame(shimKindData, 1, []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("error is %v, want one naming the missing process", err)
	}
}

// TestSplitDeviceRecord pins the scan-result payload layout: device id, a null byte, then the
// announcement record.
//
// Requirements: 1.4
func TestSplitDeviceRecord(t *testing.T) {
	deviceID, record := splitDeviceRecord([]byte("device-1\x00{\"a\":1}"))
	if deviceID != "device-1" {
		t.Fatalf("device id is %q, want %q", deviceID, "device-1")
	}
	if string(record) != `{"a":1}` {
		t.Fatalf("record is %q", record)
	}

	// No separator means the whole payload is a device id with no record, which is a shim bug
	// but must not panic.
	deviceID, record = splitDeviceRecord([]byte("device-2"))
	if deviceID != "device-2" || len(record) != 0 {
		t.Fatalf("got (%q, %q), want (\"device-2\", \"\")", deviceID, record)
	}
	if got, _ := splitDeviceRecord(nil); got != "" {
		t.Fatalf("nil payload gave device id %q", got)
	}
}

var _ clock.Clock = (*manualClock)(nil)
