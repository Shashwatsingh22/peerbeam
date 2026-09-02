package bt

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/discovery"
	"github.com/peerbeam/peerbeam/internal/core/transport"
)

// RFCOMMMaxWriteBytes is the largest single write an RFCOMM link reliably accepts.
//
// It is the reason Req 7.10 sets the Bluetooth chunk size to 512 bytes: a chunk plus its
// frame header and AEAD tag has to fit one write, or the shim would fragment it and the
// framing would have to be reassembled a second time on top of the codec that already does it.
const RFCOMMMaxWriteBytes = 1024

// BtTransport is transport.Transport over a BluetoothBridge.
//
// It is a thin adapter on purpose. Everything that decides behaviour - ranking, the ladder,
// switch policy, chunking, framing, crypto - is shared with the LAN path, so the only thing
// this type contributes is the Req 2.1 goodput figure, the Req 7.10 chunk size, and the
// translation from a PeerEndpoint to a device id.
type BtTransport struct {
	bridge BluetoothBridge
}

// NewBtTransport returns a transport over bridge. A nil bridge is replaced with an
// unavailable one, so Req 12.3's "report BT_Transport unavailable" is the behaviour rather
// than a nil dereference.
func NewBtTransport(bridge BluetoothBridge) *BtTransport {
	if bridge == nil {
		bridge = NewUnavailableBridge("no bluetooth bridge was configured")
	}
	return &BtTransport{bridge: bridge}
}

// Name is the ranking and reporting identifier (Req 2.2, 2.5).
func (t *BtTransport) Name() string { return transport.NameBT }

// Medium is the medium a Peer must be visible on for this Transport to be a candidate
// (Req 2.1).
func (t *BtTransport) Medium() discovery.Medium { return discovery.MediumBluetooth }

// ExpectedGoodputBytesPerSecond is the fixed 40 KiB/s ranking figure from Req 2.1, which is
// what puts this Transport below LAN in every ranking.
func (t *BtTransport) ExpectedGoodputBytesPerSecond() int64 {
	return transport.BTExpectedGoodput
}

// ChunkSizeBytes is the 512-byte Transfer chunk size from Req 7.10.
func (t *BtTransport) ChunkSizeBytes() int { return transport.BTChunkBytes }

// Available reports whether this Transport can be a candidate at all (Req 12.3).
func (t *BtTransport) Available() bool { return t.bridge.Available() }

// Unavailable returns the Req 12.3 report when Bluetooth cannot be used, and false when it
// can. It is a method on the Transport rather than on the bridge so internal/app has one
// place to ask.
func (t *BtTransport) Unavailable() (*report, bool) {
	if t.bridge.Available() {
		return nil, false
	}
	reason := "no bluetooth interface is available on this host"
	if unavailable, ok := t.bridge.(*UnavailableBridge); ok && unavailable.Reason != "" {
		reason = unavailable.Reason
	}
	return &report{TransportName: transport.NameBT, Reason: reason}, true
}

// report is the unavailability report. It is deliberately small: internal/core/report owns the
// user-facing shape, and this type only carries the two values it needs.
type report struct {
	TransportName string
	Reason        string
}

func (r *report) Error() string {
	return fmt.Sprintf("%s is unavailable: %s", r.TransportName, r.Reason)
}

// Connect opens a stream to the Peer's Bluetooth device.
//
// The device id travels in PeerEndpoint.Address. That field is documented as "IP literal, or
// Bluetooth device id" precisely so one endpoint type serves both media, which is what lets
// the connection ladder walk a mixed candidate list without knowing what a device id is.
func (t *BtTransport) Connect(
	ctx context.Context,
	endpoint discovery.PeerEndpoint,
	timeout time.Duration,
) (transport.TransportConnection, error) {
	if !t.bridge.Available() {
		return nil, ErrBluetoothUnavailable
	}
	if endpoint.Address == "" {
		return nil, fmt.Errorf("endpoint carries no bluetooth device id")
	}
	return t.bridge.Connect(ctx, endpoint.Address, timeout)
}

// Listen accepts inbound Bluetooth streams until ctx is done.
func (t *BtTransport) Listen(ctx context.Context, onInbound func(transport.TransportConnection)) error {
	if !t.bridge.Available() {
		return ErrBluetoothUnavailable
	}
	return t.bridge.Accept(ctx, onInbound)
}

// StartAdvertising publishes the announcement record over Bluetooth (Req 1.1).
func (t *BtTransport) StartAdvertising(ctx context.Context, record []byte) error {
	if !t.bridge.Available() {
		return ErrBluetoothUnavailable
	}
	return t.bridge.StartAdvertising(ctx, record)
}

// StopAdvertising stops publishing.
func (t *BtTransport) StopAdvertising(ctx context.Context) error {
	if !t.bridge.Available() {
		return nil
	}
	return t.bridge.StopAdvertising(ctx)
}

// ScanInto feeds discovered peers into a PeerRegistry until ctx is done or the scan ends
// (Req 1.4).
//
// Each record goes through the same DecodeAndCheckAnnouncement as a LAN datagram, so a
// malformed Bluetooth record produces the same malformed-announcement event as a malformed
// UDP one (Req 1.11). onMalformed and onObserved are optional callbacks, matching the LAN
// beacon's shape so internal/app wires both the same way.
func (t *BtTransport) ScanInto(
	ctx context.Context,
	registry *discovery.PeerRegistry,
	ownFingerprint string,
	onMalformed func(reasons []string, deviceID string),
	onObserved func(fingerprint string, deviceID string),
) error {
	if !t.bridge.Available() {
		return ErrBluetoothUnavailable
	}
	found, err := t.bridge.Scan(ctx)
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case peer, open := <-found:
			if !open {
				return nil
			}
			check := discovery.DecodeAndCheckAnnouncement(peer.Record)
			if check.Malformed != nil {
				if onMalformed != nil {
					onMalformed(check.Malformed, peer.DeviceID)
				}
				continue
			}
			if ownFingerprint != "" && check.Valid.Fingerprint == ownFingerprint {
				continue // our own record, reflected back
			}
			// The device id is the address for this medium, which is what Connect will
			// dial later (Req 1.8).
			if outcome := registry.Observe(*check.Valid, discovery.MediumBluetooth, peer.DeviceID); outcome.AtCapacity != nil {
				continue
			}
			if onObserved != nil {
				onObserved(check.Valid.Fingerprint, peer.DeviceID)
			}
		}
	}
}

// btConnection adapts a byte stream to transport.TransportConnection, bounding each write to
// what the link accepts.
type btConnection struct {
	stream        io.ReadWriteCloser
	maxWriteBytes int
}

// NewConnection wraps a raw stream as a Bluetooth TransportConnection. A shim implementation
// uses it so the write-splitting rule lives in one place rather than in each platform's shim.
func NewConnection(stream io.ReadWriteCloser, maxWriteBytes int) transport.TransportConnection {
	if maxWriteBytes <= 0 {
		maxWriteBytes = RFCOMMMaxWriteBytes
	}
	return &btConnection{stream: stream, maxWriteBytes: maxWriteBytes}
}

func (c *btConnection) TransportName() string { return transport.NameBT }

// Write splits the payload into link-sized writes and loops on short ones.
//
// This is the difference that matters between the two transports. A TCP socket takes an
// arbitrary buffer; an RFCOMM link has a maximum transmission unit, and a write over it is
// either rejected or fragmented by the driver. Splitting here means the codec above never has
// to know, and a Wire_Frame still arrives as one contiguous byte run.
func (c *btConnection) Write(bytes []byte) error {
	for len(bytes) > 0 {
		piece := bytes
		if len(piece) > c.maxWriteBytes {
			piece = piece[:c.maxWriteBytes]
		}
		written := 0
		for written < len(piece) {
			n, err := c.stream.Write(piece[written:])
			if err != nil {
				return err
			}
			if n <= 0 {
				return fmt.Errorf("bluetooth link accepted no bytes")
			}
			written += n
		}
		bytes = bytes[len(piece):]
	}
	return nil
}

func (c *btConnection) Read(into []byte) (int, error) { return c.stream.Read(into) }
func (c *btConnection) Close() error                  { return c.stream.Close() }

// newPipePair returns two connected Bluetooth connections for the in-memory bridge. net.Pipe
// is synchronous and unbuffered, which models a stream link more faithfully than a buffered
// channel would: a writer blocks until a reader takes the bytes.
func newPipePair() (transport.TransportConnection, transport.TransportConnection) {
	a, b := net.Pipe()
	return NewConnection(a, RFCOMMMaxWriteBytes), NewConnection(b, RFCOMMMaxWriteBytes)
}

var _ transport.Transport = (*BtTransport)(nil)
var _ transport.TransportConnection = (*btConnection)(nil)
