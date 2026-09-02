package bt

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/transport"
)

// BluetoothBridge is the whole Bluetooth surface: advertise presence, scan for peers, open
// and accept byte streams. Deliberately dumb - no framing, no retries, no policy - because
// everything above it is shared with the LAN path and must not be reimplemented per medium.
//
// The interface is declared here rather than in internal/core because it is inherently an
// I/O contract, and because the only thing core needs from Bluetooth is a
// transport.Transport, which BtTransport provides.
type BluetoothBridge interface {
	// Available reports whether this host has a usable Bluetooth interface. False makes
	// BT_Transport unavailable at startup (Req 12.3).
	Available() bool
	// MaxWriteBytes is the largest single write the link accepts. It bounds the frame
	// writer, and it is why Req 7.10 sets the Bluetooth chunk size to 512 bytes.
	MaxWriteBytes() int
	// StartAdvertising publishes the announcement record so peers can find this node
	// (Req 1.1, 1.4).
	StartAdvertising(ctx context.Context, record []byte) error
	StopAdvertising(ctx context.Context) error
	// Scan yields discovered peers until ctx is done. The channel is closed when the scan
	// stops, so a caller ranging over it terminates without a second signal.
	Scan(ctx context.Context) (<-chan DiscoveredBtPeer, error)
	// Connect opens a stream to a device. It must honour both ctx and timeout and must not
	// retry: retry policy belongs to transport.ConnectLadder (Req 2.4).
	Connect(ctx context.Context, deviceID string, timeout time.Duration) (transport.TransportConnection, error)
	// Accept hands inbound streams to onInbound until ctx is done.
	Accept(ctx context.Context, onInbound func(transport.TransportConnection)) error
}

// DiscoveredBtPeer is one scan result: which device it came from and the announcement record
// read off it.
//
// The record is the full announcement rather than the advertisement payload. A Bluetooth
// advertisement is far too small for a 64-character display name plus a 64-character
// fingerprint, so the advertisement carries the service UUID and the first bytes of the
// fingerprint, and the shim reads the complete record from the peer's service record before
// emitting this. The 15-second budget in Req 1.4 is what pays for that extra read.
type DiscoveredBtPeer struct {
	DeviceID string
	Record   []byte
}

// ErrBluetoothUnavailable is what every operation returns when no bridge is present. It is a
// sentinel so the caller can distinguish "this host has no Bluetooth", which is a normal
// startup condition under Req 12.3, from "the Bluetooth we have just failed", which is not.
var ErrBluetoothUnavailable = errors.New("no bluetooth interface is available on this host")

// UnavailableBridge is the bridge used when the host exposes no Bluetooth interface.
//
// It exists so internal/app can wire a bridge unconditionally and let Available() decide,
// rather than carrying a nil check at every call site. Req 12.3 wants startup to complete
// with LAN as the only candidate and a report that BT_Transport is unavailable; a nil bridge
// would make that a panic instead.
type UnavailableBridge struct {
	// Reason is why Bluetooth is unavailable, for the Req 12.3 report.
	Reason string
}

// NewUnavailableBridge returns a bridge that reports itself unavailable.
func NewUnavailableBridge(reason string) *UnavailableBridge {
	if reason == "" {
		reason = "no bluetooth shim is configured"
	}
	return &UnavailableBridge{Reason: reason}
}

func (b *UnavailableBridge) Available() bool    { return false }
func (b *UnavailableBridge) MaxWriteBytes() int { return 0 }

func (b *UnavailableBridge) StartAdvertising(context.Context, []byte) error {
	return b.err()
}
func (b *UnavailableBridge) StopAdvertising(context.Context) error { return b.err() }

func (b *UnavailableBridge) Scan(context.Context) (<-chan DiscoveredBtPeer, error) {
	return nil, b.err()
}

func (b *UnavailableBridge) Connect(context.Context, string, time.Duration) (transport.TransportConnection, error) {
	return nil, b.err()
}

func (b *UnavailableBridge) Accept(context.Context, func(transport.TransportConnection)) error {
	return b.err()
}

func (b *UnavailableBridge) err() error {
	if b.Reason == "" {
		return ErrBluetoothUnavailable
	}
	return errors.Join(ErrBluetoothUnavailable, errors.New(b.Reason))
}

// InMemoryBluetoothBridge is a bridge that pipes bytes over channels inside one process.
//
// It is what the end-to-end tests use for the Bluetooth leg (task 22.2), and it is the reason
// a rebind from LAN to Bluetooth can be tested at all: no test host can be relied upon to
// have two paired radios. It reports the same MaxWriteBytes as a real RFCOMM link so the
// 512-byte chunk size of Req 7.10 is exercised rather than bypassed.
//
// Safe for concurrent use.
type InMemoryBluetoothBridge struct {
	// Fabric is shared between the bridges that should be able to see each other.
	fabric   *Fabric
	deviceID string

	mu          sync.Mutex
	available   bool
	advertising []byte
}

// Fabric connects InMemoryBluetoothBridge instances, the way a room full of radios connects
// real ones.
type Fabric struct {
	mu      sync.Mutex
	bridges map[string]*InMemoryBluetoothBridge
	inbound map[string]chan transport.TransportConnection
	// partitioned devices refuse connections, so a test can take the Bluetooth link away
	// as well as the LAN one.
	partitioned map[string]bool
}

// NewFabric returns an empty fabric.
func NewFabric() *Fabric {
	return &Fabric{
		bridges:     map[string]*InMemoryBluetoothBridge{},
		inbound:     map[string]chan transport.TransportConnection{},
		partitioned: map[string]bool{},
	}
}

// Partition makes a device refuse connections. Passing false restores it.
func (f *Fabric) Partition(deviceID string, partitioned bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.partitioned[deviceID] = partitioned
}

// NewInMemoryBluetoothBridge returns a bridge on fabric, identified by deviceID.
func NewInMemoryBluetoothBridge(fabric *Fabric, deviceID string) *InMemoryBluetoothBridge {
	b := &InMemoryBluetoothBridge{fabric: fabric, deviceID: deviceID, available: true}

	fabric.mu.Lock()
	fabric.bridges[deviceID] = b
	fabric.inbound[deviceID] = make(chan transport.TransportConnection, 8)
	fabric.mu.Unlock()
	return b
}

// SetAvailable toggles availability, so a test can exercise the Req 12.3 path where a host has
// no Bluetooth.
func (b *InMemoryBluetoothBridge) SetAvailable(available bool) {
	b.mu.Lock()
	b.available = available
	b.mu.Unlock()
}

func (b *InMemoryBluetoothBridge) Available() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.available
}

// MaxWriteBytes matches what an RFCOMM link accepts, so the Bluetooth chunk size of Req 7.10
// is the binding constraint in tests as it is in production.
func (b *InMemoryBluetoothBridge) MaxWriteBytes() int { return RFCOMMMaxWriteBytes }

// DeviceID is this bridge's address on the fabric.
func (b *InMemoryBluetoothBridge) DeviceID() string { return b.deviceID }

func (b *InMemoryBluetoothBridge) StartAdvertising(_ context.Context, record []byte) error {
	if !b.Available() {
		return ErrBluetoothUnavailable
	}
	b.mu.Lock()
	b.advertising = append([]byte(nil), record...)
	b.mu.Unlock()
	return nil
}

func (b *InMemoryBluetoothBridge) StopAdvertising(context.Context) error {
	b.mu.Lock()
	b.advertising = nil
	b.mu.Unlock()
	return nil
}

// Scan yields every other advertising bridge on the fabric once, then closes the channel.
// A real scan keeps yielding; one pass is enough for a test and avoids a goroutine that
// outlives the test.
func (b *InMemoryBluetoothBridge) Scan(ctx context.Context) (<-chan DiscoveredBtPeer, error) {
	if !b.Available() {
		return nil, ErrBluetoothUnavailable
	}

	b.fabric.mu.Lock()
	found := make([]DiscoveredBtPeer, 0, len(b.fabric.bridges))
	for id, other := range b.fabric.bridges {
		if id == b.deviceID {
			continue
		}
		other.mu.Lock()
		record := append([]byte(nil), other.advertising...)
		advertising := other.available && len(record) > 0
		other.mu.Unlock()
		if advertising {
			found = append(found, DiscoveredBtPeer{DeviceID: id, Record: record})
		}
	}
	b.fabric.mu.Unlock()

	out := make(chan DiscoveredBtPeer, len(found))
	for _, peer := range found {
		out <- peer
	}
	close(out)
	_ = ctx
	return out, nil
}

func (b *InMemoryBluetoothBridge) Connect(
	ctx context.Context,
	deviceID string,
	_ time.Duration,
) (transport.TransportConnection, error) {
	if !b.Available() {
		return nil, ErrBluetoothUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	b.fabric.mu.Lock()
	inbound := b.fabric.inbound[deviceID]
	blocked := b.fabric.partitioned[deviceID]
	target := b.fabric.bridges[deviceID]
	b.fabric.mu.Unlock()

	switch {
	case blocked:
		return nil, errors.New("bluetooth device " + deviceID + " is out of range")
	case inbound == nil || target == nil:
		return nil, errors.New("no bluetooth device " + deviceID + " on this fabric")
	case !target.Available():
		return nil, ErrBluetoothUnavailable
	}

	local, remote := newPipePair()
	select {
	case inbound <- remote:
		return local, nil
	case <-ctx.Done():
		_ = local.Close()
		_ = remote.Close()
		return nil, ctx.Err()
	}
}

func (b *InMemoryBluetoothBridge) Accept(ctx context.Context, onInbound func(transport.TransportConnection)) error {
	if !b.Available() {
		return ErrBluetoothUnavailable
	}

	b.fabric.mu.Lock()
	inbound := b.fabric.inbound[b.deviceID]
	b.fabric.mu.Unlock()
	if inbound == nil {
		return errors.New("bridge is not registered on a fabric")
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case conn, open := <-inbound:
			if !open {
				return nil
			}
			if onInbound != nil {
				onInbound(conn)
				continue
			}
			_ = conn.Close()
		}
	}
}

var _ BluetoothBridge = (*UnavailableBridge)(nil)
var _ BluetoothBridge = (*InMemoryBluetoothBridge)(nil)
