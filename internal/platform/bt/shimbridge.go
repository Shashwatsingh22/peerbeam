package bt

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/transport"
)

// The shim protocol. This is Option B from the design: a standalone helper executable speaking
// a length-prefixed frame format over stdin and stdout.
//
// Option A links the per-OS shim into the binary over cgo, which is what release builds want
// because it keeps the deliverable to one file (Req 12.2). Option B is easier to iterate on
// because the shim can be restarted, logged, and debugged independently, and the Go side is
// identical either way: both end up behind BluetoothBridge. See the note at the bottom of this
// file for what changes when Option A lands.
const (
	// ShimFrameHeaderBytes is the fixed shim frame header: kind, stream id, payload length.
	//
	//	offset  size  field
	//	  0      1    kind        u8
	//	  1      4    streamId    u32 big-endian, 0 for control frames
	//	  5      4    length      u32 big-endian
	//	  9      N    payload
	ShimFrameHeaderBytes = 9
	// ShimMaxPayloadBytes bounds one shim frame. It is generous next to the 512-byte
	// Bluetooth chunk size, and bounded so a corrupt length cannot make the node allocate
	// without limit.
	ShimMaxPayloadBytes = 64 * 1024
)

// Shim frame kinds. The set is closed; an unrecognised kind is a protocol error rather than
// something to skip, because unlike the wire protocol there is no version negotiation with a
// helper this node started itself.
const (
	shimKindStartAdvertising uint8 = 1
	shimKindStopAdvertising  uint8 = 2
	shimKindScan             uint8 = 3
	shimKindScanResult       uint8 = 4
	shimKindScanDone         uint8 = 5
	shimKindConnect          uint8 = 6
	shimKindConnected        uint8 = 7
	shimKindAccepted         uint8 = 8
	shimKindData             uint8 = 9
	shimKindClose            uint8 = 10
	shimKindError            uint8 = 11
	shimKindAvailable        uint8 = 12
)

// ShimPath is where the helper executable is looked for when no explicit path is given. Before
// release the shim is either embedded with go:embed and extracted here on first run, or
// replaced by the linked cgo shim of Option A.
func ShimPath() string {
	if explicit := os.Getenv("PEERBEAM_BT_SHIM"); explicit != "" {
		return explicit
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home + "/.peerbeam/bin/peerbeam-bt-shim"
}

// ShimBluetoothBridge is a BluetoothBridge backed by a helper process.
//
// Safe for concurrent use. The mutex guards the stream table and the write side of the pipe;
// it is never held while waiting on a read, because a shim that stopped responding would
// otherwise block every other operation including the shutdown that would fix it.
type ShimBluetoothBridge struct {
	path string

	mu        sync.Mutex
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdout    *bufio.Reader
	available bool
	started   bool

	nextStreamId uint32
	streams      map[uint32]*shimStream
	accepted     chan transport.TransportConnection
	scanResults  chan DiscoveredBtPeer
	connectWait  map[uint32]chan error

	stopOnce sync.Once
	stopped  chan struct{}
}

// NewShimBluetoothBridge returns a bridge that will start the helper at path. An empty path
// uses ShimPath.
//
// It does not start the process: Available must be cheap and must not have side effects,
// because internal/app calls it during startup to decide whether BT_Transport is a candidate
// at all (Req 12.3).
func NewShimBluetoothBridge(path string) *ShimBluetoothBridge {
	if path == "" {
		path = ShimPath()
	}
	return &ShimBluetoothBridge{
		path:        path,
		streams:     map[uint32]*shimStream{},
		accepted:    make(chan transport.TransportConnection, 8),
		connectWait: map[uint32]chan error{},
		stopped:     make(chan struct{}),
	}
}

// Available reports whether the shim executable exists and is executable. It does not run it:
// a missing shim is the normal case on a host without Bluetooth support, and Req 12.3 wants
// startup to continue with LAN only rather than pay for a process launch to find out.
func (b *ShimBluetoothBridge) Available() bool {
	if b.path == "" {
		return false
	}
	info, err := os.Stat(b.path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
}

// UnavailableReason explains why this bridge is not available, naming the real cause rather than a
// generic "no interface" message. What makes Bluetooth unavailable here is almost always a missing
// or non-executable shim, not an absent radio - Available never opens the radio - so the message
// says which and points at the fix. An empty string means the bridge is available.
func (b *ShimBluetoothBridge) UnavailableReason() string {
	if b.Available() {
		return ""
	}
	if b.path == "" {
		return "no bluetooth helper is configured"
	}
	info, err := os.Stat(b.path)
	switch {
	case err != nil:
		return fmt.Sprintf(
			"the bluetooth helper is not installed at %s; build it with `make shim`", b.path)
	case info.IsDir():
		return fmt.Sprintf("%s is a directory, not the bluetooth helper; rebuild it with `make shim`", b.path)
	default:
		return fmt.Sprintf("the bluetooth helper at %s is not executable; run `make shim` to reinstall it", b.path)
	}
}

// MaxWriteBytes is the RFCOMM write limit.
func (b *ShimBluetoothBridge) MaxWriteBytes() int { return RFCOMMMaxWriteBytes }

// Start launches the helper and begins reading its frames. It is called implicitly by the
// operations that need it, so a caller does not have to sequence it.
func (b *ShimBluetoothBridge) Start(ctx context.Context) error {
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return nil
	}
	if !b.Available() {
		b.mu.Unlock()
		return errors.Join(ErrBluetoothUnavailable,
			fmt.Errorf("no bluetooth shim at %s", b.path))
	}

	cmd := exec.CommandContext(ctx, b.path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		b.mu.Unlock()
		return fmt.Errorf("open shim stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		b.mu.Unlock()
		return fmt.Errorf("open shim stdout: %w", err)
	}
	// The shim's stderr goes to ours, so a native crash is visible rather than swallowed.
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		b.mu.Unlock()
		return fmt.Errorf("start bluetooth shim %s: %w", b.path, err)
	}

	b.cmd, b.stdin, b.stdout = cmd, stdin, bufio.NewReaderSize(stdout, ShimMaxPayloadBytes)
	b.started, b.available = true, true
	b.mu.Unlock()

	go b.readLoop()
	return nil
}

// Stop terminates the helper and closes every open stream.
func (b *ShimBluetoothBridge) Stop() error {
	var err error
	b.stopOnce.Do(func() {
		close(b.stopped)

		b.mu.Lock()
		cmd, stdin := b.cmd, b.stdin
		streams := make([]*shimStream, 0, len(b.streams))
		for _, s := range b.streams {
			streams = append(streams, s)
		}
		b.streams = map[uint32]*shimStream{}
		b.started = false
		b.mu.Unlock()

		for _, s := range streams {
			s.closeLocal()
		}
		if stdin != nil {
			_ = stdin.Close()
		}
		if cmd != nil && cmd.Process != nil {
			// The shim is expected to exit when its stdin closes. Killing it is the
			// fallback for one that does not.
			_ = cmd.Process.Kill()
			err = cmd.Wait()
		}
	})
	return err
}

// StartAdvertising asks the shim to publish the announcement record.
func (b *ShimBluetoothBridge) StartAdvertising(ctx context.Context, record []byte) error {
	if err := b.Start(ctx); err != nil {
		return err
	}
	return b.writeFrame(shimKindStartAdvertising, 0, record)
}

// StopAdvertising asks the shim to stop publishing.
func (b *ShimBluetoothBridge) StopAdvertising(ctx context.Context) error {
	if !b.isStarted() {
		return nil
	}
	_ = ctx
	return b.writeFrame(shimKindStopAdvertising, 0, nil)
}

// Scan asks the shim to scan and returns the results channel. The channel is closed when the
// shim reports the scan finished or the bridge stops.
func (b *ShimBluetoothBridge) Scan(ctx context.Context) (<-chan DiscoveredBtPeer, error) {
	if err := b.Start(ctx); err != nil {
		return nil, err
	}

	b.mu.Lock()
	if b.scanResults != nil {
		existing := b.scanResults
		b.mu.Unlock()
		return existing, nil
	}
	results := make(chan DiscoveredBtPeer, 16)
	b.scanResults = results
	b.mu.Unlock()

	if err := b.writeFrame(shimKindScan, 0, nil); err != nil {
		b.mu.Lock()
		b.scanResults = nil
		b.mu.Unlock()
		close(results)
		return nil, err
	}
	return results, nil
}

// Connect asks the shim to open a stream to a device and waits for it to confirm.
func (b *ShimBluetoothBridge) Connect(
	ctx context.Context,
	deviceID string,
	timeout time.Duration,
) (transport.TransportConnection, error) {
	if err := b.Start(ctx); err != nil {
		return nil, err
	}

	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	b.mu.Lock()
	b.nextStreamId++
	streamId := b.nextStreamId
	stream := newShimStream(b, streamId)
	b.streams[streamId] = stream
	confirmed := make(chan error, 1)
	b.connectWait[streamId] = confirmed
	b.mu.Unlock()

	cleanup := func() {
		b.mu.Lock()
		delete(b.streams, streamId)
		delete(b.connectWait, streamId)
		b.mu.Unlock()
	}

	if err := b.writeFrame(shimKindConnect, streamId, []byte(deviceID)); err != nil {
		cleanup()
		return nil, err
	}

	select {
	case err := <-confirmed:
		b.mu.Lock()
		delete(b.connectWait, streamId)
		b.mu.Unlock()
		if err != nil {
			cleanup()
			return nil, err
		}
		return NewConnection(stream, RFCOMMMaxWriteBytes), nil
	case <-attemptCtx.Done():
		cleanup()
		return nil, attemptCtx.Err()
	case <-b.stopped:
		cleanup()
		return nil, errors.New("bluetooth shim stopped")
	}
}

// Accept hands inbound streams to onInbound until ctx is done.
func (b *ShimBluetoothBridge) Accept(ctx context.Context, onInbound func(transport.TransportConnection)) error {
	if err := b.Start(ctx); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-b.stopped:
			return nil
		case conn := <-b.accepted:
			if onInbound != nil {
				onInbound(conn)
				continue
			}
			_ = conn.Close()
		}
	}
}

func (b *ShimBluetoothBridge) isStarted() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.started
}

// writeFrame writes one shim frame. The mutex is held across the write so two goroutines cannot
// interleave halves of a frame, which would desynchronise the shim for good.
func (b *ShimBluetoothBridge) writeFrame(kind uint8, streamId uint32, payload []byte) error {
	if len(payload) > ShimMaxPayloadBytes {
		return fmt.Errorf("shim payload of %d bytes exceeds the %d-byte maximum",
			len(payload), ShimMaxPayloadBytes)
	}

	frame := make([]byte, ShimFrameHeaderBytes+len(payload))
	frame[0] = kind
	binary.BigEndian.PutUint32(frame[1:5], streamId)
	binary.BigEndian.PutUint32(frame[5:9], uint32(len(payload)))
	copy(frame[ShimFrameHeaderBytes:], payload)

	b.mu.Lock()
	stdin := b.stdin
	b.mu.Unlock()
	if stdin == nil {
		return errors.New("bluetooth shim is not running")
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	_, err := stdin.Write(frame)
	return err
}

// readLoop reads frames from the shim until it stops or fails.
func (b *ShimBluetoothBridge) readLoop() {
	header := make([]byte, ShimFrameHeaderBytes)
	for {
		b.mu.Lock()
		stdout := b.stdout
		b.mu.Unlock()
		if stdout == nil {
			return
		}

		if _, err := io.ReadFull(stdout, header); err != nil {
			b.shimFailed(err)
			return
		}
		kind := header[0]
		streamId := binary.BigEndian.Uint32(header[1:5])
		length := binary.BigEndian.Uint32(header[5:9])

		if length > ShimMaxPayloadBytes {
			// A length this large means the stream is out of sync, and reading it would
			// hand the shim control of an allocation.
			b.shimFailed(fmt.Errorf("shim declared a %d-byte payload, over the %d-byte maximum",
				length, ShimMaxPayloadBytes))
			return
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(stdout, payload); err != nil {
			b.shimFailed(err)
			return
		}

		b.dispatch(kind, streamId, payload)
	}
}

func (b *ShimBluetoothBridge) dispatch(kind uint8, streamId uint32, payload []byte) {
	switch kind {
	case shimKindAvailable:
		b.mu.Lock()
		b.available = len(payload) > 0 && payload[0] != 0
		b.mu.Unlock()

	case shimKindScanResult:
		// Payload is the device id, a null byte, then the announcement record.
		deviceID, record := splitDeviceRecord(payload)
		b.mu.Lock()
		results := b.scanResults
		b.mu.Unlock()
		if results != nil {
			select {
			case results <- DiscoveredBtPeer{DeviceID: deviceID, Record: record}:
			default: // a full channel means the consumer is behind; dropping a scan
				// result is harmless because scanning repeats
			}
		}

	case shimKindScanDone:
		b.mu.Lock()
		results := b.scanResults
		b.scanResults = nil
		b.mu.Unlock()
		if results != nil {
			close(results)
		}

	case shimKindConnected:
		b.mu.Lock()
		waiter := b.connectWait[streamId]
		b.mu.Unlock()
		if waiter != nil {
			waiter <- nil
		}

	case shimKindAccepted:
		stream := newShimStream(b, streamId)
		b.mu.Lock()
		b.streams[streamId] = stream
		b.mu.Unlock()
		select {
		case b.accepted <- NewConnection(stream, RFCOMMMaxWriteBytes):
		default:
			// Nobody is accepting, so the far side is told rather than left hanging.
			_ = b.writeFrame(shimKindClose, streamId, nil)
			b.mu.Lock()
			delete(b.streams, streamId)
			b.mu.Unlock()
		}

	case shimKindData:
		b.mu.Lock()
		stream := b.streams[streamId]
		b.mu.Unlock()
		if stream != nil {
			stream.deliver(payload)
		}

	case shimKindClose:
		b.mu.Lock()
		stream := b.streams[streamId]
		delete(b.streams, streamId)
		b.mu.Unlock()
		if stream != nil {
			stream.closeLocal()
		}

	case shimKindError:
		err := errors.New(string(payload))
		b.mu.Lock()
		waiter := b.connectWait[streamId]
		stream := b.streams[streamId]
		delete(b.connectWait, streamId)
		delete(b.streams, streamId)
		b.mu.Unlock()
		if waiter != nil {
			waiter <- err
			return
		}
		if stream != nil {
			stream.failLocal(err)
		}
	}
}

// shimFailed tears everything down when the helper dies or desynchronises. Every open stream
// gets an error rather than blocking forever, which is what lets the Sessions above rebind to
// LAN (Req 3.3) instead of hanging.
func (b *ShimBluetoothBridge) shimFailed(cause error) {
	b.mu.Lock()
	streams := make([]*shimStream, 0, len(b.streams))
	for _, s := range b.streams {
		streams = append(streams, s)
	}
	waiters := make([]chan error, 0, len(b.connectWait))
	for _, w := range b.connectWait {
		waiters = append(waiters, w)
	}
	results := b.scanResults
	b.streams = map[uint32]*shimStream{}
	b.connectWait = map[uint32]chan error{}
	b.scanResults = nil
	b.started, b.available = false, false
	b.mu.Unlock()

	err := fmt.Errorf("bluetooth shim failed: %w", cause)
	for _, s := range streams {
		s.failLocal(err)
	}
	for _, w := range waiters {
		w <- err
	}
	if results != nil {
		close(results)
	}
}

func splitDeviceRecord(payload []byte) (deviceID string, record []byte) {
	for i, b := range payload {
		if b == 0 {
			return string(payload[:i]), payload[i+1:]
		}
	}
	return string(payload), nil
}

// shimStream is one Bluetooth byte stream carried over the shim's framed pipe.
//
// Reads come from a buffer the read loop fills, rather than from the pipe directly, because one
// pipe multiplexes every stream: a reader that consumed the pipe would steal another stream's
// frames.
type shimStream struct {
	bridge   *ShimBluetoothBridge
	streamId uint32

	mu       sync.Mutex
	buffered []byte
	readable chan struct{}
	closed   bool
	err      error
}

func newShimStream(bridge *ShimBluetoothBridge, streamId uint32) *shimStream {
	return &shimStream{
		bridge:   bridge,
		streamId: streamId,
		readable: make(chan struct{}, 1),
	}
}

func (s *shimStream) deliver(payload []byte) {
	s.mu.Lock()
	s.buffered = append(s.buffered, payload...)
	s.mu.Unlock()
	s.signal()
}

func (s *shimStream) signal() {
	select {
	case s.readable <- struct{}{}:
	default:
	}
}

func (s *shimStream) Read(into []byte) (int, error) {
	for {
		s.mu.Lock()
		if len(s.buffered) > 0 {
			n := copy(into, s.buffered)
			s.buffered = s.buffered[n:]
			s.mu.Unlock()
			return n, nil
		}
		closed, err := s.closed, s.err
		s.mu.Unlock()

		if err != nil {
			return 0, err
		}
		if closed {
			return 0, io.EOF
		}
		select {
		case <-s.readable:
		case <-s.bridge.stopped:
			return 0, io.EOF
		}
	}
}

func (s *shimStream) Write(payload []byte) (int, error) {
	s.mu.Lock()
	closed, err := s.closed, s.err
	s.mu.Unlock()
	if err != nil {
		return 0, err
	}
	if closed {
		return 0, io.ErrClosedPipe
	}
	if err := s.bridge.writeFrame(shimKindData, s.streamId, payload); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (s *shimStream) Close() error {
	s.mu.Lock()
	already := s.closed
	s.closed = true
	s.mu.Unlock()
	s.signal()

	if already {
		return nil
	}
	s.bridge.mu.Lock()
	delete(s.bridge.streams, s.streamId)
	s.bridge.mu.Unlock()
	return s.bridge.writeFrame(shimKindClose, s.streamId, nil)
}

func (s *shimStream) closeLocal() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.signal()
}

func (s *shimStream) failLocal(err error) {
	s.mu.Lock()
	s.closed = true
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
	s.signal()
}

// Option A note, for when the linked cgo shim replaces this file's process model.
//
// The per-OS shim exposes plain C entry points - bt_available, bt_start_advertising,
// bt_scan_poll, bt_connect, bt_read, bt_write, bt_close - and a cgo file in this package calls
// them directly, so the Go linker folds the object into the executable and the deliverable
// stays one file (Req 12.2). Nothing above BluetoothBridge changes: BtTransport, the ladder,
// the switch policy, and the codec are all written against the interface, and this file is the
// only thing that gets replaced. The shim sources live under shim/macos, shim/windows, and
// shim/linux; the macOS one wraps IOBluetooth RFCOMM, Windows wraps Winsock's
// AF_BTH/BTHPROTO_RFCOMM, and Linux wraps BlueZ RFCOMM sockets.

var _ BluetoothBridge = (*ShimBluetoothBridge)(nil)
var _ io.ReadWriteCloser = (*shimStream)(nil)
