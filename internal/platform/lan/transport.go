package lan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/discovery"
	"github.com/peerbeam/peerbeam/internal/core/transport"
)

// DefaultListenPort is the TCP port a Peer_Node listens on and publishes in its
// announcement (Req 1.1). Port 0 is accepted too and lets the operating system choose,
// which is what the loopback tests use so several nodes can run in one process.
const DefaultListenPort = 45770

// LanTransport is transport.Transport over TCP.
//
// It holds the listener rather than creating one per Listen call, because the port it
// binds is the port the discovery beacon publishes (Req 1.1): the two have to agree, and
// the only way to guarantee that with port 0 is for the bind to happen once and the beacon
// to read the result.
//
// Safe for concurrent use. The mutex guards only the listener field, never a read or write
// on a connection.
type LanTransport struct {
	mu       sync.Mutex
	listener *net.TCPListener
	port     int

	// dialer is the seam tests use. Production leaves it nil and gets net.Dialer.
	dialer func(ctx context.Context, address string, timeout time.Duration) (net.Conn, error)
}

// NewLanTransport returns a transport that has not yet bound a port.
func NewLanTransport() *LanTransport { return &LanTransport{} }

// Name is the ranking and reporting identifier (Req 2.2, 2.5).
func (t *LanTransport) Name() string { return transport.NameLAN }

// Medium is the medium a Peer must be visible on for this Transport to be a candidate
// (Req 2.1).
func (t *LanTransport) Medium() discovery.Medium { return discovery.MediumLAN }

// ExpectedGoodputBytesPerSecond is the fixed 40 MiB/s ranking figure from Req 2.1. It is
// the expected value, not a measurement: ranking has to be deterministic, so it never
// consults live metrics.
func (t *LanTransport) ExpectedGoodputBytesPerSecond() int64 {
	return transport.LANExpectedGoodput
}

// ChunkSizeBytes is the 64 KiB Transfer chunk size from Req 7.10.
func (t *LanTransport) ChunkSizeBytes() int { return transport.LANChunkBytes }

// Bind opens the listening socket and returns the port it actually bound, which is what
// the beacon publishes. Calling it twice returns the existing port rather than rebinding,
// so a caller cannot accidentally end up announcing one port and listening on another.
func (t *LanTransport) Bind(port int) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.listener != nil {
		return t.port, nil
	}
	addr := &net.TCPAddr{Port: port}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("bind %s on port %d: %w", transport.NameLAN, port, err)
	}
	t.listener = listener
	t.port = listener.Addr().(*net.TCPAddr).Port
	return t.port, nil
}

// Port is the bound port, or 0 before Bind.
func (t *LanTransport) Port() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.port
}

// Connect dials the Peer's endpoint, honouring both ctx and timeout.
//
// It does not retry. Retry policy belongs to transport.ConnectLadder, which attempts each
// candidate exactly once (Req 2.4); a Transport that retried internally would silently
// turn one 3-second attempt into several.
func (t *LanTransport) Connect(
	ctx context.Context,
	endpoint discovery.PeerEndpoint,
	timeout time.Duration,
) (transport.TransportConnection, error) {
	if endpoint.Address == "" {
		return nil, errors.New("endpoint carries no address")
	}
	if endpoint.Port < 1 || endpoint.Port > 65535 {
		return nil, fmt.Errorf("endpoint port %d is outside 1..65535", endpoint.Port)
	}
	address := net.JoinHostPort(endpoint.Address, strconv.Itoa(endpoint.Port))

	if t.dialer != nil {
		conn, err := t.dialer(ctx, address, timeout)
		if err != nil {
			return nil, err
		}
		return newLanConnection(conn), nil
	}

	// Both bounds are applied: the context carries the ladder's deadline and the timeout
	// covers a dialer that does not watch the context. Whichever fires first ends the
	// attempt.
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		// Nagle batches small writes, which would add up to 40 ms to a keepalive or an
		// acknowledgement. Req 11.1 budgets 100 ms end to end for a text message, so the
		// delay is worth more than the syscall it saves.
		_ = tcp.SetNoDelay(true)
	}
	return newLanConnection(conn), nil
}

// Listen accepts inbound connections until ctx is done, calling onInbound once per
// accepted connection.
//
// Each accepted connection is handed over on the caller's goroutine rather than a new one.
// The caller is internal/app, which starts a per-Session goroutine set anyway, and having
// Listen spawn its own would mean two places deciding a connection's lifetime.
func (t *LanTransport) Listen(ctx context.Context, onInbound func(transport.TransportConnection)) error {
	if _, err := t.Bind(DefaultListenPort); err != nil {
		return err
	}

	t.mu.Lock()
	listener := t.listener
	t.mu.Unlock()

	// Closing the listener is what unblocks Accept: net.TCPListener has no
	// context-aware accept, so cancellation has to close the socket.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-done:
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // cancellation, not a failure
			}
			return fmt.Errorf("accept on %s: %w", transport.NameLAN, err)
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
		}
		if onInbound != nil {
			onInbound(newLanConnection(conn))
			continue
		}
		_ = conn.Close()
	}
}

// Close releases the listening socket.
func (t *LanTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.listener == nil {
		return nil
	}
	err := t.listener.Close()
	t.listener = nil
	return err
}

// lanConnection adapts net.Conn to transport.TransportConnection.
type lanConnection struct {
	conn net.Conn
}

func newLanConnection(conn net.Conn) *lanConnection { return &lanConnection{conn: conn} }

// TransportName lets a Session report its active Transport without holding the Transport.
func (c *lanConnection) TransportName() string { return transport.NameLAN }

// Write sends bytes, looping until all of them are gone.
//
// net.Conn.Write already loops for a TCP socket, but the interface permits a short write,
// and a Wire_Frame that went out in part would desynchronise the receiver's framing for
// the rest of the Session.
func (c *lanConnection) Write(bytes []byte) error {
	for len(bytes) > 0 {
		n, err := c.conn.Write(bytes)
		if err != nil {
			return err
		}
		if n <= 0 {
			return errors.New("lan connection accepted no bytes")
		}
		bytes = bytes[n:]
	}
	return nil
}

// Read reads into `into` and returns the byte count, or (0, io.EOF) at end of stream. Short
// reads are expected: codec.FrameReader is incremental precisely because a Transport
// delivers arbitrary byte runs.
func (c *lanConnection) Read(into []byte) (int, error) { return c.conn.Read(into) }

// Close closes the socket.
func (c *lanConnection) Close() error { return c.conn.Close() }

// LocalAddress is the local side of the connection, for diagnostics.
func (c *lanConnection) LocalAddress() string {
	if c.conn.LocalAddr() == nil {
		return ""
	}
	return c.conn.LocalAddr().String()
}

// RemoteAddress is the peer side of the connection. The beacon uses it to record which
// address an announcement arrived from (Req 1.8).
func (c *lanConnection) RemoteAddress() string {
	if c.conn.RemoteAddr() == nil {
		return ""
	}
	return c.conn.RemoteAddr().String()
}

// Availability reports whether this host has a usable IP network interface. Req 12.8 needs
// the answer at startup: with neither LAN nor Bluetooth, the node starts with no candidate
// Transport and says so, rather than appearing to work and failing on first use.
func Availability() (available bool, reason string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false, "cannot enumerate network interfaces: " + err.Error()
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			// Loopback alone does not make a peer reachable, so it does not count
			// towards availability.
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		return true, ""
	}
	return false, "no network interface is up with an address assigned"
}

// Compile-time proof that LanTransport satisfies the core interface. Without this, a
// signature drift would only surface at the wiring site in internal/app.
var _ transport.Transport = (*LanTransport)(nil)
var _ transport.TransportConnection = (*lanConnection)(nil)
