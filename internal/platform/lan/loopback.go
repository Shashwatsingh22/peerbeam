package lan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/discovery"
	"github.com/peerbeam/peerbeam/internal/core/transport"
)

// LoopbackSwitch connects LoopbackLanTransport instances inside one process.
//
// It exists so the end-to-end tests in task 22 can run several Peer_Nodes under a plain
// `go test` with no sockets, no ports to collide over, and no firewall prompt. The
// alternative, real TCP on 127.0.0.1, works but makes a test that runs eight nodes
// dependent on port availability and on the host's network stack being configured; this
// keeps the failure modes inside the test.
//
// It is a switch rather than a direct pair because the connection ladder dials an address:
// a Transport has to be able to look up "who is listening on this port" the way TCP does.
//
// Safe for concurrent use.
type LoopbackSwitch struct {
	mu        sync.Mutex
	listeners map[int]chan net.Conn
	nextPort  int
	// partitioned ports refuse connections, which is how a test simulates a LAN going
	// away mid-transfer (Req 3.3).
	partitioned map[int]bool
}

// NewLoopbackSwitch returns an empty switch.
func NewLoopbackSwitch() *LoopbackSwitch {
	return &LoopbackSwitch{
		listeners:   map[int]chan net.Conn{},
		nextPort:    45770,
		partitioned: map[int]bool{},
	}
}

// register claims a port and returns the channel inbound connections arrive on. A port of 0
// allocates the next free one, mirroring what the operating system does for a real bind.
func (s *LoopbackSwitch) register(port int) (int, chan net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if port == 0 {
		for s.listeners[s.nextPort] != nil {
			s.nextPort++
		}
		port = s.nextPort
		s.nextPort++
	}
	if s.listeners[port] != nil {
		return 0, nil, fmt.Errorf("loopback port %d is already bound", port)
	}
	inbound := make(chan net.Conn, 16)
	s.listeners[port] = inbound
	return port, inbound, nil
}

func (s *LoopbackSwitch) unregister(port int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if inbound, found := s.listeners[port]; found {
		delete(s.listeners, port)
		close(inbound)
	}
}

// Partition makes a port refuse connections, so a test can drop the LAN under a running
// Session (Req 3.3, 3.5). Passing false restores it.
func (s *LoopbackSwitch) Partition(port int, partitioned bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.partitioned[port] = partitioned
}

// dial connects to a port, returning the local end of the pair.
func (s *LoopbackSwitch) dial(port int) (net.Conn, error) {
	s.mu.Lock()
	inbound := s.listeners[port]
	blocked := s.partitioned[port]
	s.mu.Unlock()

	if blocked {
		return nil, fmt.Errorf("loopback port %d is partitioned", port)
	}
	if inbound == nil {
		return nil, fmt.Errorf("nothing is listening on loopback port %d", port)
	}

	local, remote := net.Pipe()
	select {
	case inbound <- remote:
		return local, nil
	default:
		_ = local.Close()
		_ = remote.Close()
		return nil, fmt.Errorf("loopback port %d is not accepting", port)
	}
}

// LoopbackLanTransport is a transport.Transport over a LoopbackSwitch. It reports the same
// name, medium, expected goodput, and chunk size as the real LAN transport, so ranking and
// chunk planning behave identically and a test exercises the production decisions.
type LoopbackLanTransport struct {
	sw   *LoopbackSwitch
	mu   sync.Mutex
	port int
	// inbound is non-nil once bound.
	inbound chan net.Conn
}

// NewLoopbackLanTransport returns a transport on sw.
func NewLoopbackLanTransport(sw *LoopbackSwitch) *LoopbackLanTransport {
	return &LoopbackLanTransport{sw: sw}
}

func (t *LoopbackLanTransport) Name() string             { return transport.NameLAN }
func (t *LoopbackLanTransport) Medium() discovery.Medium { return discovery.MediumLAN }
func (t *LoopbackLanTransport) ChunkSizeBytes() int      { return transport.LANChunkBytes }
func (t *LoopbackLanTransport) ExpectedGoodputBytesPerSecond() int64 {
	return transport.LANExpectedGoodput
}

// Bind claims a port on the switch and returns it.
func (t *LoopbackLanTransport) Bind(port int) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.inbound != nil {
		return t.port, nil
	}
	bound, inbound, err := t.sw.register(port)
	if err != nil {
		return 0, err
	}
	t.port, t.inbound = bound, inbound
	return bound, nil
}

// Port is the bound port, or 0 before Bind.
func (t *LoopbackLanTransport) Port() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.port
}

// Connect dials the endpoint's port on the switch. The address is ignored: a loopback switch
// has one host.
func (t *LoopbackLanTransport) Connect(
	ctx context.Context,
	endpoint discovery.PeerEndpoint,
	timeout time.Duration,
) (transport.TransportConnection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := t.sw.dial(endpoint.Port)
	if err != nil {
		return nil, err
	}
	return newLanConnection(conn), nil
}

// Listen hands each inbound connection to onInbound until ctx is done.
func (t *LoopbackLanTransport) Listen(ctx context.Context, onInbound func(transport.TransportConnection)) error {
	if _, err := t.Bind(0); err != nil {
		return err
	}
	t.mu.Lock()
	inbound := t.inbound
	t.mu.Unlock()

	for {
		select {
		case <-ctx.Done():
			return nil
		case conn, open := <-inbound:
			if !open {
				return nil
			}
			if onInbound != nil {
				onInbound(newLanConnection(conn))
				continue
			}
			_ = conn.Close()
		}
	}
}

// Close releases the port.
func (t *LoopbackLanTransport) Close() error {
	t.mu.Lock()
	port, bound := t.port, t.inbound != nil
	t.inbound = nil
	t.mu.Unlock()
	if !bound {
		return nil
	}
	t.sw.unregister(port)
	return nil
}

// LoopbackBus delivers announcements between beacons in one process, standing in for the
// multicast group.
//
// Multicast is the part of discovery that a test cannot rely on: a sandboxed or
// containerised test host often has no interface that will join a group, and Req 12.1's
// "empty container" is exactly that case. The bus exercises the whole
// encode-decode-validate-record path that Req 1.3 and 1.11 are about, and leaves only the
// socket itself untested here.
type LoopbackBus struct {
	mu        sync.Mutex
	beacons   []*Beacon
	delivered int
}

// NewLoopbackBus returns an empty bus.
func NewLoopbackBus() *LoopbackBus { return &LoopbackBus{} }

// Join adds a beacon to the bus.
func (b *LoopbackBus) Join(beacon *Beacon) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.beacons = append(b.beacons, beacon)
}

// PublishFrom encodes one beacon's announcement and delivers it to every other beacon,
// which is what one multicast publish does.
func (b *LoopbackBus) PublishFrom(source *Beacon, fromAddress string) error {
	announcement := source.Announcement()
	payload, err := discovery.EncodeAnnouncement(announcement)
	if err != nil {
		return err
	}
	return b.Deliver(source, payload, fromAddress)
}

// Deliver hands a raw payload to every beacon except the sender, so a test can inject a
// malformed datagram as well as a well-formed one.
func (b *LoopbackBus) Deliver(source *Beacon, payload []byte, fromAddress string) error {
	b.mu.Lock()
	targets := make([]*Beacon, 0, len(b.beacons))
	for _, beacon := range b.beacons {
		if beacon != source {
			targets = append(targets, beacon)
		}
	}
	b.delivered++
	b.mu.Unlock()

	if len(targets) == 0 {
		return errors.New("no beacon is joined to the bus")
	}
	from := &net.UDPAddr{IP: net.ParseIP(fromAddress)}
	for _, beacon := range targets {
		beacon.handleDatagram(payload, from)
	}
	return nil
}

// Delivered is how many publishes the bus has carried.
func (b *LoopbackBus) Delivered() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.delivered
}

var _ transport.Transport = (*LoopbackLanTransport)(nil)
