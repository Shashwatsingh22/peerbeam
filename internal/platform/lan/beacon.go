package lan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/clock"
	"github.com/peerbeam/peerbeam/internal/core/discovery"
)

// Multicast group and timings for presence announcement.
const (
	// MulticastAddress is the group announcements are published to. It sits in the
	// administratively scoped block (239.0.0.0/8), which routers do not forward beyond
	// the local network - exactly the scope Req 1.3 describes as "a shared IP network".
	MulticastAddress = "239.255.41.7"
	// MulticastPort is the UDP port for announcements. It is separate from the TCP
	// listening port so discovery and data never contend for the same socket.
	MulticastPort = 45771

	// PublishInterval is how often presence is republished. Req 1.9 allows up to 10
	// seconds; 5 gives one free miss before a peer would notice a gap.
	PublishInterval = 5 * time.Second
	// ExpirySweepInterval is how often stale peers are swept. Req 1.5 allows 5 seconds
	// to notice a 30-second absence, so sweeping every 2 leaves room for a late sweep.
	ExpirySweepInterval = 2 * time.Second
	// ReadBufferBytes bounds one datagram read. An announcement is a small JSON object;
	// this is generous enough for a 64-character multi-byte display name and small
	// enough that a malformed length cannot be used to make the node allocate.
	ReadBufferBytes = 2048
)

// BeaconEvents is how the beacon reports what it saw without depending on the reporting
// package or on a logger. Every callback is optional.
//
// Malformed announcements go to OnMalformed rather than being dropped silently, because
// Req 1.11 requires a malformed-announcement event to be recorded.
type BeaconEvents struct {
	// OnMalformed is called with the reasons an announcement was discarded (Req 1.11).
	OnMalformed func(reasons []string, fromAddress string)
	// OnObserved is called when an announcement updated the visible Peer list.
	OnObserved func(fingerprint string, fromAddress string)
	// OnExpired is called with the fingerprints removed by a sweep (Req 1.5).
	OnExpired func(fingerprints []string)
	// OnError is called for a socket-level problem that did not stop the beacon.
	OnError func(err error)
}

// Beacon publishes this node's presence and feeds received announcements into a
// PeerRegistry (Req 1.1, 1.3, 1.5, 1.9).
//
// It owns two goroutines: one publishing on a ticker, one reading datagrams. The registry
// is not safe for concurrent use, so every mutation of it happens under this type's mutex,
// and the mutex is never held across a socket operation.
type Beacon struct {
	registry *discovery.PeerRegistry
	clk      clock.Clock
	events   BeaconEvents

	// announcement is what gets published. It is rebuilt on each publish from the
	// current port, so a port that was chosen by the operating system after Bind is
	// still published correctly.
	mu           sync.Mutex
	announcement discovery.Announcement

	// send and receive are separate sockets on purpose. A single socket joined to the
	// group would receive its own announcements on most platforms, and filtering them
	// out by fingerprint would mask a genuine misconfiguration where two nodes share a
	// fingerprint.
	send    *net.UDPConn
	receive *net.UDPConn
}

// NewBeacon returns a beacon that publishes announcement and records what it hears into
// registry.
func NewBeacon(
	registry *discovery.PeerRegistry,
	announcement discovery.Announcement,
	clk clock.Clock,
	events BeaconEvents,
) *Beacon {
	if clk == nil {
		clk = clock.NewRealClock()
	}
	return &Beacon{
		registry:     registry,
		clk:          clk,
		events:       events,
		announcement: announcement,
	}
}

// SetPort updates the port published in the announcement, for the case where Bind chose it.
func (b *Beacon) SetPort(port int) {
	b.mu.Lock()
	b.announcement.Port = port
	b.mu.Unlock()
}

// Announcement returns the announcement currently being published.
func (b *Beacon) Announcement() discovery.Announcement {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.announcement
}

// Start opens the sockets and runs the publish, receive, and expiry loops until ctx is
// done. It returns when every loop has stopped.
//
// The first publish happens immediately rather than after one tick, because Req 1.1 gives
// startup 2 seconds to publish and a 5-second ticker would miss that by itself.
func (b *Beacon) Start(ctx context.Context) error {
	group := &net.UDPAddr{IP: net.ParseIP(MulticastAddress), Port: MulticastPort}
	if group.IP == nil {
		return fmt.Errorf("multicast address %q is not an IP address", MulticastAddress)
	}

	send, err := net.DialUDP("udp4", nil, group)
	if err != nil {
		return fmt.Errorf("open multicast sender: %w", err)
	}
	// ListenMulticastUDP joins the group on every suitable interface, which is what a
	// machine with both wired and wireless interfaces needs: a peer may be on either.
	receive, err := net.ListenMulticastUDP("udp4", nil, group)
	if err != nil {
		_ = send.Close()
		return fmt.Errorf("join multicast group %s: %w", MulticastAddress, err)
	}
	_ = receive.SetReadBuffer(ReadBufferBytes * 16)

	b.mu.Lock()
	b.send, b.receive = send, receive
	b.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); b.publishLoop(ctx) }()
	go func() { defer wg.Done(); b.receiveLoop(ctx) }()
	go func() { defer wg.Done(); b.expiryLoop(ctx) }()

	<-ctx.Done()
	// Closing the sockets is what unblocks the blocking read; UDPConn has no
	// context-aware read.
	_ = send.Close()
	_ = receive.Close()
	wg.Wait()
	return nil
}

// publishLoop announces presence immediately and then every PublishInterval (Req 1.1, 1.9).
func (b *Beacon) publishLoop(ctx context.Context) {
	b.publishOnce()

	ticker := time.NewTicker(PublishInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.publishOnce()
		}
	}
}

func (b *Beacon) publishOnce() {
	b.mu.Lock()
	announcement := b.announcement
	send := b.send
	b.mu.Unlock()

	if send == nil {
		return
	}
	// The node's own announcement is validated before publishing. A local
	// misconfiguration - an over-long display name, an unbound port - would otherwise
	// become every peer's malformed-announcement event instead of this node's problem.
	if check := discovery.CheckAnnouncement(&announcement); check.Malformed != nil {
		b.reportError(fmt.Errorf("refusing to publish a malformed announcement: %v",
			check.Malformed))
		return
	}

	payload, err := discovery.EncodeAnnouncement(announcement)
	if err != nil {
		b.reportError(fmt.Errorf("encode announcement: %w", err))
		return
	}
	if _, err := send.Write(payload); err != nil && !isClosed(err) {
		b.reportError(fmt.Errorf("publish announcement: %w", err))
	}
}

// receiveLoop reads datagrams, validates them, and records the valid ones (Req 1.3, 1.11).
func (b *Beacon) receiveLoop(ctx context.Context) {
	b.mu.Lock()
	receive := b.receive
	b.mu.Unlock()
	if receive == nil {
		return
	}

	buffer := make([]byte, ReadBufferBytes)
	for {
		n, from, err := receive.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil || isClosed(err) {
				return
			}
			b.reportError(fmt.Errorf("read announcement: %w", err))
			continue
		}
		b.handleDatagram(buffer[:n], from)
	}
}

// handleDatagram validates one received announcement and records it. It is separate from the
// read loop so the whole decode-validate-record path is testable without a socket.
func (b *Beacon) handleDatagram(payload []byte, from *net.UDPAddr) {
	fromAddress := ""
	if from != nil {
		fromAddress = from.IP.String()
	}

	check := discovery.DecodeAndCheckAnnouncement(payload)
	if check.Malformed != nil {
		// Req 1.11: discard, leave the list unchanged, record the event.
		if b.events.OnMalformed != nil {
			b.events.OnMalformed(check.Malformed, fromAddress)
		}
		return
	}

	b.mu.Lock()
	own := b.announcement.Fingerprint
	b.mu.Unlock()
	if own != "" && check.Valid.Fingerprint == own {
		// This node's own announcement, echoed back by the group. Not an error and not a
		// peer.
		return
	}

	b.mu.Lock()
	outcome := b.registry.Observe(*check.Valid, discovery.MediumLAN, fromAddress)
	b.mu.Unlock()

	if outcome.AtCapacity != nil {
		b.reportError(outcome.AtCapacity)
		return
	}
	if b.events.OnObserved != nil {
		b.events.OnObserved(check.Valid.Fingerprint, fromAddress)
	}
}

// expiryLoop sweeps stale peers every ExpirySweepInterval (Req 1.5).
func (b *Beacon) expiryLoop(ctx context.Context) {
	ticker := time.NewTicker(ExpirySweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.mu.Lock()
			removed := b.registry.Expire(discovery.DefaultPeerTTL)
			b.mu.Unlock()
			if len(removed) > 0 && b.events.OnExpired != nil {
				b.events.OnExpired(removed)
			}
		}
	}
}

// Sweep runs one expiry pass immediately, for a caller driving the beacon by hand.
func (b *Beacon) Sweep() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.registry.Expire(discovery.DefaultPeerTTL)
}

// Visible returns the current visible Peer list. It goes through the beacon's mutex because
// the registry is mutated by the receive and expiry loops.
func (b *Beacon) Visible() []discovery.VisiblePeer {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.registry.Visible()
}

// AddManual records a manually supplied Peer (Req 1.6, 1.7, 1.10), under the same mutex the
// loops use.
func (b *Beacon) AddManual(host string, port int) discovery.ManualOutcome {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.registry.AddManual(host, port)
}

func (b *Beacon) reportError(err error) {
	if b.events.OnError != nil {
		b.events.OnError(err)
	}
}

// isClosed reports whether an error is the "socket already closed" case that cancellation
// produces. Cancellation closes the socket to unblock a read, so this is expected shutdown
// rather than a failure worth reporting.
func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
