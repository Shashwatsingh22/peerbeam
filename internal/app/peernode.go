package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/clipboard"
	"github.com/peerbeam/peerbeam/internal/core/clock"
	"github.com/peerbeam/peerbeam/internal/core/codec"
	"github.com/peerbeam/peerbeam/internal/core/crypto"
	"github.com/peerbeam/peerbeam/internal/core/discovery"
	"github.com/peerbeam/peerbeam/internal/core/report"
	"github.com/peerbeam/peerbeam/internal/core/session"
	"github.com/peerbeam/peerbeam/internal/core/transfer"
	"github.com/peerbeam/peerbeam/internal/core/transport"
	"github.com/peerbeam/peerbeam/internal/core/trust"
	"github.com/peerbeam/peerbeam/internal/platform/clip"
	"github.com/peerbeam/peerbeam/internal/platform/share"
)

// ProtocolVersion is the version this build speaks, published in the announcement (Req 1.1).
const ProtocolVersion = codec.ProtocolVersion

// errInboundConfirmerAfterStart is returned when the inbound pairing confirmer is set too late.
var errInboundConfirmerAfterStart = errors.New("the inbound confirmer cannot be set after the node has started")

// PeerDiscoveryWait is how long `peers` holds for a first observation on a freshly started node
// before rendering (Req 5.5).
//
// It is a shade over the LAN republish interval, so a peer already announcing on the network is
// seen within one publish cycle. It is deliberately shorter than the 15-second Bluetooth discovery
// budget: a human running `peers` will not wait that long, and the interactive session keeps the
// list live rather than taking a single snapshot, so the full budget is paid there instead.
const PeerDiscoveryWait = 6 * time.Second

// Config is everything a PeerNode needs that is not an interface. Zero values are filled in with
// defaults, so a caller only states what it wants to change.
type Config struct {
	// DisplayName is what peers see (Req 1.1). It defaults to the host name.
	DisplayName string
	// ListenPort is the TCP port to bind. 0 lets the operating system choose, which is what
	// the tests use so several nodes can run in one process.
	ListenPort int
	// StateDir holds identity.key and trusted.json. Empty means ~/.peerbeam.
	StateDir string
}

// Ports is the set of platform adapters a PeerNode runs on. Passing them in rather than
// constructing them inside is what lets the end-to-end tests substitute loopback transports and an
// in-memory clipboard while exercising the same wiring.
type Ports struct {
	// Transports is the enabled Transport set, in no particular order: ranking is
	// transport.RankFor's job (Req 2.1).
	Transports []transport.Transport
	// Clipboard reads and writes the system clipboard (Req 6.1, 6.2).
	Clipboard clip.ClipboardPort
	// Share opens the operating system share interface (Req 12.4).
	Share share.SharePort
	// KeyStore holds the long-term identity (Req 9.1).
	KeyStore trust.KeyStore
	// TrustStore persists Trusted_Peer entries (Req 9.10).
	TrustStore trust.TrustStore
	// Events receives event log entries (Req 13.5).
	Events report.EventSink
	// Display is where received text is presented (Req 5.3). Nil writes to standard output.
	Display TextDisplay
	// Presence publishes this node's presence and discovers peers on each medium (Req 3.1).
	// Empty means no discovery runs, which is what the in-process tests want: they place peers
	// in the registry directly rather than over a radio or a socket.
	Presence []PresenceSource
	// Clock is the time source. Nil means the real clock.
	Clock clock.Clock
}

// PeerNode is one running copy of Peerbeam.
//
// It owns the root context and wait group, so Stop is the single place every goroutine the node
// started is joined. Nothing below this layer holds a context: services take one per call, and
// per-Session goroutines take a child context, which is what keeps one Session's cancellation from
// reaching another (Req 4.3).
type PeerNode struct {
	config Config
	ports  Ports
	clk    clock.Clock

	identity trust.IdentityKeyPair
	pairing  *trust.PairingService
	registry *discovery.PeerRegistry
	sessions *session.SessionRegistry
	log      *report.EventLog

	// clipboards holds per-Session clipboard policy state, keyed by fingerprint (Req 6.3).
	// It is separate from the Session because clipboard preferences outlive a Session: a user
	// who enabled auto-apply does not expect it to reset on a reconnect.
	clipMu     sync.Mutex
	clipboards map[string]*clipboard.SessionClipboard

	// bindings holds the live Transport binding per Session. It is the only mutable link
	// between a Session and its connection, which is what makes a rebind a single assignment
	// rather than a rebuild (Req 3.4).
	bindMu   sync.Mutex
	bindings map[session.SessionId]*binding

	// pins holds the user's Transport pin per Peer (Req 2.10). Like the clipboard
	// preferences, it lives on the node rather than on the Session because it outlives a
	// reconnect.
	pinMu sync.Mutex
	pins  map[string]string

	// clipParts buffers multi-part clipboard payloads until every index has arrived (Req 6.8).
	// It is guarded by clipMu alongside the clipboard state it feeds.
	clipParts map[string][][]byte

	// display is where presented text goes (Req 5.3).
	display TextDisplay

	// inboundConfirmer is how the responder side of pairing asks its user to confirm a code when
	// a peer dials this node to pair (Req 9.9). Nil means decline, which is the safe default.
	inboundConfirmer PairConfirmer

	// unavailable records the Transports this host cannot offer, for the Req 12.3 and 12.8
	// startup report.
	unavailable []report.Failure

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	started bool
	stopped bool
	mu      sync.Mutex
}

// binding is one Session's live connection and the state that belongs to the binding rather than to
// the Session.
//
// The split matters for Req 3.4: everything here is discarded on a rebind, and everything on the
// Session survives it. Keepalive strikes and metrics belong here because ten below-target samples
// on a dying LAN link say nothing about the Bluetooth link that replaced it; the sequence counter
// and the keys belong to the Session because a rebind must not restart either.
type binding struct {
	conn      transport.TransportConnection
	transport transport.Transport
	crypto    *crypto.SessionCrypto
	keepalive *transport.KeepaliveTracker
	metrics   *transport.TransportMetrics
	reader    *codec.FrameReader
	cancel    context.CancelFunc
	// transfer is the sender-side progress for a Transfer running on this binding, or nil.
	transfer *transfer.TransferProgress

	// mu guards the counters below, which the reader, writer, router, and metrics loops all
	// touch. The connection itself needs no lock: one reader and one writer own their
	// directions.
	mu sync.Mutex
	// keepaliveSent maps a keepalive's sequence number to when it went out, so its
	// acknowledgement becomes a round-trip measurement (Req 2.7).
	keepaliveSent map[uint64]time.Time
	delivered     int
	lastDelivered uint64
	// received holds inbound Transfer chunks by absolute byte offset (Req 3.5, 7.2).
	received      map[int64][]byte
	receivedBytes int64
	writtenBytes  int64
	// sampledBytes is the running total at the last goodput sample, so each sample reports the
	// bytes moved in that second rather than since the Session began.
	sampledBytes int64
}

// NewPeerNode builds a node from a config and a set of ports.
//
// It performs the startup steps Req 9.1, 9.2, 9.10, 12.3, and 12.8 describe, in that order: load or
// create the identity, load the trust store, then work out which Transports this host can actually
// offer. Each of the three can fail in a way that leaves the node running but degraded, and each
// records a Failure rather than aborting, because Req 12.3 and 12.8 both require startup to
// complete and report rather than exit.
//
// The exception is the identity. Without it there is nothing to authenticate with, so a key setup
// failure is recorded and every Session request is rejected (Req 9.2) - but the node still starts,
// so the user can run `peerbeam status` and see why.
func NewPeerNode(config Config, ports Ports) (*PeerNode, error) {
	if ports.Clock == nil {
		ports.Clock = clock.NewRealClock()
	}
	if config.DisplayName == "" {
		config.DisplayName = defaultDisplayName()
	}
	if ports.Clipboard == nil {
		ports.Clipboard = clip.NewMemoryClipboardPort()
	}
	if ports.Share == nil {
		ports.Share = share.NewSharePort()
	}
	if ports.Events == nil {
		ports.Events = report.NewMemoryEventSink()
	}
	if ports.TrustStore == nil {
		ports.TrustStore = trust.NewMemoryTrustStore()
	}
	if ports.Display == nil {
		ports.Display = NewWriterTextDisplay(os.Stdout)
	}

	node := &PeerNode{
		config:     config,
		ports:      ports,
		clk:        ports.Clock,
		registry:   discovery.NewPeerRegistry(ProtocolVersion, ports.Clock),
		sessions:   session.NewSessionRegistry(ports.Clock),
		log:        report.NewEventLog(ports.Events),
		clipboards: map[string]*clipboard.SessionClipboard{},
		bindings:   map[session.SessionId]*binding{},
		pins:       map[string]string{},
		clipParts:  map[string][][]byte{},
		display:    ports.Display,
	}

	node.pairing = trust.NewPairingService(ports.TrustStore, ports.Clock)

	// Req 9.1, 9.2: identity first, since the trust store's integrity tag is keyed from it.
	if ports.KeyStore != nil {
		identity, err := ports.KeyStore.LoadOrCreateIdentity()
		node.pairing.SetIdentity(identity, err)
		if err == nil {
			node.identity = identity
		} else {
			node.unavailable = append(node.unavailable,
				report.Describe(&report.KeyStoreFailed{
					Step:   "load or create the identity key",
					Reason: err.Error(),
				}, config.DisplayName))
		}
	} else {
		node.pairing.SetIdentity(trust.IdentityKeyPair{},
			errors.New("no key store was configured"))
	}

	// Req 9.10: entries load before the first Session request.
	if err := node.pairing.Load(); err != nil {
		node.unavailable = append(node.unavailable,
			report.Describe(&report.TrustStoreFailed{Reason: err.Error()}, config.DisplayName))
	}

	// Req 12.3, 12.8: report the Transports this host cannot offer, and start anyway.
	node.recordUnavailableTransports()

	return node, nil
}

// availabilityReporter is the optional interface a Transport implements when it can be unavailable
// on a given host. transport.Transport itself does not carry it: a LAN socket is either bound or an
// error, whereas Bluetooth is legitimately absent on many machines (Req 12.3), so availability is an
// adapter concern rather than part of the core contract.
type availabilityReporter interface {
	Available() bool
	UnavailableReason() string
}

// recordUnavailableTransports notes each Transport this host cannot offer (Req 12.3), and the
// neither-available case of Req 12.8.
func (n *PeerNode) recordUnavailableTransports() {
	usable := 0
	for _, t := range n.ports.Transports {
		reporter, canReport := t.(availabilityReporter)
		if canReport && !reporter.Available() {
			n.unavailable = append(n.unavailable,
				report.Describe(&report.TransportUnavailable{
					TransportName: t.Name(),
					Reason:        reporter.UnavailableReason(),
				}, n.config.DisplayName))
			continue
		}
		usable++
	}

	if usable == 0 {
		// Req 12.8: no candidate Transport at all, so the node starts and says so rather
		// than appearing to work and failing on first use.
		n.unavailable = append(n.unavailable,
			report.Describe(&report.NoCandidateTransport{}, n.config.DisplayName))
	}
}

// UsableTransports is the Transport set that reported itself available, which is what the ladder
// ranks over (Req 2.1, 12.3).
func (n *PeerNode) UsableTransports() []transport.Transport {
	out := make([]transport.Transport, 0, len(n.ports.Transports))
	for _, t := range n.ports.Transports {
		if reporter, canReport := t.(availabilityReporter); canReport && !reporter.Available() {
			continue
		}
		out = append(out, t)
	}
	return out
}

// StartupReport lists what the node could not bring up (Req 12.3, 12.8, 9.2, 9.11). It is empty on
// a healthy node.
func (n *PeerNode) StartupReport() []report.Failure {
	return append([]report.Failure(nil), n.unavailable...)
}

// Ready reports whether the node can admit Sessions. A node with a failed key store or trust store
// runs and answers queries but rejects every Session request (Req 9.2, 9.11).
func (n *PeerNode) Ready() bool { return n.pairing.Ready() && n.pairing.StoreFailure() == nil }

// Identity is this node's long-term key pair.
func (n *PeerNode) Identity() trust.IdentityKeyPair { return n.identity }

// Fingerprint is this node's own fingerprint, published in its announcement.
func (n *PeerNode) Fingerprint() string {
	if len(n.identity.PublicKey) == 0 {
		return ""
	}
	return n.identity.Fingerprint()
}

// Announcement is what the beacon publishes (Req 1.1).
func (n *PeerNode) Announcement() discovery.Announcement {
	return discovery.Announcement{
		DisplayName:     n.config.DisplayName,
		Fingerprint:     n.Fingerprint(),
		ProtocolVersion: ProtocolVersion,
		Port:            n.config.ListenPort,
	}
}

// Registry is the visible Peer list (Req 1.2).
func (n *PeerNode) Registry() *discovery.PeerRegistry { return n.registry }

// HasPresence reports whether any Presence_Source is wired, which is whether discovery can populate
// the list at all. A node with none - the in-process tests, or a host with no usable medium - has
// nothing to wait for.
func (n *PeerNode) HasPresence() bool { return len(n.ports.Presence) > 0 }

// WaitForFirstPeer blocks until at least one peer is visible, the deadline passes, or ctx is
// cancelled (Req 5.5).
//
// A freshly started node has an empty list until a presence source hears something - up to a
// republish interval on LAN and up to the 15-second discovery budget on Bluetooth. This lets a
// command hold briefly for that first observation rather than rendering an empty list as if it
// were the final answer. It returns whether a peer became visible, so a caller can distinguish
// "still empty after waiting" from "found something".
//
// It polls rather than subscribing: the registry has no change signal, adding one for a
// human-paced wait would be machinery out of proportion to the need, and a short poll interval is
// imperceptible next to the seconds this waits.
//
// The ceiling is measured against real wall-clock time, not the node's injected Clock. The Clock
// exists to make protocol timeouts testable by advancing it by hand; this is a human-facing wait
// for a socket to hear something, so it must elapse on its own. Bounding it by the injected Clock
// would loop forever under a manual clock that no goroutine advances.
func (n *PeerNode) WaitForFirstPeer(ctx context.Context, within time.Duration) bool {
	if n.registry.Len() > 0 {
		return true
	}
	deadline := time.NewTimer(within)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return n.registry.Len() > 0
		case <-deadline.C:
			return n.registry.Len() > 0
		case <-ticker.C:
			if n.registry.Len() > 0 {
				return true
			}
		}
	}
}

// Pairing is the trust and pairing service (Req 9).
func (n *PeerNode) Pairing() *trust.PairingService { return n.pairing }

// Sessions is the Session registry (Req 4.1).
func (n *PeerNode) Sessions() *session.SessionRegistry { return n.sessions }

// Log is the event log (Req 13.5).
func (n *PeerNode) Log() *report.EventLog { return n.log }

// Transports is the enabled Transport set.
func (n *PeerNode) Transports() []transport.Transport { return n.ports.Transports }

// Clipboard is the system clipboard port.
func (n *PeerNode) Clipboard() clip.ClipboardPort { return n.ports.Clipboard }

// Share is the share-sheet port.
func (n *PeerNode) Share() share.SharePort { return n.ports.Share }

// DisplayName is this node's name.
func (n *PeerNode) DisplayName() string { return n.config.DisplayName }

// SetDisplay replaces where received text is presented (Req 5.3). It must be called before Start,
// because the router reads the display from its own goroutine once running and swapping it under a
// live reader would race. The interactive session uses it to route inbound text into its chat view.
func (n *PeerNode) SetDisplay(display TextDisplay) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.started {
		return errors.New("the display cannot be changed after the node has started")
	}
	n.display = display
	n.ports.Display = display
	return nil
}

// SetListenPort records the port actually bound, so the announcement publishes the real one.
func (n *PeerNode) SetListenPort(port int) {
	n.mu.Lock()
	n.config.ListenPort = port
	n.mu.Unlock()
}

// ClipboardFor returns the per-Session clipboard policy for a Peer, creating it on first use.
//
// Keyed by fingerprint rather than by SessionId because the preferences outlive the Session: a user
// who turned on auto-apply does not expect a reconnect to turn it off again.
func (n *PeerNode) ClipboardFor(fingerprint string) *clipboard.SessionClipboard {
	n.clipMu.Lock()
	defer n.clipMu.Unlock()

	existing, found := n.clipboards[fingerprint]
	if found {
		return existing
	}
	fresh := clipboard.NewSessionClipboard(n.clk)
	n.clipboards[fingerprint] = fresh
	return fresh
}

// Start brings the node up: it opens the root context and starts the background loops.
//
// It returns as soon as the loops are running, because the CLI needs to issue commands against a
// node that is already discovering peers. Stop is what waits for them.
func (n *PeerNode) Start(ctx context.Context) error {
	n.mu.Lock()
	if n.started {
		n.mu.Unlock()
		return errors.New("the node is already started")
	}
	n.ctx, n.cancel = context.WithCancel(ctx)
	n.started = true
	n.mu.Unlock()

	// One accept loop per Transport. Each runs under the root context, so Stop closes every
	// listener.
	for _, t := range n.ports.Transports {
		if reporter, ok := t.(interface{ Available() bool }); ok && !reporter.Available() {
			continue
		}
		listener := t
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			if err := listener.Listen(n.ctx, n.onInbound); err != nil && n.ctx.Err() == nil {
				n.reportFailure(&report.TransportUnavailable{
					TransportName: listener.Name(),
					Reason:        err.Error(),
				}, n.config.DisplayName)
			}
		}()
	}

	// One Presence_Source per available medium (Req 3.1). Each publishes this node and feeds
	// discovered peers into the registry until the root context is done. A source that returns
	// an error stopped early; it is reported naming its medium, and the others keep running
	// (Req 3.6).
	for _, source := range n.ports.Presence {
		src := source
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			if err := src.Run(n.ctx); err != nil && n.ctx.Err() == nil {
				n.reportFailure(&report.TransportUnavailable{
					TransportName: src.TransportName(),
					Reason:        err.Error(),
				}, n.config.DisplayName)
			}
		}()
	}

	// The expiry sweep for the visible Peer list (Req 1.5). The LAN beacon runs its own, but a
	// node with only Bluetooth still needs peers to age out.
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.expiryLoop(n.ctx)
	}()

	return nil
}

// Stop cancels the root context and waits for every goroutine the node started.
//
// It is the single join point on purpose: a node that leaked a goroutine per Session would fail
// Req 11.7's processor budget after enough connects and disconnects, and the leak would be invisible
// until then.
func (n *PeerNode) Stop() {
	n.mu.Lock()
	if !n.started || n.stopped {
		n.mu.Unlock()
		return
	}
	n.stopped = true
	cancel := n.cancel
	n.mu.Unlock()

	cancel()

	// Close every live binding, which unblocks the readers.
	n.bindMu.Lock()
	bindings := make([]*binding, 0, len(n.bindings))
	for _, b := range n.bindings {
		bindings = append(bindings, b)
	}
	n.bindings = map[session.SessionId]*binding{}
	n.bindMu.Unlock()

	for _, b := range bindings {
		if b.cancel != nil {
			b.cancel()
		}
		if b.conn != nil {
			_ = b.conn.Close()
		}
	}

	n.wg.Wait()
}

// expiryLoop removes peers that have gone quiet on every medium (Req 1.5).
func (n *PeerNode) expiryLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.registry.Expire(discovery.DefaultPeerTTL)
		}
	}
}

// onInbound handles a connection a Transport accepted (Req 10.1, 10.8, 10.9).
//
// It runs each accepted connection on its own goroutine under the node's wait group, so Stop joins
// it, and hands the connection to handleInbound, which routes it to pairing or the session
// handshake by its first frame type (Req 9.1, 10.1, 10.8, 10.9). Nothing is admitted before the
// relevant exchange completes.
func (n *PeerNode) onInbound(conn transport.TransportConnection) {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.handleInbound(conn)
	}()
}

// writerLoop drains a Session's outbound channels, preferring control traffic over bulk (Req 4.6).
//
// The preference is what keeps a text message responsive while a transfer saturates the same
// Session. The non-blocking select on Control first is the whole mechanism: Go's select chooses
// uniformly among ready cases, so a plain three-way select would give a saturated bulk channel an
// even chance every time and a text message would wait behind chunks.
func (n *PeerNode) writerLoop(ctx context.Context, s *session.Session, b *binding) {
	for {
		// Control first, without blocking. If something is waiting there it goes now.
		select {
		case <-ctx.Done():
			return
		case message, open := <-s.Control:
			if !open {
				return
			}
			if !n.writeMessage(s, b, message) {
				return
			}
			continue
		default:
		}

		// Nothing on control, so wait for either channel.
		select {
		case <-ctx.Done():
			return
		case message, open := <-s.Control:
			if !open {
				return
			}
			if !n.writeMessage(s, b, message) {
				return
			}
		case message, open := <-s.Outbound:
			if !open {
				return
			}
			if !n.writeMessage(s, b, message) {
				return
			}
		}
	}
}

// writeMessage seals and frames one Message. It returns false when the binding is finished.
func (n *PeerNode) writeMessage(s *session.Session, b *binding, message session.Message) bool {
	header := codec.EncodeFrame(codec.Frame{
		ProtocolVersion: ProtocolVersion,
		Type:            message.Type,
		Sequence:        message.Sequence,
		Payload:         nil,
	})
	if header.TooLarge != nil {
		return true // a zero-payload header cannot be too large; defensive only
	}

	// Req 10.2: every payload is sealed, whatever its type.
	sealed, err := b.crypto.Seal(header.Bytes[:codec.HeaderBytes], message.Sequence, message.Payload)
	if err != nil {
		n.reportFailure(&report.PayloadTooLarge{
			Length:  len(message.Payload),
			Maximum: codec.MaxPayloadBytes,
		}, s.DisplayName)
		return true
	}

	encoded := codec.EncodeFrame(codec.Frame{
		ProtocolVersion: ProtocolVersion,
		Type:            message.Type,
		Sequence:        message.Sequence,
		Payload:         sealed,
	})
	if encoded.TooLarge != nil {
		n.reportFailure(&report.PayloadTooLarge{
			Length:  encoded.TooLarge.PayloadLength,
			Maximum: encoded.TooLarge.Maximum,
		}, s.DisplayName)
		return true
	}

	if err := b.conn.Write(encoded.Bytes); err != nil {
		// The Transport went away. The switch policy decides what happens next; this loop
		// just stops.
		return false
	}
	// Counted for the goodput sample (Req 2.7). The frame is counted rather than the payload,
	// because goodput is what crossed the wire.
	b.noteWritten(len(encoded.Bytes))
	return true
}

// keepaliveLoop sends a keepalive every five seconds and marks the Transport unavailable on the
// third consecutive miss (Req 3.1, 3.2).
func (n *PeerNode) keepaliveLoop(ctx context.Context, s *session.Session, b *binding) {
	ticker := time.NewTicker(transport.KeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sequence := s.Sequence.NextSequence()
			message := session.Message{
				Type:     uint8(codec.MsgKeepalive),
				Sequence: sequence,
				Control:  true, // keepalive must not queue behind a transfer
			}
			// Recorded before the send, so an acknowledgement that arrives immediately still
			// finds its start time (Req 2.7).
			b.noteKeepaliveSent(sequence, n.clk.Now())

			select {
			case s.Control <- message:
			case <-ctx.Done():
				return
			default:
				// The control channel is full, which means the writer is stuck. That is
				// itself a missed keepalive.
				if b.keepalive.OnTimeout() {
					n.markUnavailable(s, b)
					return
				}
			}
		}
	}
}

// metricsLoop samples goodput and RTT once per second (Req 2.7).
func (n *PeerNode) metricsLoop(ctx context.Context, b *binding) {
	ticker := time.NewTicker(transport.MetricsSampleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Req 2.7: one goodput sample per second, from the bytes actually moved in that
			// second. takeThroughput resets the window, so a sample is a rate rather than a
			// running total.
			//
			// RTT is not sampled here: it comes from the keepalive exchange, which has its
			// own timer, and measuring it on this ticker would report the age of the last
			// keepalive rather than a round trip.
			b.metrics.RecordGoodput(b.takeThroughput())
		}
	}
}

// markUnavailable applies the switch decision after keepalive struck the active Transport out
// (Req 3.2, 3.3).
func (n *PeerNode) markUnavailable(s *session.Session, b *binding) {
	media := n.registry.MediaFor(s.Fingerprint)
	ranked := transport.RankFor(n.UsableTransports(), media)

	best := ""
	var bestGoodput int64
	for _, candidate := range ranked {
		if candidate.Name() == b.transport.Name() {
			continue
		}
		best, bestGoodput = candidate.Name(), candidate.ExpectedGoodputBytesPerSecond()
		break
	}

	// Req 2.10 and 2.11: a pin overrides the ranking. Passing it in is what makes the pin mean
	// something - DecideSwitch will not rebind a pinned Session, it will disconnect instead, and
	// the reason names the pinned Transport.
	decision := transport.DecideSwitch(transport.SwitchInputs{
		ActiveTransportName:     b.transport.Name(),
		ActiveExpectedGoodput:   b.transport.ExpectedGoodputBytesPerSecond(),
		BestCandidateName:       best,
		BestCandidateGoodput:    bestGoodput,
		LastTransportChangeAt:   n.clk.Now(),
		PinnedTransportName:     n.pinnedTransport(s.Fingerprint),
		ActiveIsAvailable:       false,
		ActiveUnavailableReason: "keepalive missed three times",
		Now:                     n.clk.Now(),
	})

	switch decision.Kind() {
	case transport.DecisionRebind:
		n.reportTransportChange(s, b.transport.Name(), decision.Rebind,
			report.ReasonPreviousUnavailable)
	case transport.DecisionGoDisconnected:
		// Req 3.6: the Session goes disconnected and keeps its queue.
		s.MarkDisconnected()
		n.reportFailure(&report.SwitchFailed{
			FromTransport: b.transport.Name(),
			ToTransport:   "none",
			Reason:        decision.GoDisconnected,
		}, s.DisplayName)
	}
}

// reportTransportChange writes the Req 13.3 change report and its event log entry.
func (n *PeerNode) reportTransportChange(
	s *session.Session,
	from, to string,
	reason report.TransportChangeReason,
) {
	change := report.TransportChange{
		SessionId:         s.Id.String(),
		PeerDisplayName:   s.DisplayName,
		PreviousTransport: from,
		NewTransport:      to,
		Reason:            reason,
	}
	fmt.Println(change.String())

	n.writeEvent(report.EventTransportChanged, s.DisplayName, s.Fingerprint, change.String())
}

// writeEvent records one event log entry, reporting a write failure rather than losing it silently
// (Req 13.5, 13.7).
func (n *PeerNode) writeEvent(kind report.EventType, peerName, fingerprint, outcome string) {
	failure := n.log.Write(report.EventEntry{
		Timestamp:       n.clk.Now(),
		Type:            kind,
		PeerDisplayName: report.PeerName(peerName, fingerprint),
		PeerFingerprint: fingerprint,
		Outcome:         outcome,
	})
	if failure != nil {
		// Req 13.7: report it, and change no Session state. Printing is all this does.
		fmt.Println(failure.AsFailure(peerName).String())
	}
}

// reportFailure renders an error through the single Describe mapping and prints it (Req 13.4).
func (n *PeerNode) reportFailure(err report.AppError, peerName string) {
	fmt.Println(report.Describe(err, peerName).String())
}

// reportCodecError maps a codec error onto the reporting types.
func (n *PeerNode) reportCodecError(err *codec.CodecError, peerName string) {
	switch {
	case err.UnsupportedVersion != nil:
		n.reportFailure(&report.CodecUnsupportedVersion{
			Declared: uint8(err.UnsupportedVersion.Declared),
			Accepted: uint8(err.UnsupportedVersion.Accepted),
		}, peerName)
	case err.PayloadTooLarge != nil:
		n.reportFailure(&report.PayloadTooLarge{
			Length:  int(err.PayloadTooLarge.DeclaredLength),
			Maximum: err.PayloadTooLarge.Maximum,
		}, peerName)
	case err.FramingMismatch != nil:
		n.reportFailure(&report.CodecFramingMismatch{
			DeclaredLength: err.FramingMismatch.DeclaredLength,
			ReceivedLength: err.FramingMismatch.ReceivedCount,
		}, peerName)
	}
}

// StatusLines renders one status row per Session (Req 13.1, 13.2).
func (n *PeerNode) StatusLines() []report.StatusLine {
	sessions := n.sessions.All()
	out := make([]report.StatusLine, 0, len(sessions))

	for _, s := range sessions {
		var peerName, transportName *string
		var goodput, rtt *int64

		if s.DisplayName != "" {
			name := s.DisplayName
			peerName = &name
		}
		if active := s.ActiveTransportName(); active != "" {
			transportName = &active
		}

		n.bindMu.Lock()
		b := n.bindings[s.Id]
		n.bindMu.Unlock()
		if b != nil && b.metrics != nil {
			if sample, ok := b.metrics.Goodput(); ok {
				value := sample.BytesPerSecond
				goodput = &value
			}
			if millis, ok := b.metrics.RTTMillis(); ok {
				rtt = &millis
			}
		}

		out = append(out, report.BuildStatusLine(s.Id.String(), peerName, transportName, goodput, rtt))
	}
	return out
}

// defaultDisplayName is the host name, truncated to the 64-character limit of Req 1.1.
func defaultDisplayName() string {
	name := hostName()
	if name == "" {
		return "peerbeam-node"
	}
	runes := []rune(name)
	if len(runes) > discovery.MaxDisplayNameChars {
		runes = runes[:discovery.MaxDisplayNameChars]
	}
	return string(runes)
}

// hostName is the machine's name, or "" when it cannot be read. It is a separate function so the
// default display name is testable without depending on the test host's name.
func hostName() string {
	name, err := osHostname()
	if err != nil {
		return ""
	}
	return name
}

// osHostname is the seam tests use to make the default display name deterministic. Production
// leaves it pointing at os.Hostname.
var osHostname = os.Hostname

// PeerIsVisible reports whether a fingerprint is in the visible Peer list (Req 1.2).
//
// It is a method rather than leaving callers to scan Visible() themselves, so the fingerprint
// comparison happens in one place. The list is keyed by fingerprint internally, but Visible returns
// a slice because Req 1.2 describes an ordered list a user reads.
func (n *PeerNode) PeerIsVisible(fingerprint string) bool {
	for _, peer := range n.registry.Visible() {
		if peer.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}

// rootContext is the node's root context, or context.Background when Start has not run.
//
// The fallback is not a convenience for tests. context.WithTimeout panics on a nil parent, so any
// path that derives a context has to be safe before Start: a clipboard apply reached during
// establishment, or a report written while the node is still coming up, would otherwise take the
// process down over a missing parent rather than doing the work.
func (n *PeerNode) rootContext() context.Context {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ctx == nil {
		return context.Background()
	}
	return n.ctx
}

// bindingFor returns a Session's live Transport binding, or nil.
//
// It exists for the status renderer and for tests that need to observe what a Session actually
// received. Reading the binding is the only honest way to check inbound behaviour now that the router
// consumes the inbound channel: a test that read the channel itself would be competing with the
// router for the same messages and would see whichever won.
func (n *PeerNode) bindingFor(id session.SessionId) *binding {
	n.bindMu.Lock()
	defer n.bindMu.Unlock()
	return n.bindings[id]
}
