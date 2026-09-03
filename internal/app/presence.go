package app

import (
	"context"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/discovery"
	"github.com/peerbeam/peerbeam/internal/core/transport"
	"github.com/peerbeam/peerbeam/internal/platform/bt"
	"github.com/peerbeam/peerbeam/internal/platform/lan"
)

// PresenceSource publishes this node's presence on one medium and feeds what it hears back into
// the visible Peer list. It is the piece that makes `peerbeam peers` show anything: without a
// running source, the registry is only ever written by a manual `peers add`.
//
// The interface is deliberately narrow so PeerNode.Start drives every medium the same way, and so
// the in-process tests can supply their own source or none at all. Run blocks until ctx is done,
// matching lan.Beacon.Start, so Start can put each source in its own goroutine and join them all
// through the node's wait group.
type PresenceSource interface {
	// Medium is the medium this source covers.
	Medium() discovery.Medium
	// TransportName is the ranking-and-reporting name of the transport this source publishes on,
	// e.g. "LAN_Transport". A source that stops means that transport can no longer discover
	// peers, so its failure is reported as that transport being unavailable, which is the shape
	// the startup report and Req 12.3 already use.
	TransportName() string
	// Run publishes and receives until ctx is done, then returns. A returned error is a source
	// that stopped early; Start reports it and leaves the other sources running.
	Run(ctx context.Context) error
}

// BluetoothAdvertiseInterval is how often BT_Presence republishes the announcement record.
//
// The parent spec's Req 1.9 allows presence to lapse for up to 10 seconds, so republishing every 5
// gives one free miss. Republishing rather than advertising once also recovers a shim that died and
// was restarted: a restarted shim has forgotten what it was advertising, and re-sending the same
// record is idempotent and cheap.
const BluetoothAdvertiseInterval = 5 * time.Second

// lanPresence is the LAN Presence_Source over the multicast beacon.
//
// It is a thin wrapper: lan.Beacon already owns the publish, receive, and expiry loops and already
// blocks until its context is done, so Run is just Start. The wrapper exists so the node holds a
// PresenceSource rather than a *lan.Beacon and treats both media through one interface.
type lanPresence struct {
	beacon *lan.Beacon
}

func newLanPresence(beacon *lan.Beacon) *lanPresence {
	return &lanPresence{beacon: beacon}
}

func (p *lanPresence) Medium() discovery.Medium { return discovery.MediumLAN }

func (p *lanPresence) TransportName() string { return transport.NameLAN }

func (p *lanPresence) Run(ctx context.Context) error {
	return p.beacon.Start(ctx)
}

// btPresence is the Bluetooth Presence_Source over BtTransport.
//
// Unlike the beacon, BtTransport has no single blocking loop: advertising is a one-shot call that
// has to be repeated on a ticker, and scanning is a call that feeds the registry until its context
// is done. Run drives both under one context so Stop tears both down together.
type btPresence struct {
	transport *bt.BtTransport
	// record is the announcement bytes to advertise. It is captured once at construction: the
	// display name, fingerprint, and port do not change while the node runs, and the port is
	// resolved before wiring builds this source.
	record []byte
	// registry is the list scan results feed into.
	registry *discovery.PeerRegistry
	// ownFingerprint filters this node's own record if the radio reflects it back.
	ownFingerprint string
	// onMalformed and onObserved report discovery events, matching the beacon's callbacks so the
	// node wires both media identically.
	onMalformed func(reasons []string, address string)
	onObserved  func(fingerprint string, address string)
}

func newBtPresence(
	transport *bt.BtTransport,
	record []byte,
	registry *discovery.PeerRegistry,
	ownFingerprint string,
	onMalformed func(reasons []string, address string),
	onObserved func(fingerprint string, address string),
) *btPresence {
	return &btPresence{
		transport:      transport,
		record:         record,
		registry:       registry,
		ownFingerprint: ownFingerprint,
		onMalformed:    onMalformed,
		onObserved:     onObserved,
	}
}

func (p *btPresence) Medium() discovery.Medium { return discovery.MediumBluetooth }

func (p *btPresence) TransportName() string { return transport.NameBT }

// Run advertises on a ticker and scans continuously until ctx is done.
//
// ScanInto blocks, so it owns the calling goroutine and the advertise ticker gets its own. The
// first advertisement goes out immediately rather than after one tick, so a peer scanning right now
// sees this node without waiting a full interval - the same reasoning as the beacon's immediate
// first publish.
func (p *btPresence) Run(ctx context.Context) error {
	go p.advertiseLoop(ctx)
	return p.transport.ScanInto(
		ctx, p.registry, p.ownFingerprint, p.onMalformed, p.onObserved)
}

func (p *btPresence) advertiseLoop(ctx context.Context) {
	// StartAdvertising is idempotent on the shim side, so a failure here is transient - a shim
	// still coming up, or one being restarted - and the next tick retries it. It is not fatal to
	// the source, which is why the error is dropped rather than returned: returning it would stop
	// scanning too.
	_ = p.transport.StartAdvertising(ctx, p.record)

	ticker := time.NewTicker(BluetoothAdvertiseInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Stop advertising on the way out, with a fresh context: ctx is already done, and
			// StopAdvertising needs a live one to reach the shim. It is best-effort - the shim
			// exits when its stdin closes regardless - so a short timeout is enough.
			stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = p.transport.StopAdvertising(stopCtx)
			cancel()
			return
		case <-ticker.C:
			_ = p.transport.StartAdvertising(ctx, p.record)
		}
	}
}
