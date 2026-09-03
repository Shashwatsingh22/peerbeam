package app

import (
	"github.com/peerbeam/peerbeam/internal/core/clock"
	"github.com/peerbeam/peerbeam/internal/core/discovery"
	"github.com/peerbeam/peerbeam/internal/core/report"
	"github.com/peerbeam/peerbeam/internal/core/transport"
	"github.com/peerbeam/peerbeam/internal/core/trust"
	"github.com/peerbeam/peerbeam/internal/platform/bt"
	"github.com/peerbeam/peerbeam/internal/platform/clip"
	"github.com/peerbeam/peerbeam/internal/platform/lan"
	"github.com/peerbeam/peerbeam/internal/platform/share"
	"github.com/peerbeam/peerbeam/internal/platform/store"
)

// NewProductionNode builds a node on the real platform adapters.
//
// This is the only function in the codebase that names a concrete implementation for every
// interface. Everything else takes what it is given, which is what lets the end-to-end tests run the
// same wiring over loopback transports and an in-memory clipboard.
//
// It does not fail on a missing capability. Req 12.3 wants a host with no Bluetooth to start with
// LAN only and say so, and Req 12.8 wants a host with neither to start and say that; both are
// recorded in the startup report rather than returned as an error, so `peerbeam status` can show the
// user why something is missing instead of the process refusing to run.
func NewProductionNode(config Config) (*PeerNode, error) {
	clk := clock.NewRealClock()

	keyStore, err := store.NewFileKeyStore(config.StateDir)
	if err != nil {
		return nil, err
	}

	// The trust store's integrity tag is keyed from the identity, so the identity is loaded
	// first. A key store failure is not fatal here: NewPeerNode records it and rejects every
	// Session request (Req 9.2), which is more useful than refusing to start, because the user
	// needs a running command line to find out what went wrong.
	identity, keyErr := keyStore.LoadOrCreateIdentity()

	var trustStore trust.TrustStore
	if keyErr == nil {
		fileTrustStore, storeErr := store.NewFileTrustStore(config.StateDir, identity)
		if storeErr != nil {
			return nil, storeErr
		}
		trustStore = fileTrustStore
	} else {
		// With no identity there is no tag key, so a file-backed store cannot be verified.
		// An in-memory store keeps the node's shape intact while every Session request is
		// rejected anyway.
		trustStore = trust.NewMemoryTrustStore()
	}

	// The display name is resolved before the transports are probed, so the unavailability
	// reports name this machine rather than "unknown peer". NewPeerNode would fill it in too, but
	// by then these Failures are already built.
	if config.DisplayName == "" {
		config.DisplayName = defaultDisplayName()
	}

	built := buildTransports(config)

	node, err := NewPeerNode(config, Ports{
		Transports: built.transports,
		Clipboard:  clip.NewCommandClipboardPort(),
		Share:      share.NewSharePort(),
		KeyStore:   keyStore,
		TrustStore: trustStore,
		Events:     report.NewMemoryEventSink(),
		Clock:      clk,
	})
	if err != nil {
		return nil, err
	}

	// Carry forward what the platform could not offer, so the startup report names it (Req 12.3,
	// 12.8).
	node.unavailable = append(node.unavailable, built.unavailable...)

	// The port actually bound is published, not the one requested (Req 3.5): a config of 0 lets
	// the OS choose, and a peer needs the chosen port to dial back.
	if built.lanPort != 0 {
		node.SetListenPort(built.lanPort)
	}

	// Presence sources are built last, because each needs the node's registry and its
	// announcement, and the announcement needs the bound port set above (Req 3.1, 4.3).
	node.ports.Presence = buildPresenceSources(node, built)

	return node, nil
}

// builtTransports is what buildTransports hands back: the enabled Transport set, the concrete
// handles the Presence_Sources need, the bound LAN port, and what could not be offered.
type builtTransports struct {
	transports  []transport.Transport
	unavailable []report.Failure

	lan     *lan.LanTransport
	lanPort int
	bt      *bt.BtTransport
}

// buildTransports builds the Transport set for this host and reports what it could not.
//
// It keeps the concrete *lan.LanTransport and *bt.BtTransport rather than only their interface
// values, because the Presence_Sources need methods that are not on transport.Transport:
// Bluetooth advertising and scanning, and the beacon that wraps the LAN registry. Ranking, the
// ladder, and switching still see only the interface.
func buildTransports(config Config) builtTransports {
	var built builtTransports

	// LAN. Req 12.8 asks whether a reachable IP interface exists at all; the transport is added
	// either way so its name appears in reports, and its availability is what the ranking
	// filters on.
	lanTransport := lan.NewLanTransport()
	built.lan = lanTransport
	if available, reason := lan.Availability(); !available {
		built.unavailable = append(built.unavailable, report.Describe(&report.TransportUnavailable{
			TransportName: transport.NameLAN,
			Reason:        reason,
		}, config.DisplayName))
	} else {
		// Bind now, so the announcement can publish the real port before any peer tries to
		// dial back. Listen binds lazily too and is idempotent, so binding here does not
		// conflict with the accept loop Start opens. A bind failure is recorded like any other
		// unavailability rather than aborting: the node can still discover and be discovered on
		// Bluetooth.
		if port, err := lanTransport.Bind(config.ListenPort); err != nil {
			built.unavailable = append(built.unavailable, report.Describe(&report.TransportUnavailable{
				TransportName: transport.NameLAN,
				Reason:        err.Error(),
			}, config.DisplayName))
		} else {
			built.lanPort = port
			built.transports = append(built.transports, lanTransport)
		}
	}

	// Bluetooth. A missing shim is the normal case on most hosts, so it is reported once at
	// startup and the node carries on with LAN (Req 12.3).
	bridge := bt.NewShimBluetoothBridge("")
	btTransport := bt.NewBtTransport(bridge)
	built.bt = btTransport
	if reason := btTransport.UnavailableReason(); reason != "" {
		built.unavailable = append(built.unavailable, report.Describe(&report.TransportUnavailable{
			TransportName: transport.NameBT,
			Reason:        reason,
		}, config.DisplayName))
	} else {
		built.transports = append(built.transports, btTransport)
	}

	return built
}

// buildPresenceSources builds one Presence_Source per available medium.
//
// A source is built only for a medium whose Transport was added to the enabled set, so a host with
// no Bluetooth gets a LAN source alone and a host with neither gets none. The malformed and
// observed callbacks feed the node's event log, matching how the beacon and the Bluetooth scan
// already report on their own.
func buildPresenceSources(node *PeerNode, built builtTransports) []PresenceSource {
	var sources []PresenceSource
	announcement := node.Announcement()

	// A malformed record is reported through the single Describe mapping (Req 1.11). An observed
	// peer is not logged as an event: the event log's four types are session and transfer
	// lifecycle, and a discovered peer is neither - its visible effect is the peer appearing in
	// the list. onObserved stays a hook rather than being dropped so a later "peer appeared"
	// notice in the interactive layer has somewhere to attach.
	onMalformed := func(reasons []string, address string) {
		node.reportFailure(&report.AnnouncementMalformed{Reasons: reasons}, address)
	}
	var onObserved func(fingerprint, address string)

	if built.lan != nil && transportEnabled(built.transports, transport.NameLAN) {
		beacon := lan.NewBeacon(node.registry, announcement, node.clk, lan.BeaconEvents{
			OnMalformed: onMalformed,
			OnObserved:  onObserved,
		})
		sources = append(sources, newLanPresence(beacon))
	}

	if built.bt != nil && transportEnabled(built.transports, transport.NameBT) {
		record, err := discovery.EncodeAnnouncement(announcement)
		if err == nil {
			sources = append(sources, newBtPresence(
				built.bt, record, node.registry, node.Fingerprint(), onMalformed, onObserved))
		} else {
			// A local announcement that will not encode is this node's own problem, recorded
			// so the user sees why Bluetooth discovery is not running rather than silently
			// omitting the source.
			node.unavailable = append(node.unavailable, report.Describe(&report.TransportUnavailable{
				TransportName: transport.NameBT,
				Reason:        "cannot encode this node's announcement: " + err.Error(),
			}, node.config.DisplayName))
		}
	}

	return sources
}

// transportEnabled reports whether a Transport with the given name made it into the enabled set.
func transportEnabled(transports []transport.Transport, name string) bool {
	for _, t := range transports {
		if t.Name() == name {
			return true
		}
	}
	return false
}
