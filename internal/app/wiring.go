package app

import (
	"github.com/peerbeam/peerbeam/internal/core/clock"
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
	transports, unavailable := availableTransports(config.DisplayName)

	node, err := NewPeerNode(config, Ports{
		Transports: transports,
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
	node.unavailable = append(node.unavailable, unavailable...)
	return node, nil
}

// availableTransports builds the Transport set for this host and reports what it could not.
func availableTransports(displayName string) ([]transport.Transport, []report.Failure) {
	var transports []transport.Transport
	var unavailable []report.Failure

	// LAN. Req 12.8 asks whether a reachable IP interface exists at all; the transport is added
	// either way so its name appears in reports, and its availability is what the ranking
	// filters on.
	lanTransport := lan.NewLanTransport()
	if available, reason := lan.Availability(); !available {
		unavailable = append(unavailable, report.Describe(&report.TransportUnavailable{
			TransportName: transport.NameLAN,
			Reason:        reason,
		}, displayName))
	} else {
		transports = append(transports, lanTransport)
	}

	// Bluetooth. A missing shim is the normal case on most hosts, so it is reported once at
	// startup and the node carries on with LAN (Req 12.3).
	bridge := bt.NewShimBluetoothBridge("")
	btTransport := bt.NewBtTransport(bridge)
	if reason := btTransport.UnavailableReason(); reason != "" {
		unavailable = append(unavailable, report.Describe(&report.TransportUnavailable{
			TransportName: transport.NameBT,
			Reason:        reason,
		}, displayName))
	} else {
		transports = append(transports, btTransport)
	}

	return transports, unavailable
}
