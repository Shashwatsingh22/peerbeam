package app

import (
	"context"
	"testing"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/discovery"
)

// TestEndToEndInboundPairingOverLoopback drives the responder side of pairing through the real
// accept path: one node starts its listener with an inbound confirmer, the other dials it with
// PairWith, and both must end up trusting each other. This is the two-machine pairing flow, run
// between two processes in one test over the loopback fabric because no CI host has two radios.
//
// Requirements: 9.1, 9.3, 9.4, 9.9
func TestEndToEndInboundPairingOverLoopback(t *testing.T) {
	set := newFabricSet()
	dialer := newE2ENode(t, set, "dialer")
	accepter := newE2ENode(t, set, "accepter")

	// The accepter confirms any code it is shown. In production this is where the receiving user
	// is prompted; the test stands in for that user with a yes.
	if err := accepter.node.SetInboundConfirmer(
		PairConfirmerFunc(func(context.Context, string, string, string) (bool, error) {
			return true, nil
		}),
	); err != nil {
		t.Fatalf("setting inbound confirmer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := accepter.node.Start(ctx); err != nil {
		t.Fatalf("starting accepter: %v", err)
	}
	t.Cleanup(accepter.node.Stop)
	if err := dialer.node.Start(ctx); err != nil {
		t.Fatalf("starting dialer: %v", err)
	}
	t.Cleanup(dialer.node.Stop)

	// The dialer needs the accepter in its visible list to dial it, so put it there on both
	// media the loopback fabric offers.
	dialer.node.Registry().Observe(discovery.Announcement{
		DisplayName:     "accepter",
		Fingerprint:     accepter.node.Fingerprint(),
		ProtocolVersion: ProtocolVersion,
		Port:            accepter.port,
	}, discovery.MediumLAN, "127.0.0.1")

	// The dialer confirms too, standing in for its user.
	result, failure := dialer.node.PairWith(ctx, accepter.node.Fingerprint(),
		PairConfirmerFunc(func(context.Context, string, string, string) (bool, error) {
			return true, nil
		}))
	if failure != nil {
		t.Fatalf("dialer pairing: %s", failure.Error())
	}
	if result.Fingerprint != accepter.node.Fingerprint() {
		t.Fatalf("paired with %s, want the accepter %s", result.Fingerprint, accepter.node.Fingerprint())
	}

	// The dialer trusts the accepter immediately on return.
	if _, trusted := dialer.node.Pairing().Trusted(accepter.node.Fingerprint()); !trusted {
		t.Fatal("the dialer does not trust the accepter after pairing")
	}

	// The accepter records trust on its own goroutine, so wait briefly for it to land.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, trusted := accepter.node.Pairing().Trusted(dialer.node.Fingerprint()); trusted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the accepter never recorded trust for the dialer")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestEndToEndInboundPairingDeclinedByDefault checks the safe default: a node with no inbound
// confirmer declines an inbound pairing rather than trusting silently (Req 9.9).
func TestEndToEndInboundPairingDeclinedByDefault(t *testing.T) {
	set := newFabricSet()
	dialer := newE2ENode(t, set, "dialer")
	accepter := newE2ENode(t, set, "accepter")
	// No SetInboundConfirmer on the accepter, so it must decline.

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := accepter.node.Start(ctx); err != nil {
		t.Fatalf("starting accepter: %v", err)
	}
	t.Cleanup(accepter.node.Stop)
	if err := dialer.node.Start(ctx); err != nil {
		t.Fatalf("starting dialer: %v", err)
	}
	t.Cleanup(dialer.node.Stop)

	dialer.node.Registry().Observe(discovery.Announcement{
		DisplayName:     "accepter",
		Fingerprint:     accepter.node.Fingerprint(),
		ProtocolVersion: ProtocolVersion,
		Port:            accepter.port,
	}, discovery.MediumLAN, "127.0.0.1")

	_, failure := dialer.node.PairWith(ctx, accepter.node.Fingerprint(),
		PairConfirmerFunc(func(context.Context, string, string, string) (bool, error) {
			return true, nil
		}))
	if failure == nil {
		t.Fatal("pairing completed even though the accepter had no confirmer")
	}
	// Neither side recorded trust.
	if _, trusted := accepter.node.Pairing().Trusted(dialer.node.Fingerprint()); trusted {
		t.Fatal("the accepter trusted the dialer despite declining")
	}
	if _, trusted := dialer.node.Pairing().Trusted(accepter.node.Fingerprint()); trusted {
		t.Fatal("the dialer trusted the accepter despite the decline")
	}
}
