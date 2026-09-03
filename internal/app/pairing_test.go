package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/codec"
	"github.com/peerbeam/peerbeam/internal/core/crypto"
	"github.com/peerbeam/peerbeam/internal/core/transport"
	"github.com/peerbeam/peerbeam/internal/core/trust"
	"pgregory.net/rapid"
)

// connectedPair returns two TransportConnections wired to each other over a buffered in-memory
// link. A real Bluetooth L2CAP channel and a TCP socket both buffer, so both sides can send their
// opening frame before either reads - which the pairing exchange relies on, since it is symmetric
// and both halves write first. net.Pipe is synchronous and would deadlock exactly there, so it is
// deliberately not used here.
func connectedPair() (transport.TransportConnection, transport.TransportConnection) {
	ab := newBufferedPipe()
	ba := newBufferedPipe()
	return &bufferedConn{read: ba, write: ab}, &bufferedConn{read: ab, write: ba}
}

// bufferedPipe is an in-memory byte stream built on a buffered channel: writes hand a copy to the
// channel and do not block until it fills, reads block until a chunk arrives or it is closed. A
// buffered channel is used rather than a hand-rolled cond because its blocking and wakeup semantics
// are the standard library's and not something this test has to get right.
type bufferedPipe struct {
	ch        chan []byte
	closeOnce sync.Once
	done      chan struct{}
	mu        sync.Mutex
	leftover  []byte
}

func newBufferedPipe() *bufferedPipe {
	return &bufferedPipe{ch: make(chan []byte, 64), done: make(chan struct{})}
}

func (p *bufferedPipe) Write(b []byte) (int, error) {
	cp := append([]byte(nil), b...)
	select {
	case <-p.done:
		return 0, net.ErrClosed
	case p.ch <- cp:
		return len(b), nil
	}
}

func (p *bufferedPipe) Read(into []byte) (int, error) {
	p.mu.Lock()
	if len(p.leftover) > 0 {
		n := copy(into, p.leftover)
		p.leftover = p.leftover[n:]
		p.mu.Unlock()
		return n, nil
	}
	p.mu.Unlock()

	select {
	case chunk, ok := <-p.ch:
		if !ok {
			return 0, net.ErrClosed
		}
		n := copy(into, chunk)
		if n < len(chunk) {
			p.mu.Lock()
			p.leftover = append(p.leftover, chunk[n:]...)
			p.mu.Unlock()
		}
		return n, nil
	case <-p.done:
		// Drain anything already queued before reporting the close, so bytes written before
		// Close are still delivered.
		select {
		case chunk := <-p.ch:
			n := copy(into, chunk)
			if n < len(chunk) {
				p.mu.Lock()
				p.leftover = append(p.leftover, chunk[n:]...)
				p.mu.Unlock()
			}
			return n, nil
		default:
			return 0, net.ErrClosed
		}
	}
}

func (p *bufferedPipe) Close() error {
	p.closeOnce.Do(func() { close(p.done) })
	return nil
}

// bufferedConn is a TransportConnection over two bufferedPipes, one per direction.
type bufferedConn struct {
	read  *bufferedPipe
	write *bufferedPipe
}

func (c *bufferedConn) TransportName() string         { return transport.NameBT }
func (c *bufferedConn) Read(into []byte) (int, error) { return c.read.Read(into) }
func (c *bufferedConn) Write(b []byte) error {
	_, err := c.write.Write(b)
	return err
}
func (c *bufferedConn) Close() error {
	c.read.Close()
	c.write.Close()
	return nil
}

// pairingNode builds a minimal node with a real identity and trust store, enough to run runPairing.
// A fresh temp dir per node gives each its own Ed25519 identity, so the two derive a real code.
func pairingNode(t *testing.T, name string) *PeerNode {
	t.Helper()
	set := newFabricSet()
	return newE2ENode(t, set, name).node
}

// scriptedConfirmer answers ConfirmPairing from a fixed decision and records what code it was
// shown, so a test can both drive the outcome and assert the code was derived rather than received.
type scriptedConfirmer struct {
	confirm bool
	mu      sync.Mutex
	sawCode string
	sawName string
}

func (c *scriptedConfirmer) ConfirmPairing(_ context.Context, _, peerDisplayName, code string) (bool, error) {
	c.mu.Lock()
	c.sawCode = code
	c.sawName = peerDisplayName
	c.mu.Unlock()
	return c.confirm, nil
}

// runBothSides runs the two halves of a pairing exchange concurrently and returns each side's
// result. Both must run at once because net.Pipe is unbuffered: a single-threaded caller would
// deadlock on the first write.
func runBothSides(
	alice, bob *PeerNode,
	aliceConfirm, bobConfirm *scriptedConfirmer,
) (aliceRes, bobRes *pairResult, aliceErr, bobErr error) {
	connA, connB := connectedPair()
	ctx := context.Background()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		res, failure := alice.runPairing(ctx, connA, aliceConfirm)
		aliceRes = res
		if failure != nil {
			aliceErr = failure
		}
	}()
	go func() {
		defer wg.Done()
		res, failure := bob.runPairing(ctx, connB, bobConfirm)
		bobRes = res
		if failure != nil {
			bobErr = failure
		}
	}()
	wg.Wait()
	// Close only after both halves have returned. Closing as each side finishes would let the
	// side that returns first tear down the pipe under the other's final read, which is a race
	// in the harness rather than anything the exchange does wrong.
	_ = connA.Close()
	_ = connB.Close()
	return
}

// Property 48: the verification code is derived, never carried.
//
// Both sides must show the same code, and that code must not appear in any byte either side put on
// the wire. The second half is the security-relevant one: it is what makes a network attacker
// unable to learn or dictate the code.
//
// Requirements: 9.2
func TestPropertyPairingCodeIsDerivedNeverCarried(t *testing.T) {
	// Not a rapid property over many cases: each case builds two Ed25519 identities off disk,
	// which is too heavy to run hundreds of times. The invariant is over the two fixed roles, so
	// a handful of distinct identity pairs exercises it.
	for i := 0; i < 8; i++ {
		alice := pairingNode(t, "alice")
		bob := pairingNode(t, "bob")

		// Capture the bytes each side writes by pairing over a recording pipe.
		aliceWrite := &recordingConn{}
		bobWrite := &recordingConn{}
		connA, connB := connectedPair()
		aliceConn := &teeConn{TransportConnection: connA, record: aliceWrite}
		bobConn := &teeConn{TransportConnection: connB, record: bobWrite}

		ac := &scriptedConfirmer{confirm: true}
		bc := &scriptedConfirmer{confirm: true}

		ctx := context.Background()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); alice.runPairing(ctx, aliceConn, ac) }()
		go func() { defer wg.Done(); bob.runPairing(ctx, bobConn, bc) }()
		wg.Wait()
		// Close after both return, so neither tears the pipe down under the other's final read.
		connA.Close()
		connB.Close()

		ac.mu.Lock()
		bc.mu.Lock()
		aliceCode, bobCode := ac.sawCode, bc.sawCode
		ac.mu.Unlock()
		bc.mu.Unlock()

		if aliceCode == "" || bobCode == "" {
			t.Fatalf("a side never saw a code: alice=%q bob=%q", aliceCode, bobCode)
		}
		if aliceCode != bobCode {
			t.Fatalf("the two sides derived different codes: alice=%q bob=%q", aliceCode, bobCode)
		}
		// The code must be absent from every byte either side transmitted.
		if strings.Contains(string(aliceWrite.bytes()), aliceCode) {
			t.Fatalf("the code %q appears in alice's transmitted bytes", aliceCode)
		}
		if strings.Contains(string(bobWrite.bytes()), bobCode) {
			t.Fatalf("the code %q appears in bob's transmitted bytes", bobCode)
		}
	}
}

// Property 49: pairing completes only on mutual confirmation.
//
// Over all four combinations of the two users' decisions, trust is recorded on both nodes in
// exactly the both-confirmed case, and in the other three neither node records trust.
//
// Requirements: 9.4, 9.5
func TestPropertyPairingNeedsMutualConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name           string
		aliceC, bobC   bool
		wantBothPaired bool
	}{
		{"both confirm", true, true, true},
		{"alice rejects", false, true, false},
		{"bob rejects", true, false, false},
		{"both reject", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alice := pairingNode(t, "alice")
			bob := pairingNode(t, "bob")
			aliceFP := alice.Fingerprint()
			bobFP := bob.Fingerprint()

			aRes, bRes, _, _ := runBothSides(alice, bob,
				&scriptedConfirmer{confirm: tc.aliceC},
				&scriptedConfirmer{confirm: tc.bobC})

			// Trust is checked against the store, not the return value, because the store is
			// what a later Connect consults.
			_, aliceTrustsBob := alice.pairing.Trusted(bobFP)
			_, bobTrustsAlice := bob.pairing.Trusted(aliceFP)

			if tc.wantBothPaired {
				if !aliceTrustsBob || !bobTrustsAlice {
					t.Fatalf("both confirmed but trust is alice->bob=%v bob->alice=%v",
						aliceTrustsBob, bobTrustsAlice)
				}
				if aRes == nil || bRes == nil {
					t.Fatalf("both confirmed but a result was nil: alice=%v bob=%v", aRes, bRes)
				}
			} else {
				if aliceTrustsBob || bobTrustsAlice {
					t.Fatalf("pairing was not mutual but trust was recorded: alice->bob=%v bob->alice=%v",
						aliceTrustsBob, bobTrustsAlice)
				}
				if aRes != nil || bRes != nil {
					t.Fatalf("pairing failed but a result was non-nil: alice=%v bob=%v", aRes, bRes)
				}
			}
		})
	}
}

// Property 50: a mismatched key is reported apart from an untrusted peer.
//
// When a fingerprint already holds a key, an offer carrying a different key under that fingerprint
// is reported as a key mismatch and never as an untrusted peer, and records no trust. Fabricating a
// colliding fingerprint is not possible, so this exercises the decision Admit makes directly, which
// is the branch runPairing consults.
//
// Requirements: 9.7
func TestPropertyMismatchedKeyIsReportedApart(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// A trust store already holding one key under some fingerprint. A MemoryTrustStore
		// seeded directly is the cleanest way to reach the stored-but-different state; a real
		// pairing would need a second matching key, which adds nothing to what is being tested.
		storedKey := make([]byte, trust.PublicKeyBytes)
		for i := range storedKey {
			storedKey[i] = byte(rapid.IntRange(0, 255).Draw(rt, "k"))
		}
		peer, err := trust.NewTrustedPeer(storedKey, "peer", time.Now())
		if err != nil {
			rt.Skip("generated key was not a valid trusted peer")
		}

		trustStore := trust.NewMemoryTrustStore()
		if err := trustStore.Put(peer); err != nil {
			rt.Fatalf("seeding: %v", err)
		}
		pairing := trust.NewPairingService(trustStore, nil)
		// Admit needs a loaded, ready store and a local identity to reach the mismatch branch
		// rather than the store-failure branch.
		pairing.SetIdentity(newIdentity(rt), nil)
		if err := pairing.Load(); err != nil {
			rt.Fatalf("loading: %v", err)
		}
		fingerprint := trust.Fingerprint(storedKey)

		// A different key presented under that same fingerprint.
		otherKey := append([]byte(nil), storedKey...)
		otherKey[0] ^= 0xFF

		decision := pairing.Admit(fingerprint, otherKey)
		if decision.Kind() != trust.AdmitKeyMismatch {
			rt.Fatalf("a differing key under a stored fingerprint gave %s, want key mismatch",
				decision.Kind())
		}
	})
}

// newIdentity returns a valid local identity for a PairingService under test.
func newIdentity(rt *rapid.T) trust.IdentityKeyPair {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		rt.Fatalf("generating identity: %v", err)
	}
	return trust.IdentityKeyPair{PublicKey: pub, PrivateKey: priv}
}

// Property 51: nothing but pairing precedes trust.
//
// Any frame that is not a pairing frame, delivered before trust exists, is a protocol violation
// that leaves all trust state untouched. This is asserted through readPairingFrame, which is the
// single gate every pre-trust read passes through.
//
// Requirements: 9.8
func TestPropertyOnlyPairingPrecedesTrust(t *testing.T) {
	nonPairing := []codec.MessageType{
		codec.MsgKeyExchangeInit, codec.MsgText, codec.MsgClipboard,
		codec.MsgTransferOffer, codec.MsgChunk, codec.MsgKeepalive,
	}
	for _, mt := range nonPairing {
		t.Run(mt.String(), func(t *testing.T) {
			node := pairingNode(t, "local")
			before := len(node.pairing.TrustedPeers())

			connA, connB := connectedPair()
			// Feed one non-pairing frame from the far side.
			go func() {
				encoded := codec.EncodeFrame(codec.Frame{
					ProtocolVersion: ProtocolVersion,
					Type:            uint8(mt),
					Payload:         []byte("payload"),
				})
				_ = connB.Write(encoded.Bytes)
			}()

			deadline := time.Now().Add(crypto.VerificationCodeValidity)
			_, failure := node.readPairingFrame(context.Background(), connA, codec.MsgPairingOffer, deadline)
			connA.Close()
			connB.Close()

			if failure == nil {
				t.Fatalf("a %s before trust was accepted rather than refused", mt)
			}
			if len(node.pairing.TrustedPeers()) != before {
				t.Fatal("a pre-trust non-pairing frame changed the trust store")
			}
		})
	}
}

// recordingConn accumulates every byte written to it, so a test can assert on what crossed the wire.
type recordingConn struct {
	mu  sync.Mutex
	buf []byte
}

func (r *recordingConn) add(p []byte) {
	r.mu.Lock()
	r.buf = append(r.buf, p...)
	r.mu.Unlock()
}

func (r *recordingConn) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf...)
}

// teeConn wraps a TransportConnection and copies every written byte into record, so the transmitted
// bytes can be inspected without changing what the peer receives.
type teeConn struct {
	transport.TransportConnection
	record *recordingConn
}

func (t *teeConn) Write(p []byte) error {
	t.record.add(p)
	return t.TransportConnection.Write(p)
}
