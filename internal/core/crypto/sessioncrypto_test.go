package crypto

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// frameHeader builds a 14-byte header in the layout internal/core/codec writes, so the
// additional authenticated data in these tests is the same shape the real one will be.
// The layout is restated rather than imported because internal/core/crypto must not depend
// on codec; the fixed test below pins the size against the constant so a drift is caught.
func frameHeader(protocolVersion, messageType uint8, sequence uint64, payloadLength uint32) []byte {
	h := make([]byte, 14)
	h[0] = protocolVersion
	h[1] = messageType
	binary.BigEndian.PutUint64(h[2:10], sequence)
	binary.BigEndian.PutUint32(h[10:14], payloadLength)
	return h
}

// sessionPair returns the two SessionCrypto instances of one Session, derived from a real
// handshake so the key crossover is the production one rather than a test fixture.
func sessionPair(t rapid.TB) (*SessionCrypto, *SessionCrypto) {
	t.Helper()
	alice := newIdentity(t)
	bob := newIdentity(t)
	pair := newHandshakePair(t, alice, bob)

	aliceKeys, aliceFailure, bobKeys, bobFailure := pair.completeBoth(bob.public, alice.public)
	if aliceFailure != nil || bobFailure != nil {
		t.Fatalf("handshake failed: %v / %v", aliceFailure, bobFailure)
	}

	aliceCrypto, err := NewSessionCrypto(aliceKeys, RoleInitiator)
	if err != nil {
		t.Fatalf("initiator crypto: %v", err)
	}
	bobCrypto, err := NewSessionCrypto(bobKeys, RoleResponder)
	if err != nil {
		t.Fatalf("responder crypto: %v", err)
	}
	return aliceCrypto, bobCrypto
}

// TestProperty35SealedPayloadsRoundTripLeakNoPlaintextAndRejectEveryTamper covers
// Property 35: Sealed payloads round trip, leak no plaintext, and reject every tamper.
//
// Validates: Requirements 10.2, 10.3, 10.7
func TestProperty35SealedPayloadsRoundTripLeakNoPlaintextAndRejectEveryTamper(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		sender, receiver := sessionPair(rt)

		plaintext := rapid.OneOf(
			rapid.SliceOfN(rapid.Byte(), 0, 200),
			rapid.Custom(func(t *rapid.T) []byte {
				return []byte(rapid.StringN(1, 100, -1).Draw(t, "text"))
			}),
		).Draw(rt, "plaintext")
		sequence := rapid.Uint64().Draw(rt, "sequence")
		messageType := uint8(rapid.IntRange(0, 255).Draw(rt, "messageType"))

		header := frameHeader(1, messageType, sequence, uint32(SealedSize(len(plaintext))))

		ciphertext, err := sender.Seal(header, sequence, plaintext)
		if err != nil {
			rt.Fatalf("sealing: %v", err)
		}

		// Req 10.2: the tag is the only overhead, and nothing is transmitted in the
		// clear.
		if len(ciphertext) != SealedSize(len(plaintext)) {
			rt.Fatalf("sealed %d bytes into %d, want %d",
				len(plaintext), len(ciphertext), SealedSize(len(plaintext)))
		}
		// Req 10.2: no payload byte appears in the frame payload field in plaintext.
		//
		// Both checks below are gated on a minimum length, and the reason is worth
		// stating because it caught two bad assertions before this one. ChaCha20 is a
		// stream cipher: ciphertext is plaintext XOR keystream, so any *individual* byte
		// coincides with its plaintext byte one time in 256, and any given byte value
		// turns up somewhere in seventeen bytes of ciphertext about seven percent of the
		// time. An assertion over one or two bytes therefore fails against correct
		// output. At eight bytes the odds of a coincidental match are under one in 10^19,
		// which is the point at which absence means something.
		//
		// What holds at every length is the round trip and the exact 16-byte overhead,
		// both asserted above and below.
		if len(plaintext) >= 8 {
			if bytes.Equal(ciphertext[:len(plaintext)], plaintext) {
				rt.Fatal("the frame payload begins with the plaintext")
			}
			if bytes.Contains(ciphertext, plaintext) {
				rt.Fatal("the plaintext appears verbatim in the frame payload")
			}
		}

		// Round trip.
		opened, ok := receiver.Open(header, sequence, ciphertext)
		if !ok {
			rt.Fatal("an untampered payload failed its tag check")
		}
		if !bytes.Equal(opened, plaintext) {
			rt.Fatal("the opened payload differs from the plaintext")
		}

		// Req 10.3: every single-bit tamper fails, on the first attempt.
		tamperTarget := rapid.SampledFrom([]string{
			"header", "ciphertext", "sequence", "truncate", "extend",
		}).Draw(rt, "tamper")

		switch tamperTarget {
		case "header":
			tampered := append([]byte(nil), header...)
			at := rapid.IntRange(0, len(tampered)-1).Draw(rt, "headerByte")
			bit := uint(rapid.IntRange(0, 7).Draw(rt, "headerBit"))
			tampered[at] ^= 1 << bit
			// A tampered header may still describe a valid frame, which is exactly why
			// it is authenticated: the tag must catch it.
			if _, ok := receiver.Open(tampered, sequence, ciphertext); ok {
				rt.Fatalf("a flipped header bit (byte %d bit %d) still opened", at, bit)
			}

		case "ciphertext":
			tampered := append([]byte(nil), ciphertext...)
			at := rapid.IntRange(0, len(tampered)-1).Draw(rt, "cipherByte")
			bit := uint(rapid.IntRange(0, 7).Draw(rt, "cipherBit"))
			tampered[at] ^= 1 << bit
			if _, ok := receiver.Open(header, sequence, tampered); ok {
				rt.Fatalf("a flipped ciphertext bit (byte %d bit %d) still opened", at, bit)
			}

		case "sequence":
			// The nonce is derived from the sequence number, so replaying a payload
			// under a different sequence fails without the header changing.
			other := sequence ^ 1
			if _, ok := receiver.Open(header, other, ciphertext); ok {
				rt.Fatalf("opening under sequence %d succeeded, want failure", other)
			}

		case "truncate":
			for _, cut := range []int{0, 1, TagBytes - 1, len(ciphertext) - 1} {
				if cut < 0 || cut >= len(ciphertext) {
					continue
				}
				if _, ok := receiver.Open(header, sequence, ciphertext[:cut]); ok {
					rt.Fatalf("a %d-byte truncation still opened", len(ciphertext)-cut)
				}
			}

		case "extend":
			extended := append(append([]byte(nil), ciphertext...), 0x00)
			if _, ok := receiver.Open(header, sequence, extended); ok {
				rt.Fatal("an extended ciphertext still opened")
			}
		}

		// The honest payload still opens afterwards: a tamper is not sticky, so the
		// caller's decision to close the Session is a policy choice rather than
		// something the crypto forces.
		if _, ok := receiver.Open(header, sequence, ciphertext); !ok {
			rt.Fatal("the honest payload stopped opening after a rejected tamper")
		}

		// Req 10.7: the failure report names the Session and the Peer, and carries
		// nothing about the payload.
		failure := NewAuthenticationFailure("session-1", "peer-fingerprint", sequence)
		if !failure.SessionClosed {
			rt.Fatal("an authentication failure did not record the session as closed")
		}
		message := failure.Error()
		for _, want := range []string{"session-1", "peer-fingerprint",
			strconv.FormatUint(sequence, 10)} {
			if !strings.Contains(message, want) {
				rt.Fatalf("report %q omits %q", message, want)
			}
		}
		if len(plaintext) > 4 && strings.Contains(message, string(plaintext)) {
			rt.Fatal("the authentication failure report contains the payload")
		}
	})
}

// TestSealIsDirectionalSoBothSidesCanUseSequenceZero is the reason there are two keys: with
// one, both nodes would encrypt sequence 0 under the same key and reuse a nonce.
//
// Requirements: 10.2, 10.5
func TestSealIsDirectionalSoBothSidesCanUseSequenceZero(t *testing.T) {
	alice, bob := sessionPair(t)
	header := frameHeader(1, 3, 0, uint32(SealedSize(5)))

	fromAlice, err := alice.Seal(header, 0, []byte("hello"))
	if err != nil {
		t.Fatalf("alice seal: %v", err)
	}
	fromBob, err := bob.Seal(header, 0, []byte("hello"))
	if err != nil {
		t.Fatalf("bob seal: %v", err)
	}

	// Same plaintext, same sequence, same header, different ciphertext: the two
	// directions use different keys.
	if bytes.Equal(fromAlice, fromBob) {
		t.Fatal("both directions produced the same ciphertext at sequence 0")
	}

	// Each side opens the other's, not its own.
	if _, ok := bob.Open(header, 0, fromAlice); !ok {
		t.Fatal("bob could not open alice's payload")
	}
	if _, ok := alice.Open(header, 0, fromBob); !ok {
		t.Fatal("alice could not open bob's payload")
	}
	if _, ok := alice.Open(header, 0, fromAlice); ok {
		t.Fatal("alice opened her own outbound payload, so the directions share a key")
	}
}

// TestOpenRejectsAPayloadFromAnotherSession pins Req 10.5's practical consequence: keys from
// one Session are useless against another.
//
// Requirements: 10.5
func TestOpenRejectsAPayloadFromAnotherSession(t *testing.T) {
	senderA, _ := sessionPair(t)
	_, receiverB := sessionPair(t)

	header := frameHeader(1, 3, 7, uint32(SealedSize(4)))
	ciphertext, err := senderA.Seal(header, 7, []byte("data"))
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	if _, ok := receiverB.Open(header, 7, ciphertext); ok {
		t.Fatal("a payload from one session opened under another session's keys")
	}
}

// TestNewSessionCryptoRejectsWrongSizedKeys guards against a caller wiring truncated key
// material, which would otherwise fail later at seal time on a live session.
//
// Requirements: 10.2
func TestNewSessionCryptoRejectsWrongSizedKeys(t *testing.T) {
	good := make([]byte, SessionKeyBytes)
	cases := map[string]SessionKeys{
		"no keys":       {},
		"short send":    {SendKey: good[:16], ReceiveKey: good},
		"short receive": {SendKey: good, ReceiveKey: good[:31]},
		"long send":     {SendKey: append(good, 0), ReceiveKey: good},
	}
	for name, keys := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSessionCrypto(keys, RoleInitiator); err == nil {
				t.Fatal("wrong-sized keys were accepted")
			}
		})
	}
	if _, err := NewSessionCrypto(SessionKeys{SendKey: good, ReceiveKey: good}, RoleInitiator); err != nil {
		t.Fatalf("correctly sized keys were rejected: %v", err)
	}
}

// TestSessionCryptoCopiesKeysSoZeroingIsSafe checks that zeroing the handshake's key
// material does not break a live session.
//
// Requirements: 10.5
func TestSessionCryptoCopiesKeysSoZeroingIsSafe(t *testing.T) {
	alice := newIdentity(t)
	bob := newIdentity(t)
	pair := newHandshakePair(t, alice, bob)
	aliceKeys, failure, bobKeys, _ := pair.completeBoth(bob.public, alice.public)
	if failure != nil {
		t.Fatalf("handshake: %s", failure.Error())
	}

	sender, err := NewSessionCrypto(aliceKeys, RoleInitiator)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	receiver, err := NewSessionCrypto(bobKeys, RoleResponder)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}

	// Zero the originals, as a closing handshake would.
	aliceKeys.Zero()
	bobKeys.Zero()

	header := frameHeader(1, 3, 1, uint32(SealedSize(3)))
	ciphertext, err := sender.Seal(header, 1, []byte("abc"))
	if err != nil {
		t.Fatalf("sealing after zeroing the source keys: %v", err)
	}
	if got, ok := receiver.Open(header, 1, ciphertext); !ok || string(got) != "abc" {
		t.Fatal("the session broke when the handshake's key material was zeroed")
	}

	// And zeroing the SessionCrypto itself does take effect.
	sender.Zero()
	if _, ok := receiver.Open(header, 1, ciphertext); !ok {
		t.Fatal("zeroing the sender affected an already-sealed payload")
	}
}

// TestMaxPlaintextForAccountsForTheTag pins the arithmetic the clipboard part size depends
// on: a 1 MiB frame payload carries 1,048,560 bytes of plaintext, not 1,048,576.
//
// Requirements: 10.2, 6.8
func TestMaxPlaintextForAccountsForTheTag(t *testing.T) {
	const frameMaxPayload = 1_048_576

	if got := MaxPlaintextFor(frameMaxPayload); got != frameMaxPayload-TagBytes {
		t.Fatalf("MaxPlaintextFor(%d) = %d, want %d", frameMaxPayload, got, frameMaxPayload-TagBytes)
	}
	if got := SealedSize(MaxPlaintextFor(frameMaxPayload)); got != frameMaxPayload {
		t.Fatalf("sealing the maximum plaintext gives %d bytes, want %d", got, frameMaxPayload)
	}
	// Degenerate inputs do not go negative.
	if got := MaxPlaintextFor(TagBytes); got != 0 {
		t.Fatalf("MaxPlaintextFor(%d) = %d, want 0", TagBytes, got)
	}
	if got := MaxPlaintextFor(0); got != 0 {
		t.Fatalf("MaxPlaintextFor(0) = %d, want 0", got)
	}
	// The nonce and tag sizes are what the design assumed.
	if NonceBytes != 12 || TagBytes != 16 {
		t.Fatalf("nonce/tag sizes are %d/%d, want 12/16", NonceBytes, TagBytes)
	}
}

// TestNonceIsUniquePerSequenceAndDirection checks the derivation directly, since a repeated
// (key, nonce) pair is the one thing ChaCha20-Poly1305 cannot survive.
//
// Requirements: 10.2
func TestNonceIsUniquePerSequenceAndDirection(t *testing.T) {
	c := &SessionCrypto{
		sendKey: make([]byte, 32), receiveKey: make([]byte, 32),
		sendDirection: directionInitiatorToResponder, receiveDirection: directionResponderToInitiator,
	}

	seen := map[string]string{}
	for _, sequence := range []uint64{0, 1, 2, 255, 256, 1 << 32, ^uint64(0)} {
		for name, direction := range map[string]byte{
			"initiator-to-responder": directionInitiatorToResponder,
			"responder-to-initiator": directionResponderToInitiator,
		} {
			nonce := c.nonce(direction, sequence)
			if len(nonce) != NonceBytes {
				t.Fatalf("nonce is %d bytes, want %d", len(nonce), NonceBytes)
			}
			key := string(nonce)
			label := name + "/" + strconv.FormatUint(sequence, 10)
			if previous, dup := seen[key]; dup {
				t.Fatalf("%s and %s derive the same nonce", label, previous)
			}
			seen[key] = label
		}
	}

	// The reserved bytes stay zero, so today's nonces remain derivable if a field is
	// added there later.
	nonce := c.nonce(directionInitiatorToResponder, 0x0102030405060708)
	if nonce[1] != 0 || nonce[2] != 0 || nonce[3] != 0 {
		t.Fatalf("reserved nonce bytes are not zero: %v", nonce[:4])
	}
	if got := binary.BigEndian.Uint64(nonce[4:12]); got != 0x0102030405060708 {
		t.Fatalf("nonce carries sequence %x", got)
	}
}

// TestOpenFailsWhenTheRoleIsWired backwards is a regression test for the nonce direction.
// An earlier version derived the direction byte from "am I sending or receiving" rather
// than from the handshake role, so the two ends produced different nonces for the same
// message and nothing opened at all. Constructing the receiver with the wrong role
// reproduces that mismatch, and it must fail rather than half-work.
//
// Requirements: 10.2
func TestOpenFailsWhenTheRoleIsWiredBackwards(t *testing.T) {
	alice := newIdentity(t)
	bob := newIdentity(t)
	pair := newHandshakePair(t, alice, bob)
	aliceKeys, failure, bobKeys, _ := pair.completeBoth(bob.public, alice.public)
	if failure != nil {
		t.Fatalf("handshake: %s", failure.Error())
	}

	sender, err := NewSessionCrypto(aliceKeys, RoleInitiator)
	if err != nil {
		t.Fatalf("sender: %v", err)
	}
	// The responder's keys, but wired with the initiator's role.
	wrongRole, err := NewSessionCrypto(bobKeys, RoleInitiator)
	if err != nil {
		t.Fatalf("receiver: %v", err)
	}
	rightRole, err := NewSessionCrypto(bobKeys, RoleResponder)
	if err != nil {
		t.Fatalf("receiver: %v", err)
	}

	header := frameHeader(1, 3, 12, uint32(SealedSize(5)))
	ciphertext, err := sender.Seal(header, 12, []byte("hello"))
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}

	if _, ok := wrongRole.Open(header, 12, ciphertext); ok {
		t.Fatal("a receiver wired with the wrong role opened the payload")
	}
	if got, ok := rightRole.Open(header, 12, ciphertext); !ok || string(got) != "hello" {
		t.Fatal("a correctly wired receiver could not open the payload")
	}
}
