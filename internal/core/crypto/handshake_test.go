package crypto

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// identity is one node's long-term key pair plus its fingerprint, which is what a
// handshake needs on each side.
type identity struct {
	public      ed25519.PublicKey
	private     ed25519.PrivateKey
	fingerprint string
}

func newIdentity(t rapid.TB) identity {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating an identity: %v", err)
	}
	return identity{public: public, private: private, fingerprint: Fingerprint(public)}
}

// handshakePair drives one complete exchange between two identities and returns both
// sides' derived keys.
type handshakePair struct {
	initiator, responder identity
	initiatorEphemeral   EphemeralKeyPair
	responderEphemeral   EphemeralKeyPair
	initiatorMessage     HandshakeMessage
	responderMessage     HandshakeMessage
}

func newHandshakePair(t rapid.TB, initiator, responder identity) handshakePair {
	t.Helper()

	initiatorEphemeral, err := GenerateEphemeralKeyPair()
	if err != nil {
		t.Fatalf("initiator ephemeral: %v", err)
	}
	responderEphemeral, err := GenerateEphemeralKeyPair()
	if err != nil {
		t.Fatalf("responder ephemeral: %v", err)
	}

	// Both sides sign the same transcript, built in initiator-then-responder order.
	transcript := HandshakeTranscript(
		initiatorEphemeral.PublicKey, responderEphemeral.PublicKey,
		initiator.fingerprint, responder.fingerprint)

	initiatorSignature, err := SignHandshake(initiator.private, transcript)
	if err != nil {
		t.Fatalf("initiator signature: %v", err)
	}
	responderSignature, err := SignHandshake(responder.private, transcript)
	if err != nil {
		t.Fatalf("responder signature: %v", err)
	}

	return handshakePair{
		initiator:          initiator,
		responder:          responder,
		initiatorEphemeral: initiatorEphemeral,
		responderEphemeral: responderEphemeral,
		initiatorMessage: HandshakeMessage{
			Fingerprint: initiator.fingerprint,
			PublicKey:   initiator.public,
			Ephemeral:   initiatorEphemeral.PublicKey,
			Signature:   initiatorSignature,
		},
		responderMessage: HandshakeMessage{
			Fingerprint: responder.fingerprint,
			PublicKey:   responder.public,
			Ephemeral:   responderEphemeral.PublicKey,
			Signature:   responderSignature,
		},
	}
}

// completeBoth runs the exchange from both ends.
func (p handshakePair) completeBoth(
	storedResponderKey, storedInitiatorKey []byte,
) (SessionKeys, *HandshakeFailure, SessionKeys, *HandshakeFailure) {
	initiatorKeys, initiatorFailure := CompleteHandshake(
		RoleInitiator, p.initiator.public, p.initiator.fingerprint,
		p.initiatorEphemeral, p.responderMessage, storedResponderKey)

	responderKeys, responderFailure := CompleteHandshake(
		RoleResponder, p.responder.public, p.responder.fingerprint,
		p.responderEphemeral, p.initiatorMessage, storedInitiatorKey)

	return initiatorKeys, initiatorFailure, responderKeys, responderFailure
}

// TestProperty34HandshakeBindsSessionKeysToBothLongTermKeys covers
// Property 34: The handshake binds Session keys to both long-term keys and produces fresh
// keys.
//
// Validates: Requirements 10.1, 10.5
func TestProperty34HandshakeBindsSessionKeysToBothLongTermKeys(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		alice := newIdentity(rt)
		bob := newIdentity(rt)
		pair := newHandshakePair(rt, alice, bob)

		// An honest exchange: both sides derive the same two keys, crossed over.
		aliceKeys, aliceFailure, bobKeys, bobFailure :=
			pair.completeBoth(bob.public, alice.public)
		if aliceFailure != nil {
			rt.Fatalf("honest exchange failed on the initiator: %s", aliceFailure.Error())
		}
		if bobFailure != nil {
			rt.Fatalf("honest exchange failed on the responder: %s", bobFailure.Error())
		}

		if !equalBytes(aliceKeys.SendKey, bobKeys.ReceiveKey) {
			rt.Fatal("the initiator's send key is not the responder's receive key")
		}
		if !equalBytes(aliceKeys.ReceiveKey, bobKeys.SendKey) {
			rt.Fatal("the responder's send key is not the initiator's receive key")
		}
		// The two directions must not share a key, or the derived nonce would repeat.
		if equalBytes(aliceKeys.SendKey, aliceKeys.ReceiveKey) {
			rt.Fatal("both directions derived the same key")
		}
		if len(aliceKeys.SendKey) != SessionKeyBytes {
			rt.Fatalf("session key is %d bytes, want %d", len(aliceKeys.SendKey), SessionKeyBytes)
		}

		// Req 10.5: fresh keys per Session. Another exchange between the same two
		// identities shares the long-term keys but not the ephemerals.
		second := newHandshakePair(rt, alice, bob)
		secondKeys, failure, _, _ := second.completeBoth(bob.public, alice.public)
		if failure != nil {
			rt.Fatalf("second exchange failed: %s", failure.Error())
		}
		for _, a := range [][]byte{aliceKeys.SendKey, aliceKeys.ReceiveKey} {
			for _, b := range [][]byte{secondKeys.SendKey, secondKeys.ReceiveKey} {
				if equalBytes(a, b) {
					rt.Fatal("two sessions between the same identities share key material")
				}
			}
		}

		// Substituting either long-term public key makes the exchange fail (Req 10.1).
		impostor := newIdentity(rt)
		switch rapid.SampledFrom([]string{
			"substitute-stored-key", "substitute-presented-key", "corrupt-signature",
			"wrong-fingerprint", "corrupt-ephemeral",
		}).Draw(rt, "attack") {

		case "substitute-stored-key":
			// The trust store holds someone else's key: the presented key no longer
			// matches, so the Session must not form.
			_, failure, _, _ := pair.completeBoth(impostor.public, alice.public)
			assertFailed(rt, failure, "trust check")

		case "substitute-presented-key":
			// The peer presents a different long-term key than the stored one.
			tampered := pair
			tampered.responderMessage.PublicKey = impostor.public
			_, failure, _, _ := tampered.completeBoth(bob.public, alice.public)
			assertFailed(rt, failure, "trust check")

		case "corrupt-signature":
			tampered := pair
			signature := append([]byte(nil), pair.responderMessage.Signature...)
			at := rapid.IntRange(0, len(signature)-1).Draw(rt, "sigByte")
			signature[at] ^= byte(rapid.IntRange(1, 255).Draw(rt, "sigMask"))
			tampered.responderMessage.Signature = signature
			_, failure, _, _ := tampered.completeBoth(bob.public, alice.public)
			assertFailed(rt, failure, "signature check")

		case "wrong-fingerprint":
			// Claiming one identity while presenting another's key.
			tampered := pair
			tampered.responderMessage.Fingerprint = impostor.fingerprint
			_, failure, _, _ := tampered.completeBoth(bob.public, alice.public)
			if failure == nil {
				rt.Fatal("a mismatched fingerprint completed the exchange")
			}

		case "corrupt-ephemeral":
			// Flipping an ephemeral key byte breaks the signature, since the transcript
			// covers it.
			tampered := pair
			ephemeral := append([]byte(nil), pair.responderMessage.Ephemeral...)
			at := rapid.IntRange(0, len(ephemeral)-1).Draw(rt, "ephByte")
			ephemeral[at] ^= byte(rapid.IntRange(1, 255).Draw(rt, "ephMask"))
			tampered.responderMessage.Ephemeral = ephemeral
			_, failure, _, _ := tampered.completeBoth(bob.public, alice.public)
			assertFailed(rt, failure, "signature check")
		}
	})
}

func assertFailed(t rapid.TB, failure *HandshakeFailure, wantStep string) {
	t.Helper()
	if failure == nil {
		t.Fatalf("a tampered exchange succeeded, want failure at %q", wantStep)
	}
	if failure.Step != wantStep {
		t.Fatalf("failed at %q, want %q (%s)", failure.Step, wantStep, failure.Reason)
	}
	if strings.TrimSpace(failure.Reason) == "" {
		t.Fatal("failure carries no reason")
	}
}

// TestHandshakeTranscriptIsIdenticalOnBothSides is the property the whole exchange rests
// on: both nodes build byte-identical signing input from data they hold in opposite roles.
//
// Requirements: 10.1
func TestHandshakeTranscriptIsIdenticalOnBothSides(t *testing.T) {
	alice := newIdentity(t)
	bob := newIdentity(t)
	aliceEph, _ := GenerateEphemeralKeyPair()
	bobEph, _ := GenerateEphemeralKeyPair()

	// Alice is the initiator, so both sides put her values first.
	fromAlice := HandshakeTranscript(aliceEph.PublicKey, bobEph.PublicKey,
		alice.fingerprint, bob.fingerprint)
	fromBob := HandshakeTranscript(aliceEph.PublicKey, bobEph.PublicKey,
		alice.fingerprint, bob.fingerprint)

	if !equalBytes(fromAlice, fromBob) {
		t.Fatal("the two sides built different transcripts")
	}
	// Swapping the roles changes the transcript, which is why the order is fixed.
	swapped := HandshakeTranscript(bobEph.PublicKey, aliceEph.PublicKey,
		bob.fingerprint, alice.fingerprint)
	if equalBytes(fromAlice, swapped) {
		t.Fatal("the transcript is order-independent, so a role confusion would go unnoticed")
	}
	// The domain separator is present, so this digest cannot collide with another use.
	if !strings.HasPrefix(string(fromAlice), handshakeTranscriptDomain) {
		t.Fatal("the transcript is not domain separated")
	}
}

// TestCompleteHandshakeRejectsMalformedInput checks the shape guards, so a malformed
// message is refused before reaching any cryptographic operation.
//
// Requirements: 10.1
func TestCompleteHandshakeRejectsMalformedInput(t *testing.T) {
	alice := newIdentity(t)
	bob := newIdentity(t)
	pair := newHandshakePair(t, alice, bob)

	cases := map[string]struct {
		mangle   func(*HandshakeMessage)
		stored   []byte
		wantStep string
	}{
		"short ephemeral": {
			mangle:   func(m *HandshakeMessage) { m.Ephemeral = m.Ephemeral[:16] },
			stored:   bob.public,
			wantStep: "peer ephemeral key",
		},
		"short long-term key": {
			mangle:   func(m *HandshakeMessage) { m.PublicKey = m.PublicKey[:16] },
			stored:   bob.public,
			wantStep: "peer long-term key",
		},
		"no stored key": {
			mangle:   func(*HandshakeMessage) {},
			stored:   nil,
			wantStep: "trust check",
		},
		"empty signature": {
			mangle:   func(m *HandshakeMessage) { m.Signature = nil },
			stored:   bob.public,
			wantStep: "signature check",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			message := pair.responderMessage
			message.PublicKey = append([]byte(nil), message.PublicKey...)
			message.Ephemeral = append([]byte(nil), message.Ephemeral...)
			message.Signature = append([]byte(nil), message.Signature...)
			c.mangle(&message)

			keys, failure := CompleteHandshake(
				RoleInitiator, alice.public, alice.fingerprint,
				pair.initiatorEphemeral, message, c.stored)

			if failure == nil {
				t.Fatal("malformed input completed the exchange")
			}
			if failure.Step != c.wantStep {
				t.Fatalf("failed at %q, want %q", failure.Step, c.wantStep)
			}
			if len(keys.SendKey) != 0 || len(keys.ReceiveKey) != 0 {
				t.Fatal("a failed exchange returned key material")
			}
		})
	}
}

// TestProperty36NothingIsProcessedBeforeTheHandshakeCompletes covers
// Property 36: Nothing is processed before the handshake completes.
//
// Validates: Requirements 10.8, 10.9, 11.5
func TestProperty36NothingIsProcessedBeforeTheHandshakeCompletes(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		openedAt := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
		gate := NewHandshakeGate(openedAt)
		peer := Fingerprint([]byte("peer-key"))

		messageType := uint8(rapid.IntRange(0, 255).Draw(rt, "messageType"))
		isKeyExchange := rapid.Bool().Draw(rt, "isKeyExchange")
		elapsed := rapid.SampledFrom([]time.Duration{
			0, time.Millisecond, time.Second,
			HandshakeDeadline - time.Nanosecond,
			HandshakeDeadline,
			HandshakeDeadline + time.Second,
		}).Draw(rt, "elapsed")
		now := openedAt.Add(elapsed)

		got := gate.Admit(messageType, isKeyExchange, peer, now)

		// Exactly one branch.
		set := 0
		if got.Process {
			set++
		}
		if got.Violation != nil {
			set++
		}
		if got.Expired != nil {
			set++
		}
		if set != 1 {
			rt.Fatalf("%d branches set in %+v", set, got)
		}

		switch {
		case elapsed >= HandshakeDeadline:
			// Req 10.8: the deadline outranks the type check. The report names the
			// peer and the elapsed time.
			if got.Expired == nil {
				rt.Fatalf("at %s past the deadline got %+v, want expired", elapsed, got)
			}
			if got.Expired.PeerFingerprint != peer {
				rt.Fatalf("expiry names peer %q, want %q", got.Expired.PeerFingerprint, peer)
			}
			if got.Expired.Elapsed != elapsed {
				rt.Fatalf("expiry reports %s elapsed, want %s", got.Expired.Elapsed, elapsed)
			}
			if !strings.Contains(got.Expired.Error(), "5s") {
				rt.Fatalf("expiry %q does not name the deadline", got.Expired.Error())
			}

		case isKeyExchange:
			// Only key exchange types are processed before completion.
			if !got.Process {
				rt.Fatalf("a key exchange message got %+v, want processed", got)
			}

		default:
			// Req 10.9: anything else is a protocol violation naming the peer.
			if got.Violation == nil {
				rt.Fatalf("message type %d got %+v, want a violation", messageType, got)
			}
			if got.Violation.PeerFingerprint != peer {
				rt.Fatalf("violation names peer %q, want %q",
					got.Violation.PeerFingerprint, peer)
			}
			if got.Violation.MessageType != messageType {
				rt.Fatalf("violation names type %d, want %d",
					got.Violation.MessageType, messageType)
			}
			if strings.TrimSpace(got.Violation.Reason) == "" {
				rt.Fatal("violation carries no reason")
			}
		}

		// Once complete, every type is processed regardless of the clock.
		gate.Complete()
		after := gate.Admit(messageType, isKeyExchange, peer, now)
		if !after.Process {
			rt.Fatalf("after completion, type %d got %+v", messageType, after)
		}
		if _, expired := gate.Expired(now.Add(time.Hour)); expired {
			rt.Fatal("a completed handshake expired later")
		}
	})
}

// TestHandshakeGateDeadlineBoundary pins the 5-second bound of Req 10.8.
//
// Requirements: 10.8
func TestHandshakeGateDeadlineBoundary(t *testing.T) {
	if HandshakeDeadline != 5*time.Second {
		t.Fatalf("handshake deadline is %s, want 5s", HandshakeDeadline)
	}

	openedAt := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	gate := NewHandshakeGate(openedAt)

	if _, expired := gate.Expired(openedAt.Add(HandshakeDeadline - time.Nanosecond)); expired {
		t.Fatal("expired one nanosecond early")
	}
	failure, expired := gate.Expired(openedAt.Add(HandshakeDeadline))
	if !expired {
		t.Fatal("did not expire at exactly the deadline")
	}
	if failure.Elapsed != HandshakeDeadline {
		t.Fatalf("reports %s elapsed, want %s", failure.Elapsed, HandshakeDeadline)
	}
	if !gate.Deadline().Equal(openedAt.Add(HandshakeDeadline)) {
		t.Fatalf("deadline is %s, want %s", gate.Deadline(), openedAt.Add(HandshakeDeadline))
	}
}

// TestHKDFMatchesRFC5869 checks the derivation against test case 1 of RFC 5869, so a
// refactor of the extract or expand step is caught against a published vector rather than
// against itself.
//
// Requirements: 10.1, 10.5
func TestHKDFMatchesRFC5869(t *testing.T) {
	// RFC 5869 appendix A.1, SHA-256 with salt and info.
	ikm := repeatByte(0x0b, 22)
	salt := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	info := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9}
	wantHex := "3cb25f25faacd57a90434f64d0362f2a" +
		"2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
		"34007208d5b887185865"

	got, err := HKDF(ikm, salt, info, 42)
	if err != nil {
		t.Fatalf("HKDF: %v", err)
	}
	if hexOf(got) != wantHex {
		t.Fatalf("HKDF output\n got  %s\n want %s", hexOf(got), wantHex)
	}

	// Different info strings from the same secret give independent output, which is what
	// lets one exchange produce two directional keys.
	a, _ := HKDF(ikm, salt, []byte("direction-a"), 32)
	b, _ := HKDF(ikm, salt, []byte("direction-b"), 32)
	if equalBytes(a, b) {
		t.Fatal("two info strings produced the same key")
	}

	// And an over-long request is refused rather than silently truncated.
	if _, err := HKDF(ikm, salt, info, 255*32+1); err == nil {
		t.Fatal("an over-long HKDF request succeeded")
	}
}

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, digits[v>>4], digits[v&0x0f])
	}
	return string(out)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
