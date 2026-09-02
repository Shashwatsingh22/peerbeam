package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Handshake sizes and timings.
const (
	// EphemeralKeyBytes is the size of an X25519 public or private key.
	EphemeralKeyBytes = 32
	// SessionKeyBytes is the size of one directional ChaCha20-Poly1305 key.
	SessionKeyBytes = 32
	// HandshakeDeadline is how long a key exchange may take from the Transport
	// connection opening (Req 10.8).
	HandshakeDeadline = 5 * time.Second
)

// Domain separators. Every hash and signature in the protocol is prefixed with one, so
// a value produced for one purpose can never be mistaken for a value produced for
// another. The version suffix means a future change to a transcript layout is a new
// string rather than a silent incompatibility.
const (
	handshakeTranscriptDomain = "peerbeam-kx-v1"
	sessionKeyDomain          = "peerbeam-session-v1"
	sendKeyLabel              = "initiator-to-responder"
	receiveKeyLabel           = "responder-to-initiator"
)

// Role says which end of the handshake a node is. It decides which derived key is used
// for sending and which for receiving: both nodes derive the same two keys, and the role
// is what stops them both encrypting with the same one.
type Role uint8

const (
	RoleInitiator Role = iota
	RoleResponder
)

func (r Role) String() string {
	if r == RoleInitiator {
		return "initiator"
	}
	return "responder"
}

// EphemeralKeyPair is a one-Session X25519 key pair. It exists for the length of one
// handshake and is never stored, which is what gives a Session forward secrecy against
// a later compromise of the long-term key.
type EphemeralKeyPair struct {
	PublicKey  []byte
	privateKey []byte
}

// GenerateEphemeralKeyPair draws a fresh X25519 key pair from crypto/rand.
func GenerateEphemeralKeyPair() (EphemeralKeyPair, error) {
	return generateEphemeralKeyPairFrom(rand.Reader)
}

func generateEphemeralKeyPairFrom(entropy io.Reader) (EphemeralKeyPair, error) {
	private := make([]byte, EphemeralKeyBytes)
	if _, err := io.ReadFull(entropy, private); err != nil {
		return EphemeralKeyPair{}, fmt.Errorf("draw ephemeral key: %w", err)
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return EphemeralKeyPair{}, fmt.Errorf("derive ephemeral public key: %w", err)
	}
	return EphemeralKeyPair{PublicKey: public, privateKey: private}, nil
}

// HandshakeMessage is what each side puts on the wire: who it claims to be, its
// ephemeral public key, and a signature tying the two together within this exchange.
//
// The long-term public key travels alongside the fingerprint even though the fingerprint
// is its hash, because the receiver needs the key itself to verify the signature and
// must compare it byte for byte against the stored one (Req 9.7). Sending only the
// fingerprint would force the receiver to trust its own stored key to verify a signature
// that is supposed to prove the sender holds it.
type HandshakeMessage struct {
	Fingerprint string
	PublicKey   []byte // Ed25519 long-term public key
	Ephemeral   []byte // X25519 ephemeral public key
	Signature   []byte // Ed25519 over the transcript
}

// SessionKeys are the two directional keys for one Session (Req 10.5).
//
// Two keys rather than one is what makes the derived nonce safe. With a single key, both
// nodes would encrypt from sequence 0 upward under the same key, and the first message
// each sent would reuse a nonce, which for ChaCha20-Poly1305 means losing both
// confidentiality and authenticity. Separate keys per direction mean each key sees each
// sequence number exactly once.
type SessionKeys struct {
	SendKey    []byte
	ReceiveKey []byte
}

// Zero overwrites the key material in place. It is called when a Session closes, so keys
// do not sit in memory for the life of the process. It is not a guarantee - Go may have
// copied the slice - but it shortens the window without pretending to close it.
func (k *SessionKeys) Zero() {
	for i := range k.SendKey {
		k.SendKey[i] = 0
	}
	for i := range k.ReceiveKey {
		k.ReceiveKey[i] = 0
	}
}

// HandshakeTranscript is the exact byte string both sides sign. It is a named function
// because the two sides must produce byte-identical input from data they hold in
// opposite roles, and any disagreement shows up as an unverifiable signature rather
// than as a useful error.
//
// The initiator's values always come first, regardless of which side is computing it.
// That fixed order is what makes the transcript agree across the two nodes.
func HandshakeTranscript(
	initiatorEphemeral, responderEphemeral []byte,
	initiatorFingerprint, responderFingerprint string,
) []byte {
	out := make([]byte, 0,
		len(handshakeTranscriptDomain)+
			len(initiatorEphemeral)+len(responderEphemeral)+
			len(initiatorFingerprint)+len(responderFingerprint))

	out = append(out, handshakeTranscriptDomain...)
	out = append(out, initiatorEphemeral...)
	out = append(out, responderEphemeral...)
	out = append(out, initiatorFingerprint...)
	out = append(out, responderFingerprint...)
	return out
}

// SignHandshake signs the transcript with this node's long-term private key. The
// signature is what binds the ephemeral key to the long-term identity: without it, an
// attacker could substitute its own ephemeral key and complete an exchange as anyone.
func SignHandshake(privateKey ed25519.PrivateKey, transcript []byte) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key is %d bytes, want %d",
			len(privateKey), ed25519.PrivateKeySize)
	}
	return ed25519.Sign(privateKey, transcript), nil
}

// HandshakeFailure reports why an exchange did not complete. Step names the check that
// failed, so the report can say what went wrong without leaking anything about the keys.
type HandshakeFailure struct {
	Step            string
	PeerFingerprint string
	Reason          string
	// AttemptedTransport is named by Req 10.8's report; it is set by the caller, which
	// is the only party that knows which Transport was in use.
	AttemptedTransport string
	// Elapsed is how long the attempt took, which Property 36 requires the deadline
	// report to carry.
	Elapsed time.Duration
}

func (f *HandshakeFailure) Error() string {
	base := fmt.Sprintf("key exchange failed at %s with peer %s: %s",
		f.Step, f.PeerFingerprint, f.Reason)
	if f.AttemptedTransport != "" {
		base += " (transport " + f.AttemptedTransport + ")"
	}
	if f.Elapsed > 0 {
		base += fmt.Sprintf(" after %s", f.Elapsed)
	}
	return base
}

// CompleteHandshake verifies the Peer's handshake message and derives the Session keys.
//
// The checks run in this order, and every one of them must pass:
//
//  1. Shapes: key and ephemeral lengths. A malformed input is rejected before it reaches
//     any cryptographic operation.
//  2. The presented long-term key matches the one stored for that Trusted_Peer, byte for
//     byte (Req 9.7, 10.1). This is the check that binds the Session to the identity the
//     user paired with; without it the signature would only prove that *somebody* signed.
//  3. The fingerprint the Peer claims matches the key it presented, so a Peer cannot
//     claim one identity while signing with another key.
//  4. The signature over the transcript verifies (Req 10.1).
//  5. ECDH, then HKDF to two directional keys.
//
// storedPeerKey is the key from the trust store. Passing it in rather than looking it up
// keeps this package free of a dependency on internal/core/trust, and makes the binding
// explicit at the call site.
func CompleteHandshake(
	role Role,
	localIdentity ed25519.PublicKey,
	localFingerprint string,
	local EphemeralKeyPair,
	peer HandshakeMessage,
	storedPeerKey []byte,
) (SessionKeys, *HandshakeFailure) {
	fail := func(step, reason string) (SessionKeys, *HandshakeFailure) {
		return SessionKeys{}, &HandshakeFailure{
			Step:            step,
			PeerFingerprint: peer.Fingerprint,
			Reason:          reason,
		}
	}

	// 1. Shapes.
	if len(local.privateKey) != EphemeralKeyBytes || len(local.PublicKey) != EphemeralKeyBytes {
		return fail("local ephemeral key", "local ephemeral key pair is malformed")
	}
	if len(peer.Ephemeral) != EphemeralKeyBytes {
		return fail("peer ephemeral key",
			fmt.Sprintf("ephemeral key is %d bytes, want %d", len(peer.Ephemeral), EphemeralKeyBytes))
	}
	if len(peer.PublicKey) != ed25519.PublicKeySize {
		return fail("peer long-term key",
			fmt.Sprintf("public key is %d bytes, want %d", len(peer.PublicKey), ed25519.PublicKeySize))
	}
	if len(localIdentity) != ed25519.PublicKeySize {
		return fail("local long-term key", "local identity public key is malformed")
	}

	// 2. Req 9.7 and 10.1: the presented key is the stored key, byte for byte.
	if len(storedPeerKey) == 0 {
		return fail("trust check", "no stored public key for this peer")
	}
	if !constantTimeEqual(storedPeerKey, peer.PublicKey) {
		return fail("trust check", "presented public key differs from the stored key")
	}

	// 3. The claimed fingerprint belongs to the presented key.
	if want := fingerprintOf(peer.PublicKey); peer.Fingerprint != want {
		return fail("fingerprint check", "fingerprint does not match the presented public key")
	}

	// 4. Req 10.1: the signature over the transcript.
	initiatorEphemeral, responderEphemeral := local.PublicKey, peer.Ephemeral
	initiatorFingerprint, responderFingerprint := localFingerprint, peer.Fingerprint
	if role == RoleResponder {
		initiatorEphemeral, responderEphemeral = peer.Ephemeral, local.PublicKey
		initiatorFingerprint, responderFingerprint = peer.Fingerprint, localFingerprint
	}
	transcript := HandshakeTranscript(
		initiatorEphemeral, responderEphemeral,
		initiatorFingerprint, responderFingerprint)

	if !ed25519.Verify(ed25519.PublicKey(peer.PublicKey), transcript, peer.Signature) {
		return fail("signature check", "signature over the handshake transcript did not verify")
	}

	// 5. ECDH, then HKDF.
	shared, err := curve25519.X25519(local.privateKey, peer.Ephemeral)
	if err != nil {
		return fail("key agreement", err.Error())
	}
	// X25519 with a low-order point yields an all-zero shared secret. curve25519.X25519
	// already returns an error for those, so reaching here with zeros would mean the
	// library changed; checking costs nothing and the alternative is a session both
	// sides think is secure.
	if isAllZero(shared) {
		return fail("key agreement", "shared secret is all zero")
	}

	keys, err := deriveSessionKeys(role, shared, initiatorEphemeral, responderEphemeral)
	if err != nil {
		return fail("key derivation", err.Error())
	}
	return keys, nil
}

// deriveSessionKeys turns the shared secret into two directional keys.
//
// The salt is both ephemeral public keys in initiator-then-responder order, so it is the
// same on both nodes and different for every Session. That is what makes Req 10.5 hold:
// two Sessions between the same identities share a long-term key but not an ephemeral
// pair, so they cannot derive the same Session keys.
//
// The two keys come from one expand call with different labels in the info string. The
// role then decides which is the send key locally, so the initiator's send key is the
// responder's receive key.
func deriveSessionKeys(role Role, shared, initiatorEphemeral, responderEphemeral []byte) (SessionKeys, error) {
	salt := make([]byte, 0, len(initiatorEphemeral)+len(responderEphemeral))
	salt = append(salt, initiatorEphemeral...)
	salt = append(salt, responderEphemeral...)

	initiatorToResponder, err := HKDF(shared, salt,
		[]byte(sessionKeyDomain+"|"+sendKeyLabel), SessionKeyBytes)
	if err != nil {
		return SessionKeys{}, err
	}
	responderToInitiator, err := HKDF(shared, salt,
		[]byte(sessionKeyDomain+"|"+receiveKeyLabel), SessionKeyBytes)
	if err != nil {
		return SessionKeys{}, err
	}

	if role == RoleInitiator {
		return SessionKeys{SendKey: initiatorToResponder, ReceiveKey: responderToInitiator}, nil
	}
	return SessionKeys{SendKey: responderToInitiator, ReceiveKey: initiatorToResponder}, nil
}

// HandshakeGate decides what a connection may process before its key exchange completes
// (Req 10.9), and enforces the 5-second deadline (Req 10.8).
//
// It is a type rather than two loose functions because both rules are about the same
// state - "has this connection finished its handshake" - and a caller that tracked that
// with a bare bool would eventually check one rule and forget the other.
type HandshakeGate struct {
	openedAt  time.Time
	deadline  time.Duration
	completed bool
}

// NewHandshakeGate returns a gate for a connection opened at openedAt.
func NewHandshakeGate(openedAt time.Time) *HandshakeGate {
	return &HandshakeGate{openedAt: openedAt, deadline: HandshakeDeadline}
}

// Complete marks the exchange finished, after which every Message type is allowed.
func (g *HandshakeGate) Complete() { g.completed = true }

// Completed reports whether the exchange has finished.
func (g *HandshakeGate) Completed() bool { return g.completed }

// GateDecision is what to do with a received frame before the handshake completes.
type GateDecision struct {
	// Process is set when the frame may be handled.
	Process bool
	// Violation is Req 10.9: a non-key-exchange type arrived too early. The frame is
	// discarded without its payload being parsed, and the connection closes.
	Violation *ProtocolViolation
	// Expired is Req 10.8: the deadline passed. Establishment is abandoned and no
	// Session is left behind.
	Expired *HandshakeFailure
}

// ProtocolViolation reports a frame that arrived before it was allowed (Req 10.9).
type ProtocolViolation struct {
	PeerFingerprint string
	MessageType     uint8
	Reason          string
}

func (v *ProtocolViolation) Error() string {
	return fmt.Sprintf("protocol violation from peer %s: %s (message type %d)",
		v.PeerFingerprint, v.Reason, v.MessageType)
}

// Admit decides what to do with a frame of messageType received at now.
//
// isKeyExchange is passed in rather than compared against a constant here, because the
// message type codes live in internal/core/codec and this package must not depend on it.
// The caller answers the one question this rule needs.
//
// The deadline is checked before the type. A frame arriving after the deadline is not a
// protocol violation even if its type is wrong: the establishment has already failed, and
// reporting a violation would send the operator looking for a misbehaving peer instead of
// a slow link.
func (g *HandshakeGate) Admit(
	messageType uint8,
	isKeyExchange bool,
	peerFingerprint string,
	now time.Time,
) GateDecision {
	if g.completed {
		return GateDecision{Process: true}
	}

	if elapsed := now.Sub(g.openedAt); elapsed >= g.deadline {
		return GateDecision{Expired: &HandshakeFailure{
			Step:            "handshake deadline",
			PeerFingerprint: peerFingerprint,
			Reason: fmt.Sprintf("key exchange did not complete within %s",
				g.deadline),
			Elapsed: elapsed,
		}}
	}

	if !isKeyExchange {
		return GateDecision{Violation: &ProtocolViolation{
			PeerFingerprint: peerFingerprint,
			MessageType:     messageType,
			Reason:          "non-key-exchange message received before the key exchange completed",
		}}
	}
	return GateDecision{Process: true}
}

// Expired reports whether the deadline has passed without the exchange completing
// (Req 10.8). It is separate from Admit so the establishment timer can fail an attempt
// that received nothing at all.
func (g *HandshakeGate) Expired(now time.Time) (*HandshakeFailure, bool) {
	if g.completed {
		return nil, false
	}
	elapsed := now.Sub(g.openedAt)
	if elapsed < g.deadline {
		return nil, false
	}
	return &HandshakeFailure{
		Step:    "handshake deadline",
		Reason:  fmt.Sprintf("key exchange did not complete within %s", g.deadline),
		Elapsed: elapsed,
	}, true
}

// Deadline is when the exchange must have completed by.
func (g *HandshakeGate) Deadline() time.Time { return g.openedAt.Add(g.deadline) }

// ErrNoSharedSecret is returned when key agreement produces nothing usable.
var ErrNoSharedSecret = errors.New("crypto: key agreement produced no shared secret")

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
