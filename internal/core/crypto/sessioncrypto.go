package crypto

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD parameters for ChaCha20-Poly1305.
const (
	// NonceBytes is the 12-byte nonce size.
	NonceBytes = chacha20poly1305.NonceSize
	// TagBytes is the 16-byte authentication tag appended to every ciphertext. It is
	// the only wire overhead encryption adds, because the nonce is derived rather than
	// transmitted.
	TagBytes = 16
)

// Direction bytes distinguish the two nonce spaces. They go in the nonce so that even if
// a caller ever used one key in both directions, the nonces would still differ.
//
// Crucially they name the *direction of travel*, not the local perspective. An earlier
// version used "outbound" and "inbound" relative to whoever was calling, which meant the
// sender derived a nonce with the outbound byte and the receiver derived one with the
// inbound byte for the very same message, so nothing ever opened. Both nodes have to agree
// on the nonce for a given message, and the only way to do that is to key it on something
// both see the same way: which end originated the traffic.
const (
	directionInitiatorToResponder byte = 0x01
	directionResponderToInitiator byte = 0x02
)

// SessionCrypto seals and opens Message payloads for one Session (Req 10.2).
//
// It is the only place in the codebase that encrypts, which is deliberate: Req 10.2 covers
// every Message type including acknowledgements, errors, and keepalives, and a second
// encryption path would be a second chance to forget one of them.
//
// Not safe for concurrent use. One Session, one owning goroutine.
type SessionCrypto struct {
	sendKey    []byte
	receiveKey []byte
	// sendDirection and receiveDirection are fixed at construction from the handshake
	// role, so the two nodes derive the same nonce for the same message.
	sendDirection    byte
	receiveDirection byte
}

// NewSessionCrypto returns crypto over the keys a completed handshake derived.
//
// role is required, not optional. It selects the direction byte for each nonce, and both
// nodes must reach the same byte for the same message; deriving it from "am I sending or
// receiving" instead would give the two ends different nonces and nothing would open.
func NewSessionCrypto(keys SessionKeys, role Role) (*SessionCrypto, error) {
	if len(keys.SendKey) != SessionKeyBytes || len(keys.ReceiveKey) != SessionKeyBytes {
		return nil, fmt.Errorf("session keys are %d/%d bytes, want %d each",
			len(keys.SendKey), len(keys.ReceiveKey), SessionKeyBytes)
	}

	send, receive := directionInitiatorToResponder, directionResponderToInitiator
	if role == RoleResponder {
		send, receive = directionResponderToInitiator, directionInitiatorToResponder
	}

	// Copy, so a caller zeroing its own slices cannot silently break a live Session.
	return &SessionCrypto{
		sendKey:          append([]byte(nil), keys.SendKey...),
		receiveKey:       append([]byte(nil), keys.ReceiveKey...),
		sendDirection:    send,
		receiveDirection: receive,
	}, nil
}

// nonce derives the 12-byte nonce from the direction and the sequence number.
//
// Deriving rather than transmitting is what keeps the wire overhead at the 16-byte tag,
// which is what lets a full 1 MiB clipboard fit in two frames rather than three. It is
// safe because of three facts together: the key is per Session and per direction, the
// sequence number is monotonic within a Session, and a rebind carries the sequence state
// forward rather than restarting it (Req 3.4). So a (key, nonce) pair is used exactly
// once, which is the one thing ChaCha20-Poly1305 requires absolutely.
//
// Bytes 1 to 3 stay zero. They are room for a future field; leaving them fixed now means
// today's nonces stay derivable if one is added later.
func (c *SessionCrypto) nonce(direction byte, sequence uint64) []byte {
	n := make([]byte, NonceBytes)
	n[0] = direction
	binary.BigEndian.PutUint64(n[4:12], sequence)
	return n
}

// Seal encrypts plaintext for the wire, returning ciphertext with the tag appended.
//
// The frame header is the additional authenticated data, so it is authenticated without
// being encrypted. That is what it has to be: a receiver needs to read the version, type,
// sequence, and length to know how much to buffer, so those cannot be secret. Covering
// them with the tag means a tampered header fails the tag check rather than silently
// redirecting a payload to the wrong handler or the wrong sequence number.
//
// The sequence number is passed separately as well as being inside the header, because the
// nonce derivation must not depend on parsing the header back out. If the two ever
// disagreed, the tag check would fail, which is the safe direction for that mistake.
func (c *SessionCrypto) Seal(header []byte, sequence uint64, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(c.sendKey)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return aead.Seal(nil, c.nonce(c.sendDirection, sequence), plaintext, header), nil
}

// Open decrypts and authenticates a received payload. It returns (nil, false) on any tag
// failure, which the caller turns into: discard the Message without delivering its payload
// or applying it to Session state, on the first failure with no retry (Req 10.3), then
// close the Session and report an authentication failure (Req 10.7).
//
// There is deliberately no error value distinguishing the failure modes. A caller given a
// reason would be tempted to branch on it, and every branch other than "discard and close"
// is wrong: a tag failure means the bytes are not from the Peer, and nothing further can be
// concluded from them. A bool is the whole of what a caller may act on.
func (c *SessionCrypto) Open(header []byte, sequence uint64, ciphertext []byte) ([]byte, bool) {
	aead, err := chacha20poly1305.New(c.receiveKey)
	if err != nil {
		return nil, false
	}
	if len(ciphertext) < TagBytes {
		// Too short to carry a tag, so it cannot authenticate. Reported as a tag
		// failure rather than a separate error for the reason above.
		return nil, false
	}
	plaintext, err := aead.Open(nil, c.nonce(c.receiveDirection, sequence), ciphertext, header)
	if err != nil {
		return nil, false
	}
	return plaintext, true
}

// SealedSize is how many bytes sealing a plaintext of n bytes produces. It is used to
// check a payload against the frame limit before sealing, so an oversized payload is
// rejected rather than encrypted and then discarded.
func SealedSize(plaintextBytes int) int { return plaintextBytes + TagBytes }

// MaxPlaintextFor is the largest plaintext that fits a frame payload of maxPayloadBytes
// once the tag is added.
func MaxPlaintextFor(maxPayloadBytes int) int {
	if maxPayloadBytes <= TagBytes {
		return 0
	}
	return maxPayloadBytes - TagBytes
}

// Zero overwrites the key material held by this SessionCrypto, called when the Session
// closes.
func (c *SessionCrypto) Zero() {
	for i := range c.sendKey {
		c.sendKey[i] = 0
	}
	for i := range c.receiveKey {
		c.receiveKey[i] = 0
	}
}

// AuthenticationFailure is the Req 10.7 report: a Message whose tag did not verify. It
// names the Session and the Peer, and deliberately carries nothing about the payload.
type AuthenticationFailure struct {
	SessionId       string
	PeerFingerprint string
	// Sequence is the sequence number from the frame header. It is safe to report
	// because Req 10.6 allows type, sequence, and length; it is not the payload.
	Sequence uint64
	// SessionClosed records that the Session was torn down, which Req 10.7 requires.
	SessionClosed bool
}

func (f *AuthenticationFailure) Error() string {
	return fmt.Sprintf("session %s with peer %s: message %d failed its authentication tag check; session closed",
		f.SessionId, f.PeerFingerprint, f.Sequence)
}

// NewAuthenticationFailure builds the Req 10.7 report. SessionClosed is set here rather
// than by the caller, so a report cannot claim a tag failure without also recording that
// the Session was closed.
func NewAuthenticationFailure(sessionId, peerFingerprint string, sequence uint64) *AuthenticationFailure {
	return &AuthenticationFailure{
		SessionId:       sessionId,
		PeerFingerprint: peerFingerprint,
		Sequence:        sequence,
		SessionClosed:   true,
	}
}
