package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// Fingerprint is the lowercase hex SHA-256 of a public key.
//
// It lives here rather than only in internal/core/trust because the handshake has to
// check that a Peer's claimed fingerprint belongs to the key it presented, and trust
// already imports this package, so the reverse would be an import cycle. trust.Fingerprint
// delegates here, so there is one definition and the two can never disagree about
// casing or hash choice.
func Fingerprint(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

// fingerprintOf is the internal spelling used by the handshake.
func fingerprintOf(publicKey []byte) string { return Fingerprint(publicKey) }

// constantTimeEqual compares two byte slices without leaking their contents through
// timing.
//
// It matters here specifically. The handshake compares a presented long-term key against
// the stored one (Req 9.7), and that comparison is against attacker-supplied input: a
// byte-at-a-time comparison that returns early would let an attacker learn the stored key
// one byte at a time by timing how long the rejection takes. The digest comparisons
// elsewhere in the codebase are over values the caller already holds, which is why those
// use a plain comparison and this one does not.
func constantTimeEqual(a, b []byte) bool {
	// The length check is not itself constant time, but a key's length is not a secret:
	// it is fixed by the algorithm and visible on the wire.
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
