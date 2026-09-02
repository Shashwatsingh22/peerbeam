package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// FingerprintHexChars is the length of a fingerprint in lowercase hex: SHA-256 is 32
// bytes, so 64 characters.
const FingerprintHexChars = 64

// PublicKeyBytes is the size of an Ed25519 public key.
const PublicKeyBytes = ed25519.PublicKeySize

// Fingerprint is the lowercase hex SHA-256 of an Ed25519 public key. It is what the
// discovery announcement carries (Req 1.1), what the trust store keys on (Req 9.4),
// and what every trust report names (Req 9.5, 9.6, 9.7).
//
// One canonical spelling matters more than it looks. The fingerprint is compared as a
// string in the trust store and the peer registry, so an uppercase and a lowercase
// spelling of the same key would produce two entries for one peer, and Req 9.4's "one
// entry per public key fingerprint" would quietly stop holding.
func Fingerprint(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

// IsFingerprint reports whether s is a well-formed fingerprint: exactly 64 lowercase
// hex characters. Uppercase is rejected rather than normalised, so a caller that built
// a fingerprint the wrong way finds out here rather than by ending up with a duplicate
// trust store entry.
func IsFingerprint(s string) bool {
	if len(s) != FingerprintHexChars {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// CheckPublicKey validates a public key's shape before it is fingerprinted or stored.
// An Ed25519 public key is a fixed 32 bytes, so anything else is malformed and would
// otherwise be stored as a trusted key that no signature could ever verify against.
func CheckPublicKey(publicKey []byte) error {
	if len(publicKey) != PublicKeyBytes {
		return fmt.Errorf("public key is %d bytes, want %d", len(publicKey), PublicKeyBytes)
	}
	return nil
}
