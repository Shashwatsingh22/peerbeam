package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

// VerificationCodeValidity is how long a displayed code may be confirmed for
// (Req 9.3, 9.5).
const VerificationCodeValidity = 120 * time.Second

// VerificationCodeDigits is the code length Req 9.3 fixes: exactly 6 decimal digits.
const VerificationCodeDigits = 6

// verificationCodeDomain separates this hash from every other use of SHA-256 in the
// protocol. Without a domain string, a digest computed over the same two keys somewhere
// else would produce the same bytes, and two unrelated values that must never be
// confused would be equal.
const verificationCodeDomain = "peerbeam-pairing-v1"

// VerificationCode derives the 6-digit code the user compares across two machines
// (Req 9.3).
//
// The two keys are sorted before hashing, and that is the whole trick. Each node knows
// the pair {mine, theirs} but disagrees with the other about which is which, so hashing
// them in local order would give two different codes and the user would always see a
// mismatch. Sorting by bytes.Compare gives both nodes the same input, so both display
// the same code without exchanging it - which matters, because a code sent over the
// wire would be worthless against an attacker who controls the wire.
//
// The output is formatted with %06d so a small value keeps its leading zeros. A code of
// "000042" displayed as "42" would not be 6 digits, and the user comparing it against
// the other machine's "000042" would reasonably call it a mismatch.
func VerificationCode(keyA, keyB []byte) string {
	first, second := keyA, keyB
	if bytes.Compare(keyA, keyB) > 0 {
		first, second = keyB, keyA
	}

	h := sha256.New()
	h.Write([]byte(verificationCodeDomain))
	h.Write(first)
	h.Write(second)
	digest := h.Sum(nil)

	// The truncation to 4 bytes and the modulo both cost entropy: 6 digits is a
	// millionth of the space, so a code collision is one in a million. That is
	// Req 9.3's choice, not this function's, and it is sound because the code only has
	// to be compared by a human inside a 120-second window, not resist offline search.
	n := binary.BigEndian.Uint32(digest[0:4])
	return fmt.Sprintf("%0*d", VerificationCodeDigits, n%1_000_000)
}

// IsVerificationCode reports whether s is exactly 6 decimal digits.
func IsVerificationCode(s string) bool {
	if len(s) != VerificationCodeDigits {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// VerificationCodeExpiry is when a code displayed at displayedAt stops being
// confirmable (Req 9.3).
func VerificationCodeExpiry(displayedAt time.Time) time.Time {
	return displayedAt.Add(VerificationCodeValidity)
}

// VerificationCodeValid reports whether a code displayed at displayedAt may still be
// confirmed at now (Req 9.3, 9.5). The window is half-open: a confirmation at exactly
// 120 seconds is too late, so the code is valid "for 120 seconds from display" and not
// a moment more.
func VerificationCodeValid(displayedAt, now time.Time) bool {
	return now.Before(VerificationCodeExpiry(displayedAt))
}
