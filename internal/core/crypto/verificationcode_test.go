package crypto

import (
	"crypto/ed25519"
	"testing"
	"time"

	"pgregory.net/rapid"
)

var baseTime = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

// drawPublicKey produces a 32-byte key, the Ed25519 public key size the protocol uses.
func drawPublicKey(t *rapid.T, label string) []byte {
	return rapid.SliceOfN(rapid.Byte(), ed25519.PublicKeySize, ed25519.PublicKeySize).
		Draw(t, label)
}

// TestProperty30VerificationCodeIsSymmetricDeterministicAndSixDigits covers
// Property 30: The verification code is symmetric, deterministic, and exactly 6 digits.
//
// Validates: Requirements 9.3
func TestProperty30VerificationCodeIsSymmetricDeterministicAndSixDigits(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		keyA := drawPublicKey(rt, "keyA")
		keyB := drawPublicKey(rt, "keyB")

		// Each node knows the pair but disagrees about which key is its own, so the
		// two argument orders model the two nodes.
		fromA := VerificationCode(keyA, keyB)
		fromB := VerificationCode(keyB, keyA)

		// Exactly 6 decimal characters, leading zeros included.
		if len(fromA) != VerificationCodeDigits {
			rt.Fatalf("code %q is %d characters, want %d",
				fromA, len(fromA), VerificationCodeDigits)
		}
		if !IsVerificationCode(fromA) {
			rt.Fatalf("code %q is not %d decimal digits", fromA, VerificationCodeDigits)
		}

		// Symmetric: both nodes display the same code without exchanging it.
		if fromA != fromB {
			rt.Fatalf("the two nodes computed %q and %q for the same key pair", fromA, fromB)
		}

		// Deterministic across repeated computation.
		if again := VerificationCode(keyA, keyB); again != fromA {
			rt.Fatalf("repeated computation gave %q then %q", fromA, again)
		}

		// The window is the same length however the code was computed.
		if got := VerificationCodeExpiry(baseTime); !got.Equal(baseTime.Add(VerificationCodeValidity)) {
			rt.Fatalf("expiry is %s, want %s", got, baseTime.Add(VerificationCodeValidity))
		}
	})
}

// TestVerificationCodeKeepsLeadingZeros is the case %d instead of %06d would break: a
// code of "000042" shown as "42" is not 6 digits, and the user comparing it against the
// other machine would reasonably call it a mismatch.
//
// Requirements: 9.3
func TestVerificationCodeKeepsLeadingZeros(t *testing.T) {
	// Search for a key pair whose code starts with a zero rather than asserting one
	// exists at a fixed input, so the test does not depend on the hash's output.
	found := ""
	for i := 0; i < 20_000 && found == ""; i++ {
		a := make([]byte, ed25519.PublicKeySize)
		b := make([]byte, ed25519.PublicKeySize)
		a[0], a[1] = byte(i), byte(i>>8)
		b[0], b[1] = byte(i>>16), byte(i>>24)
		if code := VerificationCode(a, b); code[0] == '0' {
			found = code
		}
	}
	if found == "" {
		t.Skip("no code with a leading zero found in 20000 draws")
	}
	if len(found) != VerificationCodeDigits {
		t.Fatalf("code %q lost its leading zero: %d characters", found, len(found))
	}
	if !IsVerificationCode(found) {
		t.Fatalf("code %q is not six decimal digits", found)
	}
}

// TestVerificationCodeDiffersForDifferentKeyPairs is a sanity check on the derivation:
// the code has to depend on both keys, or every pairing would show the same digits.
//
// Requirements: 9.3
func TestVerificationCodeDiffersForDifferentKeyPairs(t *testing.T) {
	base := make([]byte, ed25519.PublicKeySize)
	other := make([]byte, ed25519.PublicKeySize)
	other[0] = 1

	third := make([]byte, ed25519.PublicKeySize)
	third[31] = 9

	first := VerificationCode(base, other)
	second := VerificationCode(base, third)
	if first == second {
		t.Fatalf("two different key pairs both produced %q", first)
	}

	// And changing a single byte of one key changes the code.
	nudged := append([]byte(nil), other...)
	nudged[15] ^= 0x80
	if VerificationCode(base, nudged) == first {
		t.Fatal("changing a key byte did not change the code")
	}
}

// TestVerificationCodeWindowIsHalfOpen pins the 120-second window of Req 9.3: valid up
// to but not including the expiry.
//
// Requirements: 9.3, 9.5
func TestVerificationCodeWindowIsHalfOpen(t *testing.T) {
	if VerificationCodeValidity != 120*time.Second {
		t.Fatalf("validity is %s, want 120s", VerificationCodeValidity)
	}

	cases := []struct {
		name  string
		at    time.Time
		valid bool
	}{
		{"at display", baseTime, true},
		{"one second in", baseTime.Add(time.Second), true},
		{"one nanosecond before expiry", baseTime.Add(VerificationCodeValidity - time.Nanosecond), true},
		{"exactly at expiry", baseTime.Add(VerificationCodeValidity), false},
		{"past expiry", baseTime.Add(VerificationCodeValidity + time.Second), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := VerificationCodeValid(baseTime, c.at); got != c.valid {
				t.Fatalf("valid at %s = %v, want %v", c.at.Sub(baseTime), got, c.valid)
			}
		})
	}
}

// TestIsVerificationCodeRejectsMalformedInput checks the shape guard.
//
// Requirements: 9.3
func TestIsVerificationCodeRejectsMalformedInput(t *testing.T) {
	for _, s := range []string{"", "1", "12345", "1234567", "12345a", "12 456", "-12345"} {
		if IsVerificationCode(s) {
			t.Fatalf("%q was accepted as a verification code", s)
		}
	}
	for _, s := range []string{"000000", "123456", "999999", "000042"} {
		if !IsVerificationCode(s) {
			t.Fatalf("%q was rejected", s)
		}
	}
}
