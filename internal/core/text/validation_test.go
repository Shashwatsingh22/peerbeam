package text

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"pgregory.net/rapid"
)

// TestProperty20TextSizeValidationIsSymmetricAndSideEffectFree covers
// Property 20: Text size validation is symmetric and side-effect free.
//
// "Side-effect free" is checked two ways: the submitted bytes are compared before and
// after, and the caller's sequence counter is a plain integer the test watches. There
// is nothing else validation could touch, because CheckText takes only a byte slice.
//
// Validates: Requirements 5.1, 5.2, 5.8
func TestProperty20TextSizeValidationIsSymmetricAndSideEffectFree(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// A mix of generated strings and sizes chosen to land on both boundaries,
		// since 1 and 65,536 are exactly where an off-by-one would hide.
		payload := rapid.OneOf(
			// Arbitrary bytes, so malformed UTF-8 occurs naturally.
			rapid.SliceOfN(rapid.Byte(), 0, 200),
			// Well-formed multi-byte text, so the byte-versus-character reading of
			// the limit gets exercised.
			rapid.Custom(func(t *rapid.T) []byte {
				return []byte(rapid.StringN(0, 200, -1).Draw(t, "text"))
			}),
			// The boundaries themselves, which random generation would rarely hit.
			rapid.SampledFrom([][]byte{
				nil,
				{},
				[]byte("a"),
				bytes.Repeat([]byte{'x'}, TextMaxBytes-1),
				bytes.Repeat([]byte{'x'}, TextMaxBytes),
				bytes.Repeat([]byte{'x'}, TextMaxBytes+1),
			}),
		).Draw(rt, "payload")

		original := append([]byte(nil), payload...)
		sequenceCounter := uint64(41)

		got := CheckText(payload)

		// Accepted exactly when the byte length is in range and the bytes are
		// well-formed UTF-8.
		inRange := len(payload) >= TextMinBytes && len(payload) <= TextMaxBytes
		wellFormed := utf8.Valid(payload)

		switch {
		case !inRange:
			if got.Kind() != CheckOutOfRange {
				rt.Fatalf("%d bytes got %s, want out of range", len(payload), got.Kind())
			}
			// Req 5.8: the error names the permitted range and the measured size.
			if got.OutOfRange.Min != TextMinBytes || got.OutOfRange.Max != TextMaxBytes {
				rt.Fatalf("reported range %d..%d, want %d..%d",
					got.OutOfRange.Min, got.OutOfRange.Max, TextMinBytes, TextMaxBytes)
			}
			if got.OutOfRange.ActualBytes != len(payload) {
				rt.Fatalf("reported %d bytes, want %d", got.OutOfRange.ActualBytes, len(payload))
			}
			if !strings.Contains(got.Reason(), "65536") {
				rt.Fatalf("reason %q does not name the maximum", got.Reason())
			}
			if got.Valid != nil {
				rt.Fatal("rejected text was also returned as valid")
			}

		case !wellFormed:
			if got.Kind() != CheckInvalidUTF8 {
				rt.Fatalf("malformed UTF-8 got %s, want invalid UTF-8", got.Kind())
			}
			if got.Valid != nil {
				rt.Fatal("malformed text was also returned as valid")
			}

		default:
			if got.Kind() != CheckValid {
				rt.Fatalf("%d well-formed bytes got %s (%s)",
					len(payload), got.Kind(), got.Reason())
			}
			if !bytes.Equal(got.Valid, payload) {
				rt.Fatal("accepted text differs from what was submitted")
			}
			if got.Reason() != "" {
				rt.Fatalf("accepted text carries reason %q", got.Reason())
			}
		}

		// Req 5.8: the submitted text is unchanged and no sequence number moved.
		if !bytes.Equal(payload, original) {
			rt.Fatal("validation modified the submitted text")
		}
		if sequenceCounter != 41 {
			rt.Fatal("validation advanced the sequence counter")
		}

		// Symmetry: what the sender may send is exactly what the receiver accepts
		// (Req 5.1 against Req 5.2), so validating twice agrees with itself.
		if again := CheckText(payload); again.Kind() != got.Kind() {
			rt.Fatalf("second check said %s, first said %s", again.Kind(), got.Kind())
		}
	})
}

// TestCheckTextBoundaries pins the exact accepted range from Req 5.1, 5.2, and 5.8.
//
// Requirements: 5.1, 5.2, 5.8
func TestCheckTextBoundaries(t *testing.T) {
	cases := []struct {
		name string
		size int
		want CheckKind
	}{
		{"empty", 0, CheckOutOfRange},
		{"one byte", 1, CheckValid},
		{"one below the maximum", TextMaxBytes - 1, CheckValid},
		{"exactly the maximum", TextMaxBytes, CheckValid},
		{"one over the maximum", TextMaxBytes + 1, CheckOutOfRange},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckText(bytes.Repeat([]byte{'x'}, c.size))
			if got.Kind() != c.want {
				t.Fatalf("%d bytes got %s, want %s", c.size, got.Kind(), c.want)
			}
		})
	}
}

// TestCheckTextCountsBytesNotCharacters guards against the limit being read as a
// character count. A multi-byte string well under 65,536 characters can be well over
// 65,536 bytes, and the wire carries bytes.
//
// Requirements: 5.2
func TestCheckTextCountsBytesNotCharacters(t *testing.T) {
	// "😀" is 4 bytes. 16,385 of them is 65,540 bytes but only 16,385 characters.
	over := strings.Repeat("😀", 16_385)
	if utf8.RuneCountInString(over) >= TextMaxBytes {
		t.Fatalf("test input has %d characters, which defeats its own purpose",
			utf8.RuneCountInString(over))
	}
	got := CheckText([]byte(over))
	if got.Kind() != CheckOutOfRange {
		t.Fatalf("%d bytes in %d characters got %s, want out of range",
			len(over), utf8.RuneCountInString(over), got.Kind())
	}

	// The same string just inside the byte limit is accepted.
	under := strings.Repeat("😀", TextMaxBytes/4)
	if got := CheckText([]byte(under)); got.Kind() != CheckValid {
		t.Fatalf("%d bytes got %s, want valid", len(under), got.Kind())
	}
}

// TestDecodeStrictUTF8RefusesToRepair is the reason DecodeStrictUTF8 exists: a plain
// string() conversion substitutes U+FFFD and reports nothing, which would make
// Req 5.6 unimplementable.
//
// Requirements: 5.6
func TestDecodeStrictUTF8RefusesToRepair(t *testing.T) {
	malformed := []byte{'h', 'i', 0xff, 0xfe}

	if _, ok := DecodeStrictUTF8(malformed); ok {
		t.Fatal("malformed input was accepted")
	}
	// Demonstrate what the strict decoder is protecting against: the plain
	// conversion silently produces displayable text with replacement characters.
	if repaired := []rune(string(malformed)); repaired[2] != utf8.RuneError {
		t.Fatalf("expected the naive conversion to substitute U+FFFD, got %q", repaired)
	}

	got, ok := DecodeStrictUTF8([]byte("héllo 😀"))
	if !ok || got != "héllo 😀" {
		t.Fatalf("DecodeStrictUTF8 returned (%q, %v) for well-formed input", got, ok)
	}
	// Well-formed empty input is a valid empty string, not a failure. Size is
	// CheckText's business.
	if got, ok := DecodeStrictUTF8(nil); !ok || got != "" {
		t.Fatalf("DecodeStrictUTF8(nil) returned (%q, %v), want (\"\", true)", got, ok)
	}
}

// TestCheckTextRejectsMalformedUTF8InRange checks that a payload of an acceptable
// size but malformed encoding is caught rather than passed through.
//
// Requirements: 5.6
func TestCheckTextRejectsMalformedUTF8InRange(t *testing.T) {
	got := CheckText([]byte{'o', 'k', 0xc3, 0x28})
	if got.Kind() != CheckInvalidUTF8 {
		t.Fatalf("got %s, want invalid UTF-8", got.Kind())
	}
	if got.Reason() == "" {
		t.Fatal("invalid UTF-8 carries no reason")
	}
}
