package clipboard

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf8"

	"pgregory.net/rapid"
)

// aeadTagBytes is the ChaCha20-Poly1305 tag the design accounts for when choosing
// ClipboardPartBytes. Property 24 requires every part to fit in one frame payload
// alongside it.
const aeadTagBytes = 16

// frameMaxPayload mirrors codec.MaxPayloadBytes. It is restated rather than imported
// so this package keeps no dependency on codec, and the fixed test below fails loudly
// if the two ever diverge.
const frameMaxPayload = 1_048_576

// drawClipboardContent produces content across the interesting range: empty, tiny,
// either side of one part, and either side of the 1 MiB limit.
func drawClipboardContent(t *rapid.T, label string) []byte {
	return rapid.OneOf(
		rapid.SliceOfN(rapid.Byte(), 0, 64),
		rapid.Custom(func(t *rapid.T) []byte {
			return []byte(rapid.StringN(0, 64, -1).Draw(t, "text"))
		}),
		rapid.SampledFrom([][]byte{
			nil,
			[]byte("x"),
			bytes.Repeat([]byte{'a'}, ClipboardPartBytes-1),
			bytes.Repeat([]byte{'a'}, ClipboardPartBytes),
			bytes.Repeat([]byte{'a'}, ClipboardPartBytes+1),
			bytes.Repeat([]byte{'a'}, ClipboardMaxBytes-1),
			bytes.Repeat([]byte{'a'}, ClipboardMaxBytes),
			bytes.Repeat([]byte{'a'}, ClipboardMaxBytes+1),
		}),
	).Draw(t, label)
}

// TestProperty23ClipboardSendValidation covers
// Property 23: Clipboard send validation.
//
// Validates: Requirements 6.1, 6.7, 6.11
func TestProperty23ClipboardSendValidation(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		content := drawClipboardContent(rt, "content")
		original := append([]byte(nil), content...)

		got := CheckClipboardSend(content)

		inRange := len(content) >= ClipboardMinBytes && len(content) <= ClipboardMaxBytes
		wellFormed := utf8.Valid(content)

		switch {
		case len(content) == 0:
			// Req 6.7: an empty clipboard is an unsupported content type.
			if got.Kind() != SendUnsupported {
				rt.Fatalf("empty clipboard got %s, want unsupported", got.Kind())
			}
		case len(content) > ClipboardMaxBytes:
			// Req 6.11: the error names the 1 MiB limit.
			if got.Kind() != SendTooLarge {
				rt.Fatalf("%d bytes got %s, want too large", len(content), got.Kind())
			}
			if got.TooLarge.Maximum != ClipboardMaxBytes {
				rt.Fatalf("limit reported as %d, want %d",
					got.TooLarge.Maximum, ClipboardMaxBytes)
			}
			if got.TooLarge.ActualBytes != len(content) {
				rt.Fatalf("reported %d bytes, want %d", got.TooLarge.ActualBytes, len(content))
			}
			if !strings.Contains(got.Reason(), "1048576") {
				rt.Fatalf("reason %q does not name the limit", got.Reason())
			}
		case !wellFormed:
			// Not text, so not sendable, reported the same way as an empty
			// clipboard.
			if got.Kind() != SendUnsupported {
				rt.Fatalf("malformed content got %s, want unsupported", got.Kind())
			}
		default:
			if got.Kind() != SendValid {
				rt.Fatalf("%d well-formed bytes got %s (%s)",
					len(content), got.Kind(), got.Reason())
			}
			if !bytes.Equal(got.Valid, content) {
				rt.Fatal("accepted content differs from the clipboard")
			}
			if !inRange {
				rt.Fatal("accepted content outside the permitted range")
			}
		}

		// Req 6.7 and 6.11: nothing is sent and the clipboard is unchanged. A pure
		// function over a byte slice cannot send, so the check that remains is that
		// it did not mutate what it was given.
		if !bytes.Equal(content, original) {
			rt.Fatal("validation modified the clipboard content")
		}
		if got.Kind() != SendValid && got.Valid != nil {
			rt.Fatal("a rejected check also returned valid content")
		}
	})
}

// TestProperty24ClipboardPartSplitAndJoinRoundTrip covers
// Property 24: Clipboard part split and join round trip.
//
// Validates: Requirements 6.8
func TestProperty24ClipboardPartSplitAndJoinRoundTrip(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		content := drawClipboardContent(rt, "content")
		// The property is scoped to sendable content, which is what is ever split.
		if len(content) == 0 || len(content) > ClipboardMaxBytes {
			return
		}

		parts := SplitClipboard(content)
		if len(parts) == 0 {
			rt.Fatalf("%d bytes produced no parts", len(content))
		}
		wantCount := (len(content) + ClipboardPartBytes - 1) / ClipboardPartBytes
		if len(parts) != wantCount {
			rt.Fatalf("%d bytes produced %d parts, want %d", len(content), len(parts), wantCount)
		}

		for i, part := range parts {
			if len(part) < PartHeaderBytes {
				rt.Fatalf("part %d is %d bytes, shorter than the header", i, len(part))
			}
			index := int(binary.BigEndian.Uint16(part[0:2]))
			count := int(binary.BigEndian.Uint16(part[2:4]))

			// Indices run 0..count-1 and every part declares the same count.
			if index != i {
				rt.Fatalf("part at position %d declares index %d", i, index)
			}
			if count != wantCount {
				rt.Fatalf("part %d declares count %d, want %d", i, count, wantCount)
			}
			// Body is within one part's worth, and only the last may be short.
			body := part[PartHeaderBytes:]
			if len(body) > ClipboardPartBytes {
				rt.Fatalf("part %d body is %d bytes, over %d", i, len(body), ClipboardPartBytes)
			}
			if i < len(parts)-1 && len(body) != ClipboardPartBytes {
				rt.Fatalf("part %d is short at %d bytes but is not the last", i, len(body))
			}
			// Every part fits in one frame payload alongside its AEAD tag.
			if len(part)+aeadTagBytes > frameMaxPayload {
				rt.Fatalf("part %d is %d bytes, which does not fit a %d-byte payload with a %d-byte tag",
					i, len(part), frameMaxPayload, aeadTagBytes)
			}
		}

		joined, ok := JoinClipboard(parts)
		if !ok {
			rt.Fatalf("joining %d parts failed", len(parts))
		}
		if !bytes.Equal(joined, content) {
			rt.Fatalf("round trip changed %d bytes into %d", len(content), len(joined))
		}
	})
}

// TestJoinClipboardRejectsMalformedPartSets checks every way a part set can fail to
// form one complete payload. A partial or reordered join would put corrupted text on
// the user's clipboard with nothing to signal it, so each of these must return false.
//
// Requirements: 6.8
func TestJoinClipboardRejectsMalformedPartSets(t *testing.T) {
	part := func(index, count uint16, body string) []byte {
		out := make([]byte, PartHeaderBytes+len(body))
		binary.BigEndian.PutUint16(out[0:2], index)
		binary.BigEndian.PutUint16(out[2:4], count)
		copy(out[PartHeaderBytes:], body)
		return out
	}

	cases := map[string][][]byte{
		"no parts":                nil,
		"header truncated":        {{0, 0, 1}},
		"zero part count":         {part(0, 0, "x")},
		"index at the count":      {part(1, 1, "x")},
		"index past the count":    {part(9, 1, "x")},
		"counts disagree":         {part(0, 2, "a"), part(1, 3, "b")},
		"duplicate index":         {part(0, 2, "a"), part(0, 2, "a")},
		"missing middle part":     {part(0, 3, "a"), part(2, 3, "c")},
		"too few parts for count": {part(0, 2, "a")},
		"body over one part":      {part(0, 1, strings.Repeat("x", ClipboardPartBytes+1))},
	}
	for name, parts := range cases {
		t.Run(name, func(t *testing.T) {
			if got, ok := JoinClipboard(parts); ok {
				t.Fatalf("malformed part set joined into %d bytes", len(got))
			}
		})
	}
}

// TestSplitClipboardAtTheLimitIsExactlyTwoParts pins the arithmetic the part size was
// chosen for: a full 1 MiB clipboard does not fit one frame once the AEAD tag is
// counted, and 512 KiB parts make it exactly two.
//
// Requirements: 6.8
func TestSplitClipboardAtTheLimitIsExactlyTwoParts(t *testing.T) {
	if ClipboardMaxBytes+aeadTagBytes <= frameMaxPayload {
		t.Fatal("a full clipboard now fits one frame; the part header may be unnecessary")
	}

	full := bytes.Repeat([]byte{'z'}, ClipboardMaxBytes)
	parts := SplitClipboard(full)
	if len(parts) != 2 {
		t.Fatalf("a full clipboard split into %d parts, want 2", len(parts))
	}

	// Anything at or under one part's worth stays a single part.
	for _, size := range []int{1, ClipboardPartBytes - 1, ClipboardPartBytes} {
		if got := SplitClipboard(bytes.Repeat([]byte{'z'}, size)); len(got) != 1 {
			t.Fatalf("%d bytes split into %d parts, want 1", size, len(got))
		}
	}
	// One byte more needs two.
	if got := SplitClipboard(bytes.Repeat([]byte{'z'}, ClipboardPartBytes+1)); len(got) != 2 {
		t.Fatalf("%d bytes split into %d parts, want 2", ClipboardPartBytes+1, len(got))
	}

	joined, ok := JoinClipboard(parts)
	if !ok || !bytes.Equal(joined, full) {
		t.Fatal("a full clipboard did not survive the round trip")
	}
}

// TestSplitClipboardEmptyContentProducesNoParts documents the choice not to emit an
// empty part for an empty clipboard, which Req 6.7 rejects before splitting anyway.
//
// Requirements: 6.7, 6.8
func TestSplitClipboardEmptyContentProducesNoParts(t *testing.T) {
	if got := SplitClipboard(nil); got != nil {
		t.Fatalf("nil content produced %d parts", len(got))
	}
	if got := SplitClipboard([]byte{}); got != nil {
		t.Fatalf("empty content produced %d parts", len(got))
	}
}
