package clipboard

import (
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

// Clipboard size bounds, fixed by Requirements 6.1, 6.8, 6.10, and 6.11.
const (
	// ClipboardMaxBytes is 1 MiB of UTF-8 (Req 6.1, 6.8, 6.11).
	ClipboardMaxBytes = 1_048_576
	// ClipboardMinBytes rejects an empty clipboard, which Req 6.7 reports as an
	// unsupported content type rather than as a size problem.
	ClipboardMinBytes = 1
	// ClipboardPartBytes is 512 KiB of content per part.
	//
	// The arithmetic behind it: a frame payload is at most 1,048,576 bytes
	// (Req 8.1), the clipboard limit is also 1,048,576 bytes (Req 6.8), and the
	// AEAD tag adds 16 bytes. A full clipboard therefore does not fit in one frame,
	// by 16 bytes. Splitting at half the limit keeps a full clipboard at exactly
	// two parts and anything smaller at one, without shaving the round number the
	// requirement names.
	ClipboardPartBytes = 524_288
	// PartHeaderBytes is the fixed per-part header: part index then part count,
	// both big-endian u16.
	//
	//	offset  size  field
	//	  0      2    partIndex   u16
	//	  2      2    partCount   u16
	//	  4      N    content bytes, at most ClipboardPartBytes
	PartHeaderBytes = 4
	// MaxParts is what a u16 part count allows. The clipboard limit means a real
	// payload never exceeds two parts; the bound exists so a malformed header
	// cannot ask for an unbounded allocation.
	MaxParts = 1 << 16
)

// SplitClipboard slices content into wire parts, each carrying the 4-byte header.
//
// Empty content yields no parts rather than one empty part. An empty clipboard is
// rejected before this point by CheckClipboardSend (Req 6.7), so producing a part
// for it would only invent a payload the protocol never sends.
func SplitClipboard(content []byte) [][]byte {
	if len(content) == 0 {
		return nil
	}
	count := (len(content) + ClipboardPartBytes - 1) / ClipboardPartBytes

	parts := make([][]byte, 0, count)
	for index := 0; index < count; index++ {
		start := index * ClipboardPartBytes
		end := start + ClipboardPartBytes
		if end > len(content) {
			end = len(content)
		}
		chunk := content[start:end]

		part := make([]byte, PartHeaderBytes+len(chunk))
		binary.BigEndian.PutUint16(part[0:2], uint16(index))
		binary.BigEndian.PutUint16(part[2:4], uint16(count))
		copy(part[PartHeaderBytes:], chunk)
		parts = append(parts, part)
	}
	return parts
}

// JoinClipboard reassembles parts produced by SplitClipboard, returning ok == false
// when they do not form exactly one complete payload.
//
// The checks are deliberately strict, because a partial or reordered join would put
// corrupted text on the user's clipboard with nothing to signal it: a part shorter
// than the header, a part count of zero, a part count that disagrees between parts,
// an index outside 0..count-1, a duplicate index, a missing index, a wrong number of
// parts, an over-long part, or a reassembled payload over the clipboard limit all
// return false.
func JoinClipboard(parts [][]byte) ([]byte, bool) {
	if len(parts) == 0 || len(parts) > MaxParts {
		return nil, false
	}

	var declaredCount int
	seen := make(map[int][]byte, len(parts))

	for _, part := range parts {
		if len(part) < PartHeaderBytes {
			return nil, false
		}
		index := int(binary.BigEndian.Uint16(part[0:2]))
		count := int(binary.BigEndian.Uint16(part[2:4]))
		body := part[PartHeaderBytes:]

		if count == 0 || len(body) > ClipboardPartBytes {
			return nil, false
		}
		if declaredCount == 0 {
			declaredCount = count
		} else if count != declaredCount {
			return nil, false // parts disagree on how many there are
		}
		if index >= declaredCount {
			return nil, false
		}
		if _, duplicate := seen[index]; duplicate {
			return nil, false
		}
		seen[index] = body
	}

	if len(seen) != declaredCount || len(parts) != declaredCount {
		return nil, false // a part is missing
	}

	total := 0
	for _, body := range seen {
		total += len(body)
	}
	if total > ClipboardMaxBytes {
		return nil, false
	}

	out := make([]byte, 0, total)
	for index := 0; index < declaredCount; index++ {
		out = append(out, seen[index]...)
	}
	return out, true
}

// SendCheck is a tagged result: exactly one of Valid / Unsupported / TooLarge is set.
// Callers MUST check the failure fields first.
type SendCheck struct {
	Valid []byte
	// Unsupported is Req 6.7: the clipboard holds no text content. The requirement
	// words this as an unsupported content type rather than as an empty value,
	// because from the user's side an image or a file on the clipboard and an empty
	// clipboard are the same situation: there is no text to send.
	Unsupported bool
	// TooLarge is Req 6.11: over the 1 MiB limit, which the error must name.
	TooLarge *TooLarge
}

// TooLarge reports clipboard content over the limit, naming both figures.
type TooLarge struct {
	ActualBytes int
	Maximum     int
}

func (t *TooLarge) Error() string {
	return fmt.Sprintf("clipboard content is %d bytes, exceeds the limit of %d bytes",
		t.ActualBytes, t.Maximum)
}

// SendCheckKind names the branch a SendCheck took.
type SendCheckKind uint8

const (
	SendValid SendCheckKind = iota
	SendUnsupported
	SendTooLarge
)

func (k SendCheckKind) String() string {
	switch k {
	case SendValid:
		return "valid"
	case SendTooLarge:
		return "too large"
	default:
		return "unsupported content type"
	}
}

// CheckClipboardSend validates local clipboard content before a send.
//
// It is pure, and that is what makes Req 6.7 and Req 6.11 true: both require the
// clipboard to be left unchanged and nothing to be sent, and a function that only
// inspects a byte slice cannot do either.
func CheckClipboardSend(content []byte) SendCheck {
	if len(content) < ClipboardMinBytes {
		return SendCheck{Unsupported: true} // Req 6.7
	}
	if len(content) > ClipboardMaxBytes {
		return SendCheck{TooLarge: &TooLarge{ // Req 6.11
			ActualBytes: len(content),
			Maximum:     ClipboardMaxBytes,
		}}
	}
	if !utf8.Valid(content) {
		// Not text as Req 6.1 defines it. Reported the same way as an empty
		// clipboard, since the user's situation is the same: nothing sendable.
		return SendCheck{Unsupported: true}
	}
	return SendCheck{Valid: content}
}

// Kind reports which single branch of the check holds.
func (c SendCheck) Kind() SendCheckKind {
	switch {
	case c.TooLarge != nil:
		return SendTooLarge
	case c.Unsupported:
		return SendUnsupported
	default:
		return SendValid
	}
}

// Reason renders a failed check for a report, or "" when the content may be sent.
func (c SendCheck) Reason() string {
	switch c.Kind() {
	case SendTooLarge:
		return c.TooLarge.Error()
	case SendUnsupported:
		return "clipboard holds no sendable text content"
	default:
		return ""
	}
}
