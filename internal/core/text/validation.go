package text

import (
	"fmt"
	"unicode/utf8"
)

// Size bounds for a text Message, fixed by Requirements 5.1, 5.2, 5.8, and 5.9.
// The unit is bytes of UTF-8, not characters: the wire carries bytes, and the frame
// payload limit in Req 8.1 is a byte count, so a character-based limit here would
// not compose with it.
const (
	// TextMinBytes rejects an empty submission (Req 5.8).
	TextMinBytes = 1
	// TextMaxBytes is 64 KiB (Req 5.2, 5.8, 5.9).
	TextMaxBytes = 65_536
)

// OutOfRange reports a submission outside the permitted size, naming both the
// measured size and the range, which is what Req 5.8 and Req 5.9 require the error
// to state.
type OutOfRange struct {
	ActualBytes int
	Min, Max    int
}

func (o *OutOfRange) Error() string {
	return fmt.Sprintf("text is %d bytes, permitted range is %d..%d bytes",
		o.ActualBytes, o.Min, o.Max)
}

// TextCheck is a tagged result: exactly one of Valid / OutOfRange / InvalidUTF8 is
// set. Go has no sealed sum type, so the invariant is stated rather than enforced.
// Callers MUST check the two failure fields before reading Valid.
type TextCheck struct {
	Valid       []byte
	OutOfRange  *OutOfRange // Req 5.8: names the permitted range
	InvalidUTF8 bool        // Req 5.6
}

// Kind names the branch a TextCheck took.
type CheckKind uint8

const (
	CheckValid CheckKind = iota
	CheckOutOfRange
	CheckInvalidUTF8
)

func (k CheckKind) String() string {
	switch k {
	case CheckValid:
		return "valid"
	case CheckOutOfRange:
		return "out of range"
	default:
		return "invalid utf-8"
	}
}

// Kind reports which single branch of the check holds.
func (c TextCheck) Kind() CheckKind {
	switch {
	case c.OutOfRange != nil:
		return CheckOutOfRange
	case c.InvalidUTF8:
		return CheckInvalidUTF8
	default:
		return CheckValid
	}
}

// Reason renders a failed check for a report, or "" when the text was accepted.
func (c TextCheck) Reason() string {
	switch c.Kind() {
	case CheckOutOfRange:
		return c.OutOfRange.Error()
	case CheckInvalidUTF8:
		return "text is not valid UTF-8"
	default:
		return ""
	}
}

// CheckText validates text for sending or receiving. It is a pure function with no
// side effects at all, which is the point: Req 5.8 requires a rejected submission to
// send nothing, leave the user's text unchanged, and not advance the Session's
// sequence number, and the simplest way to guarantee that is for validation to be
// incapable of doing any of those things.
//
// Size is checked before encoding, because Req 5.9 rejects an oversized payload on
// the strength of its size alone and there is no reason to scan a megabyte of bytes
// to reach a conclusion its length already settled.
//
// The same function serves both directions. Req 5.2 states the accepted receive
// range and Req 5.1 states the accepted send range, and they are the same range, so
// one implementation keeps them from drifting apart.
func CheckText(payload []byte) TextCheck {
	if len(payload) < TextMinBytes || len(payload) > TextMaxBytes {
		return TextCheck{OutOfRange: &OutOfRange{
			ActualBytes: len(payload),
			Min:         TextMinBytes,
			Max:         TextMaxBytes,
		}}
	}
	if !utf8.Valid(payload) {
		return TextCheck{InvalidUTF8: true}
	}
	return TextCheck{Valid: payload}
}

// DecodeStrictUTF8 converts bytes to a string only when they are well-formed UTF-8,
// reporting ok == false otherwise.
//
// The point is what it refuses to do. A plain string(b) conversion never fails: Go
// substitutes U+FFFD for each malformed sequence at the point the string is ranged
// over, so invalid input becomes valid-looking text with replacement characters in
// it. Req 5.6 requires a malformed payload to be withheld and reported as invalid
// UTF-8, which is impossible once the damage has been silently repaired. utf8.Valid
// answers the question before the conversion happens.
func DecodeStrictUTF8(b []byte) (string, bool) {
	if !utf8.Valid(b) {
		return "", false
	}
	return string(b), true
}
