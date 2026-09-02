package codec

import (
	"encoding/binary"
	"fmt"
)

// EncodeResult is a tagged result: exactly one of Bytes / TooLarge is set.
// Go has no sealed sum type, so the invariant is stated rather than enforced.
// Callers MUST check TooLarge first; when TooLarge is nil, Bytes holds the
// encoded Wire_Frame (never nil, since a zero-payload frame is still 14 bytes).
type EncodeResult struct {
	Bytes    []byte
	TooLarge *PayloadTooLarge // Req 8.10: names the offending length and the maximum
}

// PayloadTooLarge reports a payload rejected at encode time. It names both the
// actual length and the permitted maximum, as Req 8.10 requires. Oversize is a
// returned value, not a panic.
type PayloadTooLarge struct {
	PayloadLength int
	Maximum       int
}

func (e *PayloadTooLarge) Error() string {
	return fmt.Sprintf("payload length %d bytes exceeds maximum %d bytes", e.PayloadLength, e.Maximum)
}

// EncodeFrame serializes f into the fixed 14-byte big-endian header plus payload
// (Req 8.1). The encoding is deterministic by construction: fixed offsets, no map
// iteration, no clock, no randomness, and no transport-dependent branches, so the
// same Frame always yields byte-identical output on every transport (Req 8.9).
//
// A payload over MaxPayloadBytes is rejected here rather than truncated or
// panicked on (Req 8.10).
func EncodeFrame(f Frame) EncodeResult {
	if len(f.Payload) > MaxPayloadBytes {
		return EncodeResult{TooLarge: &PayloadTooLarge{
			PayloadLength: len(f.Payload),
			Maximum:       MaxPayloadBytes,
		}}
	}
	// Single allocation of the exact final size.
	out := make([]byte, HeaderBytes+len(f.Payload))
	out[0] = f.ProtocolVersion
	out[1] = f.Type
	binary.BigEndian.PutUint64(out[2:10], f.Sequence) // full u64 preserved exactly
	binary.BigEndian.PutUint32(out[10:14], uint32(len(f.Payload)))
	copy(out[HeaderBytes:], f.Payload)
	return EncodeResult{Bytes: out}
}
