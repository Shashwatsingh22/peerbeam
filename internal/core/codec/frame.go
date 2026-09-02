package codec

import "bytes"

// Wire layout of a Wire_Frame (Req 8.1). Fixed offsets are what make the
// encoding deterministic and identical on every transport (Req 8.9).
//
//	offset  size  field
//	  0      1    protocolVersion   u8
//	  1      1    messageType       u8   (raw code; unknown codes survive parsing)
//	  2      8    sequenceNumber    u64  big-endian, 0 .. 18_446_744_073_709_551_615
//	 10      4    payloadLength     u32  big-endian, 0 .. 1_048_576
//	 14      N    payload           N == payloadLength
const (
	// ProtocolVersion is the only protocol version this Peer_Node accepts (Req 8.6).
	ProtocolVersion = 1
	// HeaderBytes is the fixed size of the frame header in bytes.
	HeaderBytes = 14
	// MaxPayloadBytes is the largest payload a frame may carry (Req 8.1, 8.10, 8.11).
	MaxPayloadBytes = 1_048_576
)

// Frame is one Wire_Frame in memory. Type stays a raw code so that an unrecognised
// type still round-trips byte-for-byte (Req 8.4, 8.8) instead of being lost.
type Frame struct {
	ProtocolVersion uint8
	Type            uint8  // raw code
	Sequence        uint64 // full u64 range
	Payload         []byte
}

// Equal is explicit because slices are not comparable with ==.
func (f Frame) Equal(other Frame) bool {
	return f.ProtocolVersion == other.ProtocolVersion &&
		f.Type == other.Type &&
		f.Sequence == other.Sequence &&
		bytes.Equal(f.Payload, other.Payload)
}
