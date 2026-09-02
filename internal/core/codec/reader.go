package codec

import (
	"encoding/binary"
	"fmt"
	"time"
)

// PayloadTimeout is how long a frame whose header has been parsed may wait for the
// rest of its declared payload before the frame is discarded with a framing error
// (Req 8.12).
const PayloadTimeout = 10 * time.Second

// compactThreshold is the number of already-consumed leading bytes that triggers a
// buffer compaction. Compacting on every consumed frame would copy the tail
// constantly; never compacting would grow the buffer without bound. The threshold
// keeps both costs bounded.
const compactThreshold = 64 * 1024

// CodecError is a tagged error type: exactly one field is non-nil. It is a value
// callers inspect, not a string they parse, so each failure can name the specific
// fields the requirements ask for.
type CodecError struct {
	UnsupportedVersion *UnsupportedVersion // Req 8.6
	PayloadTooLarge    *DeclaredTooLarge   // Req 8.11
	FramingMismatch    *FramingMismatch    // Req 8.5 and 8.12
}

func (e *CodecError) Error() string {
	switch {
	case e == nil:
		return "<nil>"
	case e.UnsupportedVersion != nil:
		return e.UnsupportedVersion.Error()
	case e.PayloadTooLarge != nil:
		return e.PayloadTooLarge.Error()
	case e.FramingMismatch != nil:
		return e.FramingMismatch.Error()
	default:
		return "codec error with no cause set"
	}
}

// UnsupportedVersion names both the version the peer declared and the one this
// node accepts, as Req 8.6 requires.
type UnsupportedVersion struct {
	Declared int
	Accepted int
}

func (e *UnsupportedVersion) Error() string {
	return fmt.Sprintf("frame declares protocol version %d, this node accepts version %d", e.Declared, e.Accepted)
}

// DeclaredTooLarge is the read-side oversize error of Req 8.11. It is distinct from
// the encoder's PayloadTooLarge because the two happen at opposite ends: the encoder
// holds an actual payload, whereas here only a declared length is known, and that
// length arrives from a peer so it is held as an int64 and never used to size an
// allocation.
type DeclaredTooLarge struct {
	DeclaredLength int64
	Maximum        int
}

func (e *DeclaredTooLarge) Error() string {
	return fmt.Sprintf("frame declares payload length %d bytes, exceeding maximum %d bytes", e.DeclaredLength, e.Maximum)
}

// FramingMismatch reports a frame whose payload never completed, naming the declared
// length and the count actually received (Req 8.5, 8.12).
//
// When the 14-byte header itself is truncated the declared payload length is not yet
// knowable. In that case DeclaredLength is HeaderBytes and ReceivedCount is the count
// of header bytes received, so the error still names what was expected against what
// arrived.
type FramingMismatch struct {
	DeclaredLength int
	ReceivedCount  int
}

func (e *FramingMismatch) Error() string {
	return fmt.Sprintf("frame declares %d payload bytes but %d were received", e.DeclaredLength, e.ReceivedCount)
}

// ReadResult carries the frames a Push produced and, if parsing failed, the error.
// Frames decoded before the failure are still returned: they were complete and
// correct on the wire, and dropping them would lose messages the peer sent.
type ReadResult struct {
	Frames []Frame
	Err    *CodecError
}

// FrameReader turns a byte stream into Frames. It holds no socket: callers push the
// bytes they read. A transport delivers arbitrary byte runs, so parsing is
// incremental — a frame may span any number of Push calls and a single Push may
// contain many frames (Req 8.2, 8.3).
//
// Field validation is strictly in header order (Req 8.7) and the first failure wins.
//
// Not safe for concurrent use; a session drives one reader from its reader goroutine.
type FrameReader struct {
	acceptedVersion int
	clock           Clock
	buf             []byte
	off             int        // start of the frame currently being assembled, within buf
	headerParsedAt  *time.Time // set while a header is complete but its payload is not
}

// NewFrameReader returns a reader that accepts only ProtocolVersion and measures the
// Req 8.12 payload timeout with clock.
func NewFrameReader(clock Clock) *FrameReader {
	return &FrameReader{acceptedVersion: ProtocolVersion, clock: clock}
}

// Push feeds newly read bytes and returns every complete Frame now available, in
// stream order.
//
// An unrecognised message type is not an error: the frame is returned as parsed and
// the session router decides what to do with the code (Req 8.8).
//
// On any error the buffered bytes of the offending frame are discarded (Req 8.5, 8.6,
// 8.11) along with whatever followed them in the buffer, because once a frame is
// rejected the stream position is no longer trustworthy. The reader is left empty, so
// a caller that chooses to keep reading starts from a clean state.
func (r *FrameReader) Push(data []byte) ReadResult {
	// Req 8.12: a payload that failed to complete within PayloadTimeout of its header
	// being parsed is already expired, so it is reported before any newly arrived byte
	// is considered. The incoming bytes are dropped with it: they are the continuation
	// of a frame that no longer exists, so they cannot be aligned to a frame boundary.
	if r.payloadExpired() {
		return ReadResult{Err: r.discardPartial()}
	}
	r.buf = append(r.buf, data...)
	return r.parse()
}

// FlushIncomplete is called when the transport closes or the payload timer fires. If a
// partial frame is buffered, Req 8.5 / 8.12 want a framing error naming declared
// against received, and the buffered bytes discarded. Returns nil when nothing is
// buffered, since a stream that ends on a frame boundary ended cleanly.
//
// The Session's message sequence state is untouched either way: this reader never
// reports a sequence number it did not fully receive.
func (r *FrameReader) FlushIncomplete() *ReadResult {
	if r.buffered() == 0 {
		return nil
	}
	return &ReadResult{Err: r.discardPartial()}
}

// PayloadDeadline reports when the frame in progress runs out of time, so a caller can
// arm its payload timer off the same Clock that the reader validates against. ok is
// false when no header is waiting on a payload.
func (r *FrameReader) PayloadDeadline() (time.Time, bool) {
	if r.headerParsedAt == nil {
		return time.Time{}, false
	}
	return r.headerParsedAt.Add(PayloadTimeout), true
}

// parse drains as many complete frames as the buffer holds.
func (r *FrameReader) parse() ReadResult {
	var frames []Frame
	for {
		avail := r.buffered()
		if avail < HeaderBytes {
			// Not even a full header yet. No payload timer runs: the payload length
			// field has not been parsed, so Req 8.12 has not started counting.
			break
		}
		header := r.buf[r.off : r.off+HeaderBytes]

		// Fields are validated in wire order and the first failure is returned
		// (Req 8.7): version, then type, then sequence, then payload length.

		// 1. Protocol version (Req 8.6).
		version := header[0]
		if int(version) != r.acceptedVersion {
			r.discardAll()
			return ReadResult{Frames: frames, Err: &CodecError{UnsupportedVersion: &UnsupportedVersion{
				Declared: int(version),
				Accepted: r.acceptedVersion,
			}}}
		}
		// 2. Message type. Every code is accepted here, known or not (Req 8.8).
		messageType := header[1]
		// 3. Sequence number. The whole u64 range is legal per Req 8.1, so this field
		//    cannot fail; it is read in position so the order above stays meaningful.
		sequence := binary.BigEndian.Uint64(header[2:10])
		// 4. Payload length (Req 8.11). Checked here, at the header, before a single
		//    payload byte is buffered or any payload-sized allocation is made, which
		//    is what caps the memory a hostile peer can make this node reserve.
		declared := int64(binary.BigEndian.Uint32(header[10:14]))
		if declared > MaxPayloadBytes {
			r.discardAll()
			return ReadResult{Frames: frames, Err: &CodecError{PayloadTooLarge: &DeclaredTooLarge{
				DeclaredLength: declared,
				Maximum:        MaxPayloadBytes,
			}}}
		}

		if int64(avail) < int64(HeaderBytes)+declared {
			// Header is good, payload is short. Start the Req 8.12 clock at the moment
			// the payload length field was parsed, and only once for this frame.
			if r.headerParsedAt == nil {
				now := r.clock.Now()
				r.headerParsedAt = &now
			}
			break
		}

		payloadStart := r.off + HeaderBytes
		payloadEnd := payloadStart + int(declared)
		// The payload is copied out: the buffer is reused and compacted, so handing
		// out a sub-slice of it would let later pushes alter a delivered frame.
		var payload []byte
		if declared > 0 {
			payload = make([]byte, declared)
			copy(payload, r.buf[payloadStart:payloadEnd])
		}
		frames = append(frames, Frame{
			ProtocolVersion: version,
			Type:            messageType,
			Sequence:        sequence,
			Payload:         payload,
		})
		r.off = payloadEnd
		r.headerParsedAt = nil // this frame completed, nothing is waiting on a payload
		r.compact()
	}
	r.compact()
	return ReadResult{Frames: frames}
}

// buffered is the count of bytes belonging to the frame currently being assembled.
func (r *FrameReader) buffered() int { return len(r.buf) - r.off }

func (r *FrameReader) payloadExpired() bool {
	if r.headerParsedAt == nil {
		return false
	}
	return r.clock.Now().Sub(*r.headerParsedAt) >= PayloadTimeout
}

// discardPartial drops the buffered bytes of the frame in progress and builds the
// framing error of Req 8.5 / 8.12.
func (r *FrameReader) discardPartial() *CodecError {
	buffered := r.buffered()
	// With a complete header the declared payload length is known; without one it is
	// not, so the header size stands in. See FramingMismatch.
	declared, received := HeaderBytes, buffered
	if buffered >= HeaderBytes {
		declared = int(binary.BigEndian.Uint32(r.buf[r.off+10 : r.off+14]))
		received = buffered - HeaderBytes
	}
	r.discardAll()
	return &CodecError{FramingMismatch: &FramingMismatch{
		DeclaredLength: declared,
		ReceivedCount:  received,
	}}
}

// discardAll empties the buffer and stops the payload timer. The backing array is
// kept so a steady stream does not reallocate; its size is bounded by the largest
// frame this reader will ever assemble, HeaderBytes + MaxPayloadBytes, because
// anything larger is rejected at the header.
func (r *FrameReader) discardAll() {
	r.buf = r.buf[:0]
	r.off = 0
	r.headerParsedAt = nil
}

// compact reclaims the space of already-consumed frames. Fully drained buffers reset
// to the front for free; otherwise the tail moves only once the consumed prefix is
// worth the copy.
func (r *FrameReader) compact() {
	switch {
	case r.off == 0:
		return
	case r.off >= len(r.buf):
		r.buf = r.buf[:0]
		r.off = 0
	case r.off >= compactThreshold || r.off >= len(r.buf)/2:
		n := copy(r.buf, r.buf[r.off:])
		r.buf = r.buf[:n]
		r.off = 0
	}
}
