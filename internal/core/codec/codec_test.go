package codec

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/peerbeam/peerbeam/internal/core/clock"
)

var baseTime = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

// manualClock is the injected time source, so the 10-second payload timeout of Req 8.12 is checked by
// advancing it rather than by waiting.
type manualClock struct{ now time.Time }

func newManualClock() *manualClock             { return &manualClock{now: baseTime} }
func (c *manualClock) Now() time.Time          { return c.now }
func (c *manualClock) advance(d time.Duration) { c.now = c.now.Add(d) }

var _ clock.Clock = (*manualClock)(nil)

// knownTypeCodes is the closed set of recognised message type codes.
func knownTypeCodes() []uint8 {
	return []uint8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
}

// drawFrame produces a well-formed Frame. Payload sizes straddle the interesting boundaries: empty,
// small, and either side of nothing in particular - the 1 MiB limit is exercised separately, because
// generating megabyte payloads a hundred times over would make the property slow for no extra signal.
func drawFrame(t *rapid.T, label string) Frame {
	return Frame{
		ProtocolVersion: ProtocolVersion,
		Type: rapid.OneOf(
			rapid.SampledFrom(knownTypeCodes()),
			// Unrecognised codes are part of the domain: Req 8.4 and 8.8 require them to
			// round-trip rather than be rejected.
			rapid.Uint8(),
		).Draw(t, label+"Type"),
		// The full u64 range, because Req 8.1 states it and a 32-bit truncation would only
		// show up above 4 billion.
		Sequence: rapid.OneOf(
			rapid.Uint64(),
			rapid.SampledFrom([]uint64{0, 1, 255, 256, 1 << 31, 1 << 32, ^uint64(0)}),
		).Draw(t, label+"Sequence"),
		Payload: rapid.SliceOfN(rapid.Byte(), 0, 300).Draw(t, label+"Payload"),
	}
}

// TestProperty1FrameRoundTrip covers
// Property 1: Frame round trip.
//
// Validates: Requirements 8.1, 8.2, 8.3
func TestProperty1FrameRoundTrip(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		frame := drawFrame(rt, "frame")

		encoded := EncodeFrame(frame)
		if encoded.TooLarge != nil {
			rt.Fatalf("a %d-byte payload was rejected: %s", len(frame.Payload), encoded.TooLarge.Error())
		}

		reader := NewFrameReader(newManualClock())
		result := reader.Push(encoded.Bytes)
		if result.Err != nil {
			rt.Fatalf("decoding a frame we just encoded failed: %s", result.Err.Error())
		}
		if len(result.Frames) != 1 {
			rt.Fatalf("decoded %d frames from one encoding", len(result.Frames))
		}

		got := result.Frames[0]
		if !got.Equal(frame) {
			rt.Fatalf("round trip changed the frame:\n sent %+v\n got  %+v", frame, got)
		}
		// Every field individually, so a failure names which one drifted.
		if got.ProtocolVersion != frame.ProtocolVersion {
			rt.Fatalf("version %d, want %d", got.ProtocolVersion, frame.ProtocolVersion)
		}
		if got.Type != frame.Type {
			rt.Fatalf("type %d, want %d", got.Type, frame.Type)
		}
		if got.Sequence != frame.Sequence {
			rt.Fatalf("sequence %d, want %d", got.Sequence, frame.Sequence)
		}
		if !bytes.Equal(got.Payload, frame.Payload) {
			rt.Fatalf("payload of %d bytes, want %d", len(got.Payload), len(frame.Payload))
		}
	})
}

// TestProperty2ByteRoundTripAndEncodingDeterminism covers
// Property 2: Byte round trip and encoding determinism.
//
// Validates: Requirements 8.4, 8.9
func TestProperty2ByteRoundTripAndEncodingDeterminism(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		frame := drawFrame(rt, "frame")

		first := EncodeFrame(frame)
		if first.TooLarge != nil {
			rt.Fatalf("unexpected rejection: %s", first.TooLarge.Error())
		}

		// Req 8.9: the same Frame always yields byte-identical output. Encoding it repeatedly
		// has to agree, which rules out map iteration, a clock, or randomness sneaking in.
		for i := 0; i < 4; i++ {
			again := EncodeFrame(frame)
			if again.TooLarge != nil {
				rt.Fatalf("encoding %d rejected what encoding 0 accepted", i)
			}
			if !bytes.Equal(again.Bytes, first.Bytes) {
				rt.Fatalf("encoding is not deterministic: run %d differs", i)
			}
		}

		// The header is exactly 14 bytes and the total is header plus payload, so nothing is
		// padded or elided (Req 8.1).
		if len(first.Bytes) != HeaderBytes+len(frame.Payload) {
			rt.Fatalf("encoded %d bytes for a %d-byte payload, want %d",
				len(first.Bytes), len(frame.Payload), HeaderBytes+len(frame.Payload))
		}

		// Req 8.4: decoding the bytes and re-encoding the result reproduces the same bytes.
		reader := NewFrameReader(newManualClock())
		result := reader.Push(first.Bytes)
		if result.Err != nil || len(result.Frames) != 1 {
			rt.Fatalf("decode failed: %+v", result)
		}
		second := EncodeFrame(result.Frames[0])
		if !bytes.Equal(second.Bytes, first.Bytes) {
			rt.Fatal("decode then re-encode did not reproduce the original bytes")
		}
	})
}

// TestProperty3StreamFramingUnderArbitrarySegmentation covers
// Property 3: Stream framing under arbitrary segmentation.
//
// This is the property the incremental reader exists for. A Transport delivers arbitrary byte runs, so
// the same stream cut at different points must produce the same frames - including cuts that fall in
// the middle of a header field.
//
// Validates: Requirements 8.2, 8.3
func TestProperty3StreamFramingUnderArbitrarySegmentation(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		count := rapid.IntRange(0, 6).Draw(rt, "frameCount")
		frames := make([]Frame, 0, count)
		var stream []byte
		for i := 0; i < count; i++ {
			frame := drawFrame(rt, "frame"+strconv.Itoa(i))
			encoded := EncodeFrame(frame)
			if encoded.TooLarge != nil {
				rt.Fatalf("unexpected rejection: %s", encoded.TooLarge.Error())
			}
			frames = append(frames, frame)
			stream = append(stream, encoded.Bytes...)
		}

		// Cut the stream at arbitrary points, including zero-length pushes.
		cuts := rapid.SliceOfN(rapid.IntRange(0, len(stream)), 0, 12).Draw(rt, "cuts")
		bounds := append([]int{0}, cuts...)
		bounds = append(bounds, len(stream))
		sortInts(bounds)

		reader := NewFrameReader(newManualClock())
		var decoded []Frame
		for i := 1; i < len(bounds); i++ {
			result := reader.Push(stream[bounds[i-1]:bounds[i]])
			if result.Err != nil {
				rt.Fatalf("a well-formed stream failed at cut %d: %s", i, result.Err.Error())
			}
			decoded = append(decoded, result.Frames...)
		}

		// Every frame, in stream order, regardless of where the cuts fell.
		if len(decoded) != len(frames) {
			rt.Fatalf("decoded %d frames from a stream of %d", len(decoded), len(frames))
		}
		for i := range frames {
			if !decoded[i].Equal(frames[i]) {
				rt.Fatalf("frame %d differs after segmentation:\n sent %+v\n got  %+v",
					i, frames[i], decoded[i])
			}
		}
		// A stream that ended on a frame boundary ended cleanly, so there is nothing partial
		// left to flush.
		if flushed := reader.FlushIncomplete(); flushed != nil {
			rt.Fatalf("a complete stream left something buffered: %+v", flushed)
		}
	})
}

func sortInts(values []int) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// TestProperty4IncompleteFramesProduceAFramingError covers
// Property 4: Incomplete frames produce a framing error and leave sequence state untouched.
//
// Validates: Requirements 8.5, 8.12
func TestProperty4IncompleteFramesProduceAFramingError(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		frame := drawFrame(rt, "frame")
		frame.Payload = rapid.SliceOfN(rapid.Byte(), 1, 200).Draw(rt, "payload")

		encoded := EncodeFrame(frame)
		if encoded.TooLarge != nil {
			rt.Fatalf("unexpected rejection: %s", encoded.TooLarge.Error())
		}

		// Cut the frame short, anywhere from one byte to one byte before the end.
		keep := rapid.IntRange(1, len(encoded.Bytes)-1).Draw(rt, "keep")
		partial := encoded.Bytes[:keep]

		reader := NewFrameReader(newManualClock())
		result := reader.Push(partial)
		if result.Err != nil {
			rt.Fatalf("a partial frame reported an error before it was flushed: %s",
				result.Err.Error())
		}
		if len(result.Frames) != 0 {
			rt.Fatalf("a partial frame produced %d frames", len(result.Frames))
		}

		// Req 8.5: flushing reports a framing error. When the header itself was incomplete
		// there is no declared length to compare against, so the error is still a framing
		// mismatch but its declared count is what was readable.
		flushed := reader.FlushIncomplete()
		if flushed == nil {
			rt.Fatalf("flushing %d buffered bytes reported nothing", keep)
		}
		if flushed.Err == nil {
			rt.Fatal("flushing a partial frame produced no error")
		}
		if flushed.Err.FramingMismatch == nil {
			rt.Fatalf("flushing gave %s, want a framing mismatch", flushed.Err.Error())
		}
		// The error names both counts, which is what Req 8.5 requires.
		message := flushed.Err.Error()
		if !strings.Contains(message, strconv.Itoa(flushed.Err.FramingMismatch.ReceivedCount)) {
			rt.Fatalf("the error %q does not name the received count", message)
		}

		// Req 8.12: the reader is left empty, so a caller that keeps reading starts clean.
		if second := reader.FlushIncomplete(); second != nil {
			rt.Fatalf("the reader still held bytes after a flush: %+v", second)
		}
	})
}

// TestPayloadTimeoutIsTenSeconds pins the Req 8.12 window: a header whose payload never arrives is
// reported after ten seconds, not before.
//
// Requirements: 8.12
func TestPayloadTimeoutIsTenSeconds(t *testing.T) {
	if PayloadTimeout != 10*time.Second {
		t.Fatalf("the payload timeout is %s, want 10s", PayloadTimeout)
	}

	clk := newManualClock()
	reader := NewFrameReader(clk)

	// A complete header promising a payload that never comes.
	header := EncodeFrame(Frame{
		ProtocolVersion: ProtocolVersion,
		Type:            uint8(MsgText),
		Sequence:        7,
		Payload:         make([]byte, 100),
	}).Bytes[:HeaderBytes]

	if result := reader.Push(header); result.Err != nil {
		t.Fatalf("a complete header was rejected: %s", result.Err.Error())
	}

	// The deadline is readable, so a caller can arm its timer off the same clock.
	deadline, armed := reader.PayloadDeadline()
	if !armed {
		t.Fatal("no payload deadline after a header was parsed")
	}
	if !deadline.Equal(baseTime.Add(PayloadTimeout)) {
		t.Fatalf("the deadline is %s, want %s", deadline, baseTime.Add(PayloadTimeout))
	}

	// One nanosecond early, nothing is reported.
	clk.advance(PayloadTimeout - time.Nanosecond)
	if result := reader.Push(nil); result.Err != nil {
		t.Fatalf("the payload expired one nanosecond early: %s", result.Err.Error())
	}

	// At exactly the timeout it is.
	clk.advance(time.Nanosecond)
	result := reader.Push(nil)
	if result.Err == nil {
		t.Fatalf("the payload did not expire at %s", PayloadTimeout)
	}
	if result.Err.FramingMismatch == nil {
		t.Fatalf("expiry gave %s, want a framing mismatch", result.Err.Error())
	}
}

// TestProperty5HeaderValidationHappensInFieldOrder covers
// Property 5: Header validation happens in field order and reports the first failure.
//
// The order matters because several fields can be wrong at once, and a reader that checked the length
// first would report an oversized payload for a frame from an incompatible version - sending the
// operator after a size problem instead of a version mismatch.
//
// Validates: Requirements 8.6, 8.7, 8.11
func TestProperty5HeaderValidationHappensInFieldOrder(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		badVersion := rapid.Bool().Draw(rt, "badVersion")
		badLength := rapid.Bool().Draw(rt, "badLength")

		header := make([]byte, HeaderBytes)
		header[0] = ProtocolVersion
		if badVersion {
			// Any version other than the accepted one.
			header[0] = ProtocolVersion + uint8(rapid.IntRange(1, 200).Draw(rt, "versionOffset"))
		}
		header[1] = uint8(rapid.IntRange(0, 255).Draw(rt, "type"))
		binary.BigEndian.PutUint64(header[2:10], rapid.Uint64().Draw(rt, "sequence"))

		length := uint32(rapid.IntRange(0, 100).Draw(rt, "length"))
		if badLength {
			length = uint32(MaxPayloadBytes) + uint32(rapid.IntRange(1, 1000).Draw(rt, "over"))
		}
		binary.BigEndian.PutUint32(header[10:14], length)

		reader := NewFrameReader(newManualClock())
		result := reader.Push(header)

		switch {
		case badVersion:
			// Req 8.6 and 8.7: version is checked first, so it wins even when the length is
			// also wrong.
			if result.Err == nil {
				rt.Fatal("an unsupported version was accepted")
			}
			if result.Err.UnsupportedVersion == nil {
				rt.Fatalf("got %s, want an unsupported version error", result.Err.Error())
			}
			if result.Err.UnsupportedVersion.Declared != int(header[0]) {
				rt.Fatalf("the error names version %d, want %d",
					result.Err.UnsupportedVersion.Declared, header[0])
			}
			if result.Err.UnsupportedVersion.Accepted != ProtocolVersion {
				rt.Fatalf("the error names %d as accepted, want %d",
					result.Err.UnsupportedVersion.Accepted, ProtocolVersion)
			}

		case badLength:
			// Req 8.11: a declared length over the maximum is rejected at the header,
			// before any payload byte is buffered.
			if result.Err == nil {
				rt.Fatalf("a declared length of %d was accepted", length)
			}
			if result.Err.PayloadTooLarge == nil {
				rt.Fatalf("got %s, want a payload-too-large error", result.Err.Error())
			}
			if result.Err.PayloadTooLarge.DeclaredLength != int64(length) {
				rt.Fatalf("the error names %d bytes, want %d",
					result.Err.PayloadTooLarge.DeclaredLength, length)
			}
			if result.Err.PayloadTooLarge.Maximum != MaxPayloadBytes {
				rt.Fatalf("the error names a maximum of %d, want %d",
					result.Err.PayloadTooLarge.Maximum, MaxPayloadBytes)
			}

		default:
			// A well-formed header with an unrecognised type is not an error (Req 8.8).
			if result.Err != nil {
				rt.Fatalf("a well-formed header was rejected: %s", result.Err.Error())
			}
		}
	})
}

// TestProperty6OversizedPayloadsAreRejectedAtEncodeTime covers
// Property 6: Oversized payloads are rejected at encode time.
//
// Validates: Requirements 8.10
func TestProperty6OversizedPayloadsAreRejectedAtEncodeTime(t *testing.T) {
	// The boundary cases are what matter, and each allocates around a megabyte, so they are
	// enumerated rather than generated.
	cases := []struct {
		size     int
		accepted bool
	}{
		{0, true},
		{1, true},
		{MaxPayloadBytes - 1, true},
		{MaxPayloadBytes, true},
		{MaxPayloadBytes + 1, false},
		{MaxPayloadBytes * 2, false},
	}

	for _, c := range cases {
		t.Run(strconv.Itoa(c.size), func(t *testing.T) {
			got := EncodeFrame(Frame{
				ProtocolVersion: ProtocolVersion,
				Type:            uint8(MsgText),
				Payload:         make([]byte, c.size),
			})

			if c.accepted {
				if got.TooLarge != nil {
					t.Fatalf("%d bytes rejected: %s", c.size, got.TooLarge.Error())
				}
				if len(got.Bytes) != HeaderBytes+c.size {
					t.Fatalf("encoded %d bytes, want %d", len(got.Bytes), HeaderBytes+c.size)
				}
				return
			}

			if got.TooLarge == nil {
				t.Fatalf("%d bytes was accepted", c.size)
			}
			if got.Bytes != nil {
				t.Fatal("a rejected frame also returned bytes")
			}
			// Req 8.10: the error names both the length and the maximum.
			if got.TooLarge.PayloadLength != c.size {
				t.Fatalf("the error names %d bytes, want %d", got.TooLarge.PayloadLength, c.size)
			}
			if got.TooLarge.Maximum != MaxPayloadBytes {
				t.Fatalf("the error names a maximum of %d, want %d",
					got.TooLarge.Maximum, MaxPayloadBytes)
			}
			message := got.TooLarge.Error()
			for _, want := range []string{strconv.Itoa(c.size), strconv.Itoa(MaxPayloadBytes)} {
				if !strings.Contains(message, want) {
					t.Fatalf("the error %q omits %q", message, want)
				}
			}
		})
	}
}

// TestProperty7UnrecognisedMessageTypesAreSkipped covers
// Property 7: Unrecognised message types are skipped and the stream continues.
//
// "Skipped" here means the frame is parsed and handed up with its raw code, its payload bytes
// consumed, and the stream still aligned. That is what lets a newer peer send a type this build has
// never heard of without desynchronising the connection.
//
// Validates: Requirements 8.8
func TestProperty7UnrecognisedMessageTypesAreSkipped(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		count := rapid.IntRange(1, 8).Draw(rt, "frameCount")

		var stream []byte
		var sent []Frame
		for i := 0; i < count; i++ {
			// A mix of known and unknown codes, in arbitrary order.
			var code uint8
			if rapid.Bool().Draw(rt, "known"+strconv.Itoa(i)) {
				code = rapid.SampledFrom(knownTypeCodes()).Draw(rt, "knownCode"+strconv.Itoa(i))
			} else {
				code = uint8(rapid.IntRange(14, 255).Draw(rt, "unknownCode"+strconv.Itoa(i)))
			}

			frame := Frame{
				ProtocolVersion: ProtocolVersion,
				Type:            code,
				Sequence:        uint64(i),
				Payload:         rapid.SliceOfN(rapid.Byte(), 0, 64).Draw(rt, "payload"+strconv.Itoa(i)),
			}
			encoded := EncodeFrame(frame)
			if encoded.TooLarge != nil {
				rt.Fatalf("unexpected rejection: %s", encoded.TooLarge.Error())
			}
			sent = append(sent, frame)
			stream = append(stream, encoded.Bytes...)
		}

		reader := NewFrameReader(newManualClock())
		result := reader.Push(stream)
		if result.Err != nil {
			rt.Fatalf("a stream with unknown types failed: %s", result.Err.Error())
		}

		// Every frame arrives, known or not, in stream order.
		if len(result.Frames) != len(sent) {
			rt.Fatalf("decoded %d of %d frames", len(result.Frames), len(sent))
		}
		for i := range sent {
			if !result.Frames[i].Equal(sent[i]) {
				rt.Fatalf("frame %d (type %d) differs", i, sent[i].Type)
			}
			// The raw code survives, which is what lets the router decide.
			if result.Frames[i].Type != sent[i].Type {
				rt.Fatalf("frame %d type %d, want %d", i, result.Frames[i].Type, sent[i].Type)
			}
			_, known := MessageTypeFromCode(sent[i].Type)
			if !known && result.Frames[i].Type < 14 {
				rt.Fatalf("an unknown code was rewritten to %d", result.Frames[i].Type)
			}
		}
		// The stream is still aligned: nothing partial is left over.
		if flushed := reader.FlushIncomplete(); flushed != nil {
			rt.Fatal("a stream of complete frames left something buffered")
		}
	})
}

// TestGoldenWireFormat is task 2.11: a fixed frame in, hex-literal bytes out.
//
// It exists to pin the field layout against an accidental reorder. Every other test here would still
// pass if the sequence and length fields swapped places, because they encode and decode with the same
// code; only a literal catches that, and Req 8.9 makes the layout part of the protocol rather than an
// implementation detail.
//
// Requirements: 8.1, 8.9
func TestGoldenWireFormat(t *testing.T) {
	frame := Frame{
		ProtocolVersion: 1,
		Type:            3, // MsgText
		Sequence:        0x0102030405060708,
		Payload:         []byte("hi"),
	}

	// version | type | sequence (8, big-endian) | length (4, big-endian) | payload
	const want = "01" + "03" + "0102030405060708" + "00000002" + "6869"

	got := EncodeFrame(frame)
	if got.TooLarge != nil {
		t.Fatalf("unexpected rejection: %s", got.TooLarge.Error())
	}
	if hex.EncodeToString(got.Bytes) != want {
		t.Fatalf("wire format changed:\n got  %s\n want %s", hex.EncodeToString(got.Bytes), want)
	}

	// And the same bytes decode back to the same frame.
	reader := NewFrameReader(newManualClock())
	result := reader.Push(got.Bytes)
	if result.Err != nil || len(result.Frames) != 1 {
		t.Fatalf("the golden bytes did not decode: %+v", result)
	}
	if !result.Frames[0].Equal(frame) {
		t.Fatalf("the golden bytes decoded to %+v", result.Frames[0])
	}

	// A zero-payload frame is exactly the header, which is what makes the length field
	// unambiguous at zero.
	empty := EncodeFrame(Frame{ProtocolVersion: 1, Type: 11, Sequence: 0})
	if len(empty.Bytes) != HeaderBytes {
		t.Fatalf("an empty frame is %d bytes, want %d", len(empty.Bytes), HeaderBytes)
	}
	if hex.EncodeToString(empty.Bytes) != "010b"+"0000000000000000"+"00000000" {
		t.Fatalf("the empty frame layout changed: %s", hex.EncodeToString(empty.Bytes))
	}

	// The constants themselves, since the layout above depends on them.
	if HeaderBytes != 14 {
		t.Fatalf("the header is %d bytes, want 14", HeaderBytes)
	}
	if MaxPayloadBytes != 1_048_576 {
		t.Fatalf("the payload maximum is %d, want 1048576", MaxPayloadBytes)
	}
	if ProtocolVersion != 1 {
		t.Fatalf("the protocol version is %d, want 1", ProtocolVersion)
	}
}

// TestMessageTypeCodesAreStable pins the type codes, which are part of the wire protocol: renumbering
// one would silently reinterpret every frame a peer on the old numbering sends.
//
// Requirements: 8.1, 8.8
func TestMessageTypeCodesAreStable(t *testing.T) {
	want := map[uint8]MessageType{
		1: MsgKeyExchangeInit, 2: MsgKeyExchangeResponse, 3: MsgText, 4: MsgClipboard,
		5: MsgTransferOffer, 6: MsgTransferOfferReply, 7: MsgChunk, 8: MsgChunkAck,
		9: MsgDeliveryAck, 10: MsgError, 11: MsgKeepalive, 12: MsgKeepaliveAck,
		13: MsgTransferCancel,
	}
	for code, kind := range want {
		got, known := MessageTypeFromCode(code)
		if !known {
			t.Fatalf("code %d is not recognised", code)
		}
		if got != kind {
			t.Fatalf("code %d maps to %v, want %v", code, got, kind)
		}
	}

	// 0 and everything past the defined set is unknown, which is what Req 8.8 relies on.
	for _, code := range []uint8{0, 14, 15, 100, 255} {
		if _, known := MessageTypeFromCode(code); known {
			t.Fatalf("code %d is recognised but should not be", code)
		}
	}
}

// TestFrameEqualComparesPayloadContents guards the helper the round-trip properties rely on: a shallow
// comparison would make them pass on a reader that returned a stale buffer.
//
// Requirements: 8.4
func TestFrameEqualComparesPayloadContents(t *testing.T) {
	a := Frame{ProtocolVersion: 1, Type: 3, Sequence: 9, Payload: []byte("abc")}
	b := Frame{ProtocolVersion: 1, Type: 3, Sequence: 9, Payload: []byte("abc")}
	if !a.Equal(b) {
		t.Fatal("frames with equal contents compared unequal")
	}

	for _, different := range []Frame{
		{ProtocolVersion: 2, Type: 3, Sequence: 9, Payload: []byte("abc")},
		{ProtocolVersion: 1, Type: 4, Sequence: 9, Payload: []byte("abc")},
		{ProtocolVersion: 1, Type: 3, Sequence: 10, Payload: []byte("abc")},
		{ProtocolVersion: 1, Type: 3, Sequence: 9, Payload: []byte("abd")},
		{ProtocolVersion: 1, Type: 3, Sequence: 9, Payload: []byte("ab")},
		{ProtocolVersion: 1, Type: 3, Sequence: 9},
	} {
		if a.Equal(different) {
			t.Fatalf("frames compared equal despite differing: %+v", different)
		}
	}

	// nil and empty payloads are the same frame on the wire, since both encode a length of zero.
	nilPayload := Frame{ProtocolVersion: 1, Type: 3, Sequence: 9}
	emptyPayload := Frame{ProtocolVersion: 1, Type: 3, Sequence: 9, Payload: []byte{}}
	if !nilPayload.Equal(emptyPayload) {
		t.Fatal("a nil payload and an empty payload compared unequal")
	}
}

// TestReaderDiscardsTheStreamAfterAnError pins the recovery rule: once a frame is rejected the stream
// position is no longer trustworthy, so the reader empties itself rather than trying to resynchronise
// on what might be payload bytes.
//
// Requirements: 8.5, 8.6, 8.11
func TestReaderDiscardsTheStreamAfterAnError(t *testing.T) {
	good := EncodeFrame(Frame{
		ProtocolVersion: ProtocolVersion, Type: 3, Sequence: 1, Payload: []byte("first"),
	}).Bytes

	// A frame declaring an unsupported version, followed by a perfectly good frame.
	bad := make([]byte, HeaderBytes)
	bad[0] = ProtocolVersion + 1
	bad[1] = 3
	binary.BigEndian.PutUint32(bad[10:14], 0)

	stream := append(append(append([]byte(nil), good...), bad...), good...)

	reader := NewFrameReader(newManualClock())
	result := reader.Push(stream)

	// The frame before the error is still delivered: it was complete and correct on the wire.
	if len(result.Frames) != 1 {
		t.Fatalf("delivered %d frames before the error, want 1", len(result.Frames))
	}
	if string(result.Frames[0].Payload) != "first" {
		t.Fatalf("the delivered frame carries %q", result.Frames[0].Payload)
	}
	if result.Err == nil || result.Err.UnsupportedVersion == nil {
		t.Fatalf("got %+v, want an unsupported version error", result.Err)
	}

	// Everything after the error is gone, and the reader is empty.
	if flushed := reader.FlushIncomplete(); flushed != nil {
		t.Fatalf("the reader kept bytes after an error: %+v", flushed)
	}
	// It works again from a clean state.
	next := reader.Push(good)
	if next.Err != nil || len(next.Frames) != 1 {
		t.Fatalf("the reader did not recover: %+v", next)
	}
}
