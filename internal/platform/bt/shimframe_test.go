package bt

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// The shim frame protocol property tests (Properties 42-45).
//
// These exercise the framing layer of ShimBluetoothBridge against a pipe, with no helper process
// and no radio. The bridge multiplexes every Bluetooth stream over one framed pipe, so the framing
// is where a bug would silently cross two conversations or hand a hostile length to an allocator.
//
// The tests are white-box (package bt) so they can inject a reader into b.stdout and drive
// readLoop directly, which is the same seam Start would fill with the helper's stdout.

// encodeShimFrame produces the 9-byte-header wire form writeFrame produces, so a test can build a
// stream of frames to feed back through readLoop.
func encodeShimFrame(kind uint8, streamId uint32, payload []byte) []byte {
	frame := make([]byte, ShimFrameHeaderBytes+len(payload))
	frame[0] = kind
	binary.BigEndian.PutUint32(frame[1:5], streamId)
	binary.BigEndian.PutUint32(frame[5:9], uint32(len(payload)))
	copy(frame[ShimFrameHeaderBytes:], payload)
	return frame
}

// newReadLoopBridge builds a bridge wired to read from r, and starts its read loop. It stands in
// for a started bridge whose helper is writing r.
func newReadLoopBridge(r io.Reader) *ShimBluetoothBridge {
	b := NewShimBluetoothBridge("unused")
	b.mu.Lock()
	b.stdout = bufio.NewReaderSize(r, ShimMaxPayloadBytes)
	b.started = true
	b.available = true
	b.mu.Unlock()
	go b.readLoop()
	return b
}

// Property 42: shim frame round trip under arbitrary segmentation.
//
// Any sequence of frames, written to the pipe and cut at any arbitrary set of byte offsets -
// including mid-header - is read back as the same frames in the same order with the same stream
// identifiers. This is the shim protocol's analogue of the wire codec's segmentation property, and
// it is what makes a partial read on a real pipe a non-event.
//
// Scan-result frames are used as the carrier because dispatch routes them to a channel a test can
// drain in order, so the property observes reframing directly.
//
// Requirements: 1.7
func TestPropertyShimFrameRoundTripUnderSegmentation(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		count := rapid.IntRange(1, 12).Draw(rt, "frames")

		type frame struct {
			deviceID string
			record   []byte
		}
		frames := make([]frame, count)
		var stream []byte
		for i := 0; i < count; i++ {
			deviceID := fmt.Sprintf("device-%d", i)
			record := []byte(rapid.StringMatching(`[a-z0-9]{0,40}`).Draw(rt, fmt.Sprintf("rec%d", i)))
			frames[i] = frame{deviceID: deviceID, record: record}
			// scanResult payload is deviceID, a null byte, then the record.
			payload := append([]byte(deviceID+"\x00"), record...)
			stream = append(stream, encodeShimFrame(shimKindScanResult, 0, payload)...)
		}

		pr, pw := io.Pipe()
		b := newReadLoopBridge(pr)
		defer b.Stop()

		// A scan must be in progress for scanResult frames to be delivered.
		b.mu.Lock()
		results := make(chan DiscoveredBtPeer, count)
		b.scanResults = results
		b.mu.Unlock()

		// Write the whole stream in arbitrarily sized chunks, including cuts inside a header.
		go func() {
			offset := 0
			for offset < len(stream) {
				remaining := len(stream) - offset
				chunk := rapid.IntRange(1, remaining).Draw(rt, fmt.Sprintf("chunk%d", offset))
				pw.Write(stream[offset : offset+chunk])
				offset += chunk
			}
		}()

		for i := 0; i < count; i++ {
			select {
			case got := <-results:
				if got.DeviceID != frames[i].deviceID {
					rt.Fatalf("frame %d device id is %q, want %q", i, got.DeviceID, frames[i].deviceID)
				}
				if string(got.Record) != string(frames[i].record) {
					rt.Fatalf("frame %d record is %q, want %q", i, got.Record, frames[i].record)
				}
			case <-time.After(2 * time.Second):
				rt.Fatalf("frame %d never arrived; reframing lost or reordered it", i)
			}
		}
	})
}

// Property 43: stream identifier spaces never collide.
//
// The bridge numbers outbound streams from 1 upward; the shim numbers inbound streams with the high
// bit set. The property is that for any interleaving of allocations, no identifier is ever handed
// to two live streams. It is asserted over the allocation rule rather than by running two radios.
//
// Requirements: 1.7
func TestPropertyShimStreamIdSpacesNeverCollide(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		outboundCount := rapid.IntRange(0, 50).Draw(rt, "outbound")
		inboundCount := rapid.IntRange(0, 50).Draw(rt, "inbound")

		// Outbound ids are what Connect allocates: nextStreamId incremented from 0.
		b := NewShimBluetoothBridge("unused")
		outbound := map[uint32]bool{}
		for i := 0; i < outboundCount; i++ {
			b.mu.Lock()
			b.nextStreamId++
			id := b.nextStreamId
			b.mu.Unlock()
			if outbound[id] {
				rt.Fatalf("outbound id %d allocated twice", id)
			}
			outbound[id] = true
		}

		// Inbound ids are what the shim assigns: the high bit is always set (see the shim's
		// shimInboundStreamIdBase). Model that rule and check it never lands in the outbound set.
		const inboundBase uint32 = 0x8000_0000
		inbound := map[uint32]bool{}
		for i := 0; i < inboundCount; i++ {
			id := inboundBase + uint32(i) + 1
			if inbound[id] {
				rt.Fatalf("inbound id %d allocated twice", id)
			}
			inbound[id] = true
		}

		for id := range outbound {
			if inbound[id] {
				rt.Fatalf("id %d is in both spaces", id)
			}
			// Outbound ids never have the high bit set, given the counts a test can reach.
			if id&inboundBase != 0 {
				rt.Fatalf("outbound id %d has the high bit set, colliding with the inbound space", id)
			}
		}
	})
}

// Property 44: a shim failure fails every open stream.
//
// When the pipe feeding readLoop closes (the helper died) or a frame declares an oversized payload
// (the stream desynchronised), every open stream must return an error rather than blocking, so the
// sessions above can rebind instead of hanging. The property asserts the absence of a hang.
//
// Requirements: 1.7
func TestPropertyShimFailureFailsEveryStream(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		streamCount := rapid.IntRange(1, 8).Draw(rt, "streams")

		pr, pw := io.Pipe()
		b := newReadLoopBridge(pr)
		defer b.Stop()

		// Register some open streams the way Connect and Accept would.
		streams := make([]*shimStream, streamCount)
		b.mu.Lock()
		for i := 0; i < streamCount; i++ {
			id := uint32(i + 1)
			s := newShimStream(b, id)
			b.streams[id] = s
			streams[i] = s
		}
		b.mu.Unlock()

		// Fail the shim: either close the pipe, or feed an oversized length. Both must fail
		// every stream.
		failByClose := rapid.Bool().Draw(rt, "close")
		if failByClose {
			pw.Close()
		} else {
			header := make([]byte, ShimFrameHeaderBytes)
			header[0] = shimKindData
			binary.BigEndian.PutUint32(header[5:9], ShimMaxPayloadBytes+1)
			go func() { pw.Write(header); pw.Close() }()
		}

		// Every stream's Read must return, with an error, rather than block forever.
		for i, s := range streams {
			done := make(chan error, 1)
			go func(s *shimStream) {
				buf := make([]byte, 16)
				_, err := s.Read(buf)
				done <- err
			}(s)
			select {
			case err := <-done:
				if err == nil {
					rt.Fatalf("stream %d read returned nil after a shim failure", i)
				}
			case <-time.After(2 * time.Second):
				rt.Fatalf("stream %d read blocked after a shim failure", i)
			}
		}
	})
}

// Property 45: an oversized declared payload is refused without allocating.
//
// A frame header declaring a length above the maximum must be rejected before the payload is read,
// so a corrupt or hostile length cannot make the node allocate on demand. The observable
// consequence is that the read loop tears the bridge down - it does not read the declared bytes -
// so a follow-on stream fails rather than the process growing without bound.
//
// Requirements: 1.7
func TestPropertyShimOversizedLengthRefusedWithoutAllocating(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		over := uint32(ShimMaxPayloadBytes) + uint32(rapid.IntRange(1, 1_000_000).Draw(rt, "over"))

		pr, pw := io.Pipe()
		b := newReadLoopBridge(pr)
		defer b.Stop()

		// One open stream, so we can observe the teardown failing it.
		b.mu.Lock()
		s := newShimStream(b, 1)
		b.streams[1] = s
		b.mu.Unlock()

		// A header declaring an oversized payload, and not one byte of that payload. If readLoop
		// tried to read the declared length it would block here forever waiting for bytes that
		// never come; instead it must refuse on the header alone.
		header := make([]byte, ShimFrameHeaderBytes)
		header[0] = shimKindData
		binary.BigEndian.PutUint32(header[1:5], 1)
		binary.BigEndian.PutUint32(header[5:9], over)
		go func() { pw.Write(header) }()

		done := make(chan error, 1)
		go func() {
			buf := make([]byte, 16)
			_, err := s.Read(buf)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				rt.Fatal("the stream was not failed after an oversized length was declared")
			}
		case <-time.After(2 * time.Second):
			rt.Fatal("readLoop blocked, so it tried to read the oversized payload rather than refusing it")
		}
	})
}
