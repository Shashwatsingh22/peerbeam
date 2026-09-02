package transfer

import (
	"bytes"
	"testing"
	"time"

	"pgregory.net/rapid"
)

var baseTime = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

// manualClock is the injected time source. The 10-minute resume retention of Req 7.8
// and 7.13 is checked by advancing it.
type manualClock struct{ now time.Time }

func newManualClock() *manualClock             { return &manualClock{now: baseTime} }
func (c *manualClock) Now() time.Time          { return c.now }
func (c *manualClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// chunkSizeChoices covers the two real Transport sizes from Req 7.10 plus awkward
// values: 1 forces one chunk per byte, and a size larger than the file forces the
// single-short-chunk case.
var chunkSizeChoices = []int{1, 2, 3, 7, 512, 1024, 65_536}

// assertPlanShape checks everything Property 27 says a plan must satisfy, for a plan
// covering [fromOffset, fileSize).
func assertPlanShape(t rapid.TB, plan []ChunkRef, fileSize, fromOffset int64, chunkSize int) {
	t.Helper()

	remaining := fileSize - fromOffset
	wantTotal := int((remaining + int64(chunkSize) - 1) / int64(chunkSize))
	if len(plan) != wantTotal {
		t.Fatalf("plan has %d chunks, want %d (size %d from %d at %d)",
			len(plan), wantTotal, fileSize, fromOffset, chunkSize)
	}
	if len(plan) == 0 {
		return
	}

	for i, ref := range plan {
		// Indices run 0..n-1 with a consistent total.
		if ref.ChunkIndex != i {
			t.Fatalf("chunk at position %d carries index %d", i, ref.ChunkIndex)
		}
		if ref.TotalChunks != wantTotal {
			t.Fatalf("chunk %d declares total %d, want %d", i, ref.TotalChunks, wantTotal)
		}
		// Only the final chunk may be short, and no chunk may be empty or over size.
		if ref.Length <= 0 || ref.Length > chunkSize {
			t.Fatalf("chunk %d is %d bytes, want 1..%d", i, ref.Length, chunkSize)
		}
		if i < len(plan)-1 && ref.Length != chunkSize {
			t.Fatalf("chunk %d is short at %d bytes but is not the last", i, ref.Length)
		}
		// Strictly increasing offsets, abutting with no gap and no overlap.
		if i == 0 {
			if ref.ByteOffset != fromOffset {
				t.Fatalf("first chunk starts at %d, want %d", ref.ByteOffset, fromOffset)
			}
			continue
		}
		if ref.ByteOffset <= plan[i-1].ByteOffset {
			t.Fatalf("chunk %d starts at %d, not after %d", i, ref.ByteOffset, plan[i-1].ByteOffset)
		}
		if ref.ByteOffset != plan[i-1].EndOffset() {
			t.Fatalf("chunk %d starts at %d but chunk %d ended at %d",
				i, ref.ByteOffset, i-1, plan[i-1].EndOffset())
		}
	}

	// The plan reaches exactly the end of the file.
	if last := plan[len(plan)-1]; last.EndOffset() != fileSize {
		t.Fatalf("plan ends at %d, want the file size %d", last.EndOffset(), fileSize)
	}
}

// TestProperty27ChunkPlanCoversTheFileExactlyOnce covers
// Property 27: The chunk plan covers a file exactly once and reassembles to the
// original bytes.
//
// The 64 GiB upper bound of the requirement is exercised by planning against a large
// declared file size without materialising it; the reassembly half runs on small
// content, since writing chunks at their offsets is size-independent.
//
// Validates: Requirements 7.1, 7.2, 7.4, 7.8, 7.10, 3.5
func TestProperty27ChunkPlanCoversTheFileExactlyOnce(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		content := rapid.SliceOfN(rapid.Byte(), 1, 200).Draw(rt, "content")
		fileSize := int64(len(content))
		firstChunkSize := rapid.SampledFrom(chunkSizeChoices).Draw(rt, "firstChunkSize")

		// First leg from offset 0 (Req 7.2).
		plan, err := PlanChunks(fileSize, 0, firstChunkSize)
		if err != nil {
			rt.Fatalf("planning the first leg: %v", err)
		}
		assertPlanShape(rt, plan, fileSize, 0, firstChunkSize)

		// Acknowledge an arbitrary subset, in an arbitrary order, so the contiguous
		// watermark is genuinely exercised rather than always being the whole prefix.
		progress := NewTransferProgress(fileSize)
		ackOrder := rapid.Permutation(plan).Draw(rt, "ackOrder")
		acknowledged := map[int64]bool{}
		for i, ref := range ackOrder {
			if rapid.Bool().Draw(rt, "ack"+string(rune('a'+i%26))) {
				progress.OnAck(ref.ByteOffset, ref.Length)
				acknowledged[ref.ByteOffset] = true
			}
		}

		// The watermark is the end of the unbroken prefix, computed independently.
		var wantWatermark int64
		for _, ref := range plan {
			if !acknowledged[ref.ByteOffset] {
				break
			}
			wantWatermark = ref.EndOffset()
		}
		if got := progress.ContiguousAckedThrough(); got != wantWatermark {
			rt.Fatalf("contiguous watermark %d, want %d", got, wantWatermark)
		}

		// Acknowledged bytes count everything, including past a gap (Req 7.3).
		var wantAckedBytes int64
		for _, ref := range plan {
			if acknowledged[ref.ByteOffset] {
				wantAckedBytes += int64(ref.Length)
			}
		}
		if got := progress.AcknowledgedBytes(); got != wantAckedBytes {
			rt.Fatalf("acknowledged bytes %d, want %d", got, wantAckedBytes)
		}

		// Resume at a possibly different chunk size (Req 3.5, 7.8).
		resumeChunkSize := rapid.SampledFrom(chunkSizeChoices).Draw(rt, "resumeChunkSize")
		resume, err := PlanResume(fileSize, progress, resumeChunkSize)
		if err != nil {
			rt.Fatalf("planning the resume leg: %v", err)
		}
		assertPlanShape(rt, resume, fileSize, wantWatermark, resumeChunkSize)

		// Together, the acknowledged prefix and the resume plan cover the file exactly
		// once: reassembly writes each chunk at its stated offset, in an arbitrary
		// delivery order, and every byte is written exactly once.
		assembled := make([]byte, fileSize)
		writes := make([]int, fileSize)

		// The prefix the receiver already holds.
		copy(assembled[:wantWatermark], content[:wantWatermark])
		for i := int64(0); i < wantWatermark; i++ {
			writes[i]++
		}
		// The resume leg, delivered out of order.
		for _, ref := range rapid.Permutation(resume).Draw(rt, "deliveryOrder") {
			copy(assembled[ref.ByteOffset:ref.EndOffset()],
				content[ref.ByteOffset:ref.EndOffset()])
			for i := ref.ByteOffset; i < ref.EndOffset(); i++ {
				writes[i]++
			}
		}
		for i, n := range writes {
			if n != 1 {
				rt.Fatalf("byte %d written %d times, want exactly 1", i, n)
			}
		}
		if !bytes.Equal(assembled, content) {
			rt.Fatal("reassembled content differs from the original")
		}

		// Req 7.4: the digest of the reassembled content matches the offer.
		offer := TransferOffer{
			TransferId: "abc",
			FileName:   "f.bin",
			ByteSize:   fileSize,
			SHA256:     DigestOf(content),
		}
		if got := VerifyAssembled(offer, assembled, nil); !got.Verified {
			rt.Fatalf("digest mismatch on a faithful reassembly: %s", got.Failure.Error())
		}
	})
}

// TestPlanChunksAtTheRequirementSizes pins the two Chunk sizes of Req 7.10 against a
// declared 64 GiB file, without allocating one.
//
// Requirements: 7.10, 7.1
func TestPlanChunksAtTheRequirementSizes(t *testing.T) {
	const lanChunk, btChunk = 65_536, 512

	// A file at the maximum accepted size divides evenly by both sizes, so the plan is
	// exact and the counts are checkable.
	plan, err := PlanChunks(FileMaxBytes, 0, lanChunk)
	if err != nil {
		t.Fatalf("planning 64 GiB at the LAN size: %v", err)
	}
	if want := int(FileMaxBytes / lanChunk); len(plan) != want {
		t.Fatalf("64 GiB at 64 KiB is %d chunks, want %d", len(plan), want)
	}
	if plan[0].ByteOffset != 0 || plan[0].Length != lanChunk {
		t.Fatalf("first LAN chunk is %+v", plan[0])
	}
	if last := plan[len(plan)-1]; last.EndOffset() != FileMaxBytes {
		t.Fatalf("last LAN chunk ends at %d, want %d", last.EndOffset(), FileMaxBytes)
	}

	// Index 5 means a different byte offset on each Transport, which is exactly why
	// ChunkRef carries an absolute offset.
	lanLeg, _ := PlanChunks(1_000_000, 0, lanChunk)
	btLeg, _ := PlanChunks(1_000_000, 0, btChunk)
	if lanLeg[5].ByteOffset != 5*lanChunk {
		t.Fatalf("LAN chunk 5 is at %d, want %d", lanLeg[5].ByteOffset, 5*lanChunk)
	}
	if btLeg[5].ByteOffset != 5*btChunk {
		t.Fatalf("BT chunk 5 is at %d, want %d", btLeg[5].ByteOffset, 5*btChunk)
	}
	if lanLeg[5].ByteOffset == btLeg[5].ByteOffset {
		t.Fatal("the two transports agree on chunk 5's offset, which defeats the test")
	}
}

// TestPlanChunksRejectsImpossibleInputs checks that bad inputs return an error rather
// than panicking. A panic here would take down a node holding seven other healthy
// sessions, which Req 4.3 exists to prevent.
//
// Requirements: 4.3, 7.2
func TestPlanChunksRejectsImpossibleInputs(t *testing.T) {
	cases := map[string]struct {
		fileSize, fromOffset int64
		chunkSize            int
	}{
		"zero chunk size":     {100, 0, 0},
		"negative chunk size": {100, 0, -1},
		"negative file size":  {-1, 0, 10},
		"negative offset":     {100, -1, 10},
		"offset past the end": {100, 101, 10},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := PlanChunks(c.fileSize, c.fromOffset, c.chunkSize)
			if err == nil {
				t.Fatalf("got %d chunks, want an error", len(got))
			}
			if got != nil {
				t.Fatal("a failed plan also returned chunks")
			}
			if err.Error() == "" {
				t.Fatal("error carries no message")
			}
		})
	}
}

// TestPlanChunksAtTheEndOfTheFileIsEmptyNotAnError checks the fully-acknowledged case:
// a resume with nothing left to send is a normal outcome.
//
// Requirements: 7.8
func TestPlanChunksAtTheEndOfTheFileIsEmptyNotAnError(t *testing.T) {
	plan, err := PlanChunks(100, 100, 10)
	if err != nil {
		t.Fatalf("planning from the end of the file: %v", err)
	}
	if len(plan) != 0 {
		t.Fatalf("got %d chunks, want none", len(plan))
	}
}

// TestPlanResumeUsesTheContiguousWatermarkNotTheByteCount is the distinction that keeps
// a resumed file intact: with a hole in the acknowledgements, resuming from the byte
// count would skip real bytes.
//
// Requirements: 7.8, 3.5
func TestPlanResumeUsesTheContiguousWatermarkNotTheByteCount(t *testing.T) {
	progress := NewTransferProgress(30)
	progress.OnAck(0, 10)  // chunk 0
	progress.OnAck(20, 10) // chunk 2, leaving a hole at 10..20

	if got := progress.AcknowledgedBytes(); got != 20 {
		t.Fatalf("acknowledged bytes %d, want 20", got)
	}
	if got := progress.ContiguousAckedThrough(); got != 10 {
		t.Fatalf("contiguous watermark %d, want 10", got)
	}

	plan, err := PlanResume(30, progress, 10)
	if err != nil {
		t.Fatalf("planning the resume: %v", err)
	}
	if len(plan) != 2 || plan[0].ByteOffset != 10 {
		t.Fatalf("resume plan %+v, want two chunks starting at offset 10", plan)
	}
	// The already-acknowledged chunk 2 is sent again, which is the deliberate trade:
	// bandwidth over a file with a hole in it.
	if plan[1].ByteOffset != 20 {
		t.Fatalf("resume plan skipped the hole: %+v", plan)
	}
}

// TestTransferProgressIgnoresNonsenseAcknowledgements checks that a malformed
// acknowledgement cannot inflate the watermark and make a resume skip real bytes.
//
// Requirements: 7.8
func TestTransferProgressIgnoresNonsenseAcknowledgements(t *testing.T) {
	p := NewTransferProgress(100)

	p.OnAck(0, 0)    // zero length
	p.OnAck(0, -5)   // negative length
	p.OnAck(-1, 10)  // negative offset
	p.OnAck(100, 10) // at the end of the file
	p.OnAck(500, 10) // past the end
	if got := p.ContiguousAckedThrough(); got != 0 {
		t.Fatalf("watermark moved to %d on nonsense input", got)
	}
	if got := p.AcknowledgedBytes(); got != 0 {
		t.Fatalf("acknowledged %d bytes on nonsense input", got)
	}

	// An acknowledgement running past the end is clamped rather than dropped, since
	// the bytes up to the end are real.
	p.OnAck(90, 50)
	if got := p.AcknowledgedBytes(); got != 10 {
		t.Fatalf("acknowledged %d bytes, want 10 after clamping", got)
	}
}

// TestTransferProgressMergesOverlappingAcknowledgements checks that a re-acknowledged or
// overlapping range does not double-count, which would let AcknowledgedBytes exceed the
// file size and report over 100% progress.
//
// Requirements: 7.3, 7.8
func TestTransferProgressMergesOverlappingAcknowledgements(t *testing.T) {
	p := NewTransferProgress(100)
	p.OnAck(0, 50)
	p.OnAck(0, 50)  // exact duplicate
	p.OnAck(25, 50) // overlapping
	p.OnAck(75, 25) // abutting

	if got := p.AcknowledgedBytes(); got != 100 {
		t.Fatalf("acknowledged %d bytes for a 100-byte file", got)
	}
	if got := p.ContiguousAckedThrough(); got != 100 {
		t.Fatalf("watermark %d, want 100", got)
	}
	if !p.Complete() {
		t.Fatal("fully acknowledged transfer is not complete")
	}
}
