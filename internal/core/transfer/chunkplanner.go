package transfer

import "fmt"

// ChunkRef locates one Chunk of a Transfer leg.
//
// ByteOffset is absolute and is what makes a rebind work. Req 3.5 resumes at the
// Chunk size of the *new* Transport, so a Chunk index alone no longer identifies
// bytes: index 5 is offset 327,680 at the LAN size of 64 KiB and offset 2,560 at the
// Bluetooth size of 512. A Transfer is therefore a series of legs, each with its own
// base offset, Chunk size, and count, and every Chunk states where in the file it
// belongs.
//
// ChunkIndex and TotalChunks are scoped to the leg, which is what Req 7.2 puts on the
// wire. A receiver uses ByteOffset to place the bytes and the index pair to know how
// far through the current leg it is.
type ChunkRef struct {
	ByteOffset  int64
	Length      int
	ChunkIndex  int
	TotalChunks int
}

// EndOffset is the first byte after this Chunk.
func (c ChunkRef) EndOffset() int64 { return c.ByteOffset + int64(c.Length) }

// PlanError reports chunk plan inputs that cannot describe a real slice of a file.
type PlanError struct {
	FileSize   int64
	FromOffset int64
	ChunkSize  int
	Reason     string
}

func (e *PlanError) Error() string {
	return fmt.Sprintf("cannot plan chunks for file size %d from offset %d at chunk size %d: %s",
		e.FileSize, e.FromOffset, e.ChunkSize, e.Reason)
}

// PlanChunks slices [fromOffset, fileSize) into ascending Chunks of at most chunkSize
// bytes. It serves all three cases that need a plan: the first leg with fromOffset 0
// (Req 7.2), a resume from the last contiguously acknowledged offset (Req 7.8), and a
// re-slice at a new Chunk size after a Transport rebind (Req 3.5).
//
// The returned plan always satisfies, by construction: indices run 0..n-1, every ref
// carries the same TotalChunks, byte offsets strictly increase, consecutive refs abut
// with no gap and no overlap, and only the final ref may be shorter than chunkSize.
//
// It returns an error rather than panicking on bad inputs. The design sketch panicked
// on the grounds that the caller guarantees the preconditions, but fromOffset comes
// from acknowledgement state and chunkSize from the active Transport, and both are
// values a rebind can change mid-transfer. A panic there would take down a Peer_Node
// holding seven other healthy Sessions, which Req 4.3 exists to prevent.
//
// A fromOffset equal to fileSize is not an error: it means the file is fully
// acknowledged, and the empty plan is the right answer.
func PlanChunks(fileSize, fromOffset int64, chunkSize int) ([]ChunkRef, error) {
	switch {
	case chunkSize <= 0:
		return nil, &PlanError{fileSize, fromOffset, chunkSize, "chunk size must be positive"}
	case fileSize < 0:
		return nil, &PlanError{fileSize, fromOffset, chunkSize, "file size must not be negative"}
	case fromOffset < 0:
		return nil, &PlanError{fileSize, fromOffset, chunkSize, "offset must not be negative"}
	case fromOffset > fileSize:
		return nil, &PlanError{fileSize, fromOffset, chunkSize, "offset is past the end of the file"}
	}

	remaining := fileSize - fromOffset
	total := int((remaining + int64(chunkSize) - 1) / int64(chunkSize))

	refs := make([]ChunkRef, 0, total)
	for i := 0; i < total; i++ {
		offset := fromOffset + int64(i)*int64(chunkSize)
		length := int64(chunkSize)
		if end := fileSize - offset; end < length {
			length = end
		}
		refs = append(refs, ChunkRef{
			ByteOffset:  offset,
			Length:      int(length),
			ChunkIndex:  i,
			TotalChunks: total,
		})
	}
	return refs, nil
}

// PlanResume is the resume and rebind entry point: it plans from the byte offset
// following the last contiguously acknowledged Chunk (Req 7.8, 3.5). It is a named
// function rather than a comment on PlanChunks so the two callers that must use the
// contiguous watermark, rather than the acknowledged byte count, cannot pick the
// wrong one.
//
// The distinction matters. With Chunks 0 and 2 acknowledged and 1 outstanding, the
// acknowledged byte count is two Chunks' worth but the contiguous watermark is one:
// resuming from the byte count would skip Chunk 1 and produce a file with a hole in
// it that still passed a length check.
func PlanResume(fileSize int64, progress *TransferProgress, chunkSize int) ([]ChunkRef, error) {
	if progress == nil {
		return PlanChunks(fileSize, 0, chunkSize)
	}
	return PlanChunks(fileSize, progress.ContiguousAckedThrough(), chunkSize)
}
