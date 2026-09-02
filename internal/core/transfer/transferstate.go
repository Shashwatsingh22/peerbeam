package transfer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"time"
)

// File size bounds and Transfer timings, fixed by Requirement 7.
const (
	// FileMinBytes rejects an empty file (Req 7.1, 7.12).
	FileMinBytes int64 = 1
	// FileMaxBytes is 64 GiB (Req 7.1, 7.12).
	FileMaxBytes int64 = 68_719_476_736
	// MaxResendAttempts is the resend ceiling per Chunk (Req 7.7, 7.13).
	MaxResendAttempts = 5
)

const (
	// ChunkAckTimeout is how long a Chunk may go unacknowledged before it is
	// resent (Req 7.7).
	ChunkAckTimeout = 10 * time.Second
	// OfferTimeout is how long an offer waits for an accept or a decline
	// (Req 7.11).
	OfferTimeout = 60 * time.Second
	// CancelDeadline is how quickly a cancel must stop Chunk sending (Req 7.9).
	CancelDeadline = 2 * time.Second
	// ResumeRetention is how long acknowledged-Chunk state survives for a resume
	// (Req 7.8, 7.13).
	ResumeRetention = 10 * time.Minute
	// ProgressInterval is the reporting cadence (Req 7.3).
	ProgressInterval = time.Second
)

// TransferIdBytes is the width of a transfer identifier. As with a SessionId, 128 bits
// is chosen so the value can appear in a report without being guessable and cannot
// collide across restarts.
const TransferIdBytes = 16

// TransferId identifies one Transfer across offers, Chunks, acknowledgements, a
// cancel, and a resume. Req 7.5, 7.9, 7.11, 7.12 and 7.13 all require it to be named
// in a report, so it survives the whole lifecycle including failure.
type TransferId string

func (id TransferId) String() string { return string(id) }

// NewTransferId draws a fresh identifier from crypto/rand as lowercase hex.
func NewTransferId() (TransferId, error) { return newTransferIdFrom(rand.Reader) }

func newTransferIdFrom(entropy io.Reader) (TransferId, error) {
	raw := make([]byte, TransferIdBytes)
	if _, err := io.ReadFull(entropy, raw); err != nil {
		return "", fmt.Errorf("draw transfer id: %w", err)
	}
	return TransferId(hex.EncodeToString(raw)), nil
}

// TransferOffer is everything the receiver needs to decide on a Transfer and later to
// verify it (Req 7.1). The digest is in the offer rather than sent after the last
// Chunk so the receiver can verify without trusting a value that arrives alongside the
// content it is meant to check.
type TransferOffer struct {
	TransferId TransferId
	FileName   string
	ByteSize   int64
	SHA256     []byte
}

// UnsupportedFileSize reports a file outside the accepted range, naming the measured
// size and the range, which is what Req 7.12 requires.
type UnsupportedFileSize struct {
	MeasuredBytes int64
	Min, Max      int64
}

func (u *UnsupportedFileSize) Error() string {
	return fmt.Sprintf("file is %d bytes, accepted range is %d..%d bytes",
		u.MeasuredBytes, u.Min, u.Max)
}

// CheckFileSize validates a file size before an offer is built (Req 7.1, 7.12). It is
// separate from BuildOffer so the rejection can be reported without a digest having
// been computed: hashing 64 GiB to discover the file is too big would be absurd.
func CheckFileSize(byteSize int64) *UnsupportedFileSize {
	if byteSize < FileMinBytes || byteSize > FileMaxBytes {
		return &UnsupportedFileSize{MeasuredBytes: byteSize, Min: FileMinBytes, Max: FileMaxBytes}
	}
	return nil
}

// DigestOf is the SHA-256 used for both the offer and the integrity check, so the two
// can never disagree about the algorithm.
func DigestOf(content []byte) []byte {
	sum := sha256.Sum256(content)
	return sum[:]
}

// OfferOutcome is a tagged result of an offer's fate: exactly one field is set.
type OfferOutcome struct {
	Accepted bool
	// Declined is Req 7.11: the Peer said no. No Chunk is sent.
	Declined bool
	// TimedOut is Req 7.11: 60 seconds passed with no answer either way.
	TimedOut bool
	// Unsupported is Req 7.12: the file size was out of range, so no offer was
	// sent at all.
	Unsupported *UnsupportedFileSize
}

// OfferOutcomeKind names the branch an outcome took.
type OfferOutcomeKind uint8

const (
	OfferAccepted OfferOutcomeKind = iota
	OfferDeclined
	OfferTimedOut
	OfferUnsupportedSize
	OfferInvalid
)

func (k OfferOutcomeKind) String() string {
	switch k {
	case OfferAccepted:
		return "accepted"
	case OfferDeclined:
		return "declined"
	case OfferTimedOut:
		return "offer timed out"
	case OfferUnsupportedSize:
		return "unsupported file size"
	default:
		return "invalid"
	}
}

// Kind reports which single branch of the outcome holds.
func (o OfferOutcome) Kind() OfferOutcomeKind {
	switch {
	case o.Accepted:
		return OfferAccepted
	case o.Declined:
		return OfferDeclined
	case o.TimedOut:
		return OfferTimedOut
	case o.Unsupported != nil:
		return OfferUnsupportedSize
	default:
		return OfferInvalid
	}
}

// MaySendChunks reports whether the Transfer may put Chunks on the wire. Only an
// accepted offer may, which is the whole of Req 7.11 and 7.12: a declined offer, a
// timed-out offer, and an out-of-range file all send nothing.
func (o OfferOutcome) MaySendChunks() bool { return o.Accepted }

// Reason renders the outcome for the report Req 7.11 and 7.12 require.
func (o OfferOutcome) Reason() string {
	switch o.Kind() {
	case OfferAccepted:
		return ""
	case OfferDeclined:
		return "peer declined the offer"
	case OfferTimedOut:
		return fmt.Sprintf("no accept or decline within %s", OfferTimeout)
	case OfferUnsupportedSize:
		return o.Unsupported.Error()
	default:
		return "invalid offer outcome"
	}
}

// offsetRange is a half-open acknowledged byte range.
type offsetRange struct{ start, endExclusive int64 }

// TransferProgress tracks which bytes the receiver has acknowledged.
//
// It stores merged ranges rather than a set of Chunk indices, because a Transfer can
// change Chunk size partway through (Req 3.5) and an index means nothing across that
// boundary. Ranges are the one representation that survives a re-slice: they are
// stated in file offsets, which no Transport can reinterpret.
//
// Not safe for concurrent use. One Transfer is driven by one goroutine.
type TransferProgress struct {
	fileSize    int64
	ackedRanges []offsetRange
}

// NewTransferProgress returns progress for a file of fileSize bytes.
func NewTransferProgress(fileSize int64) *TransferProgress {
	return &TransferProgress{fileSize: fileSize}
}

// OnAck records that [byteOffset, byteOffset+length) was acknowledged. Out-of-range or
// non-positive input is ignored rather than stored, so a malformed acknowledgement
// cannot inflate the contiguous watermark and make a resume skip real bytes.
//
// Ranges are merged on insert, which keeps the slice small no matter how many Chunks a
// 64 GiB file is cut into and makes ContiguousAckedThrough an O(1) read of the first
// range.
func (p *TransferProgress) OnAck(byteOffset int64, length int) {
	if length <= 0 || byteOffset < 0 || byteOffset >= p.fileSize {
		return
	}
	end := byteOffset + int64(length)
	if end > p.fileSize {
		end = p.fileSize
	}

	p.ackedRanges = append(p.ackedRanges, offsetRange{byteOffset, end})
	sort.Slice(p.ackedRanges, func(i, j int) bool {
		return p.ackedRanges[i].start < p.ackedRanges[j].start
	})

	merged := p.ackedRanges[:0]
	for _, r := range p.ackedRanges {
		if len(merged) > 0 && r.start <= merged[len(merged)-1].endExclusive {
			if r.endExclusive > merged[len(merged)-1].endExclusive {
				merged[len(merged)-1].endExclusive = r.endExclusive
			}
			continue
		}
		merged = append(merged, r)
	}
	p.ackedRanges = merged
}

// ContiguousAckedThrough is the first byte after the last contiguously acknowledged
// Chunk, which is where a resume or a rebind starts (Req 3.5, 7.8).
//
// It deliberately ignores acknowledged bytes beyond a gap. Those bytes will be sent
// again on resume, which costs bandwidth; the alternative, resuming past a hole,
// costs a corrupt file.
func (p *TransferProgress) ContiguousAckedThrough() int64 {
	if len(p.ackedRanges) == 0 || p.ackedRanges[0].start != 0 {
		return 0
	}
	return p.ackedRanges[0].endExclusive
}

// AcknowledgedBytes is the total acknowledged byte count, for the progress report of
// Req 7.3. Unlike the contiguous watermark it counts bytes past a gap, because a
// progress bar should reflect work actually done.
func (p *TransferProgress) AcknowledgedBytes() int64 {
	var total int64
	for _, r := range p.ackedRanges {
		total += r.endExclusive - r.start
	}
	return total
}

// Complete reports whether the whole file has been acknowledged contiguously.
func (p *TransferProgress) Complete() bool {
	return p.fileSize > 0 && p.ContiguousAckedThrough() >= p.fileSize
}

// FileSize is the total byte size the progress is tracking (Req 7.3).
func (p *TransferProgress) FileSize() int64 { return p.fileSize }

// ProgressReport is the once-per-second report of Req 7.3.
type ProgressReport struct {
	TransferId            TransferId
	AcknowledgedBytes     int64
	TotalBytes            int64
	GoodputBytesPerSecond int64
}

// String renders the report for the status line.
func (r ProgressReport) String() string {
	return fmt.Sprintf("transfer %s: %d/%d bytes at %d B/s",
		r.TransferId, r.AcknowledgedBytes, r.TotalBytes, r.GoodputBytesPerSecond)
}

// Report builds the Req 7.3 progress report. Goodput is passed in rather than measured
// here, because it belongs to the Transport (Req 2.7) and a Transfer that measured its
// own would disagree with the status line.
func (p *TransferProgress) Report(id TransferId, goodputBytesPerSecond int64) ProgressReport {
	return ProgressReport{
		TransferId:            id,
		AcknowledgedBytes:     p.AcknowledgedBytes(),
		TotalBytes:            p.fileSize,
		GoodputBytesPerSecond: goodputBytesPerSecond,
	}
}

// IntegrityOutcome is the result of the digest comparison in Req 7.4.
type IntegrityOutcome struct {
	// Verified is set when the computed digest matches the offer.
	Verified bool
	// Failure is Req 7.5 and 7.6: the digests differ.
	Failure *IntegrityFailure
}

// IntegrityFailure names everything Req 7.5 requires: the transfer identifier, the
// offered digest, and the computed digest. RetainedLocation is Req 7.6, set only when
// the corrupt content could not be discarded.
type IntegrityFailure struct {
	TransferId     TransferId
	OfferedDigest  []byte
	ComputedDigest []byte
	// Discarded reports whether the assembled content was released.
	Discarded bool
	// RetainedLocation is where the content still sits when it could not be
	// discarded (Req 7.6). Empty when Discarded is true.
	RetainedLocation string
	// DiscardError is why the content could not be released.
	DiscardError string
}

func (f *IntegrityFailure) Error() string {
	base := fmt.Sprintf("transfer %s failed integrity check: offered %s, computed %s",
		f.TransferId, hex.EncodeToString(f.OfferedDigest), hex.EncodeToString(f.ComputedDigest))
	if f.Discarded {
		return base + "; assembled content discarded"
	}
	return fmt.Sprintf("%s; assembled content retained at %s (%s)",
		base, f.RetainedLocation, f.DiscardError)
}

// VerifyAssembled compares the digest of assembled content against the offer (Req 7.4)
// and, on a mismatch, builds the failure report and asks discard to release the
// content (Req 7.5, 7.6).
//
// discard is a function rather than a filesystem call because this package is pure;
// the receiver passes a closure over its temp file. It returns the retained location
// and an error when the content could not be released, which is exactly the Req 7.6
// case. A nil discard means there was nothing to release, which is treated as
// discarded.
func VerifyAssembled(
	offer TransferOffer,
	assembled []byte,
	discard func() (retainedLocation string, err error),
) IntegrityOutcome {
	computed := DigestOf(assembled)
	if len(offer.SHA256) == len(computed) && equalBytes(offer.SHA256, computed) {
		return IntegrityOutcome{Verified: true}
	}

	failure := &IntegrityFailure{
		TransferId:     offer.TransferId,
		OfferedDigest:  append([]byte(nil), offer.SHA256...),
		ComputedDigest: computed,
		Discarded:      true,
	}
	if discard != nil {
		if location, err := discard(); err != nil {
			failure.Discarded = false
			failure.RetainedLocation = location
			failure.DiscardError = err.Error()
		}
	}
	return IntegrityOutcome{Failure: failure}
}

// equalBytes is a plain comparison. Constant time is not required: both digests are
// derived from content the caller already holds, so there is no secret to leak by
// timing.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
