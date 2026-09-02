package transfer

import (
	"fmt"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/clock"
)

// ResendTracker counts resend attempts per Chunk (Req 7.7) and decides when a Transfer
// has to stop (Req 7.13).
//
// Counters are keyed by byte offset rather than Chunk index, for the same reason
// TransferProgress stores ranges: a Chunk size change mid-transfer (Req 3.5) renumbers
// indices, and a tracker keyed by index would silently merge the attempt counts of two
// unrelated Chunks after a rebind.
//
// Not safe for concurrent use. One Transfer, one goroutine.
type ResendTracker struct {
	maxAttempts int
	attempts    map[int64]int
}

// NewResendTracker returns a tracker at the Req 7.7 ceiling of 5 attempts.
func NewResendTracker() *ResendTracker {
	return &ResendTracker{maxAttempts: MaxResendAttempts, attempts: map[int64]int{}}
}

// RegisterResend records a resend of the Chunk at byteOffset and returns the attempt
// number together with whether the resend may go ahead.
//
// ok is false once the ceiling is spent, and the counter stops at the ceiling so a
// caller that keeps asking cannot run it away. The attempt number returned on the
// refusing call is the ceiling itself, which is what the Req 7.13 failure report names.
func (r *ResendTracker) RegisterResend(byteOffset int64) (int, bool) {
	if r.attempts[byteOffset] >= r.maxAttempts {
		return r.maxAttempts, false
	}
	r.attempts[byteOffset]++
	return r.attempts[byteOffset], true
}

// Attempts is how many resends the Chunk at byteOffset has had.
func (r *ResendTracker) Attempts(byteOffset int64) int { return r.attempts[byteOffset] }

// Exhausted reports whether the Chunk at byteOffset has spent its attempts.
func (r *ResendTracker) Exhausted(byteOffset int64) bool {
	return r.attempts[byteOffset] >= r.maxAttempts
}

// MaxAttempts is the per-Chunk resend ceiling.
func (r *ResendTracker) MaxAttempts() int { return r.maxAttempts }

// Clear forgets the counter for a Chunk, called when it is finally acknowledged so a
// long Transfer does not accumulate an entry per Chunk for its whole life.
func (r *ResendTracker) Clear(byteOffset int64) { delete(r.attempts, byteOffset) }

// TransferFailure is the Req 7.13 report: a Chunk that outlived its resends. It names
// the transfer identifier and the Chunk index, and carries the byte offset too, since
// that is what a resume actually needs.
type TransferFailure struct {
	TransferId TransferId
	ChunkIndex int
	ByteOffset int64
	Attempts   int
	// ResumableUntil is when the retained acknowledgement state lapses (Req 7.13).
	ResumableUntil time.Time
}

func (f *TransferFailure) Error() string {
	return fmt.Sprintf("transfer %s stopped: chunk %d at offset %d unacknowledged after %d resend attempts; resumable until %s",
		f.TransferId, f.ChunkIndex, f.ByteOffset, f.Attempts, f.ResumableUntil.Format(time.RFC3339))
}

// TransferState is the sender-side lifecycle of one Transfer: whether it may send, what
// has been acknowledged, how many resends each outstanding Chunk has had, and when its
// resumable state lapses.
//
// It exists so the three ways a Transfer stops - resends exhausted (Req 7.13), user
// cancel (Req 7.9), and completion - all funnel through one place that can answer "may
// I send this Chunk?". A caller that had to check three separate flags would eventually
// miss one and send a Chunk after a cancel.
//
// Not safe for concurrent use.
type TransferState struct {
	id       TransferId
	offer    TransferOffer
	progress *TransferProgress
	resends  *ResendTracker
	clk      clock.Clock

	accepted  bool
	stopped   bool
	stopCause StopCause
	failure   *TransferFailure
	// retainUntil is when acknowledged state stops being resumable (Req 7.8, 7.13).
	retainUntil time.Time
	hasRetain   bool
}

// StopCause says why a Transfer stopped sending.
type StopCause uint8

const (
	// StopNone means the Transfer is still running.
	StopNone StopCause = iota
	// StopCompleted means every byte was acknowledged.
	StopCompleted
	// StopCancelled is Req 7.9: the user cancelled.
	StopCancelled
	// StopResendsExhausted is Req 7.13: a Chunk outlived its 5 resends.
	StopResendsExhausted
	// StopOfferRejected covers Req 7.11 and 7.12: the offer was declined, timed
	// out, or never sent because the file size was out of range.
	StopOfferRejected
)

func (c StopCause) String() string {
	switch c {
	case StopNone:
		return "running"
	case StopCompleted:
		return "completed"
	case StopCancelled:
		return "cancelled"
	case StopResendsExhausted:
		return "resend attempts exhausted"
	case StopOfferRejected:
		return "offer rejected"
	default:
		return "unknown"
	}
}

// NewTransferState returns state for an offer that has not yet been accepted, so
// MaySendChunk is false until Accept is called. That default is deliberate: Req 7.11
// and 7.12 both hinge on no Chunk going out before the Peer agrees.
func NewTransferState(offer TransferOffer, clk clock.Clock) *TransferState {
	if clk == nil {
		clk = clock.NewRealClock()
	}
	return &TransferState{
		id:       offer.TransferId,
		offer:    offer,
		progress: NewTransferProgress(offer.ByteSize),
		resends:  NewResendTracker(),
		clk:      clk,
	}
}

// Id is the transfer identifier every report names.
func (s *TransferState) Id() TransferId { return s.id }

// Offer is the offer this Transfer is carrying out.
func (s *TransferState) Offer() TransferOffer { return s.offer }

// Progress is the acknowledgement state, for progress reports and resume planning.
func (s *TransferState) Progress() *TransferProgress { return s.progress }

// Accept records the Peer's acceptance, after which Chunks may be sent (Req 7.2).
func (s *TransferState) Accept() {
	if s.stopped {
		return
	}
	s.accepted = true
}

// RejectOffer records a declined offer, an offer timeout, or an out-of-range file size,
// and stops the Transfer without any Chunk having been sent (Req 7.11, 7.12).
func (s *TransferState) RejectOffer(outcome OfferOutcome) {
	if outcome.MaySendChunks() {
		return
	}
	s.accepted = false
	s.stop(StopOfferRejected)
}

// MaySendChunk reports whether a Chunk may go on the wire right now. It is the single
// gate every send passes through: false before acceptance, false after a cancel, false
// after resends are exhausted, and false once complete.
func (s *TransferState) MaySendChunk() bool { return s.accepted && !s.stopped }

// OnAck records an acknowledgement, clears that Chunk's resend counter, and completes
// the Transfer once every byte is in.
func (s *TransferState) OnAck(byteOffset int64, length int) {
	if s.stopped {
		return
	}
	s.progress.OnAck(byteOffset, length)
	s.resends.Clear(byteOffset)
	if s.progress.Complete() {
		s.stop(StopCompleted)
	}
}

// OnChunkTimeout records that the Chunk at byteOffset went unacknowledged for
// ChunkAckTimeout. It returns the resend decision: (attempt, true) to resend, or
// (attempt, false) when the ceiling is spent, in which case the Transfer is stopped and
// Failure carries the Req 7.13 report.
//
// chunkIndex is passed in rather than derived because the report names the index within
// the current leg, and only the caller planning that leg knows it.
func (s *TransferState) OnChunkTimeout(byteOffset int64, chunkIndex int) (int, bool) {
	if !s.MaySendChunk() {
		return s.resends.Attempts(byteOffset), false
	}
	attempt, ok := s.resends.RegisterResend(byteOffset)
	if ok {
		return attempt, true
	}

	s.failure = &TransferFailure{
		TransferId: s.id,
		ChunkIndex: chunkIndex,
		ByteOffset: byteOffset,
		Attempts:   attempt,
	}
	s.stop(StopResendsExhausted)
	s.failure.ResumableUntil = s.retainUntil
	return attempt, false
}

// Cancel stops Chunk sending (Req 7.9). The caller is responsible for telling the
// receiver to release its partial content, and ReleaseInstruction builds that message.
func (s *TransferState) Cancel() { s.stop(StopCancelled) }

// ReleaseInstruction is what a cancelling sender tells the receiver: release the partial
// content held for this transfer identifier (Req 7.9).
type ReleaseInstruction struct {
	TransferId TransferId
	Reason     string
}

// ReleaseInstruction returns the instruction to send after a cancel, and false when the
// Transfer was not cancelled. It is gated on the cause so a completed Transfer cannot
// accidentally tell the receiver to throw away a file it just verified.
func (s *TransferState) ReleaseInstruction() (ReleaseInstruction, bool) {
	if s.stopCause != StopCancelled {
		return ReleaseInstruction{}, false
	}
	return ReleaseInstruction{
		TransferId: s.id,
		Reason:     "sender cancelled the transfer",
	}, true
}

// Stopped reports whether the Transfer has stopped sending, and why.
func (s *TransferState) Stopped() (StopCause, bool) { return s.stopCause, s.stopped }

// Failure is the Req 7.13 report, or nil when the Transfer did not fail that way.
func (s *TransferState) Failure() *TransferFailure { return s.failure }

// Resendable reports whether the acknowledged state is still inside its retention
// window, which is what Req 7.8 and 7.13 make resume depend on.
func (s *TransferState) Resendable() bool {
	if !s.hasRetain {
		return !s.stopped || s.stopCause == StopCompleted
	}
	return s.clk.Now().Before(s.retainUntil)
}

// ResumePlan returns the Chunks a resume should send at the given Chunk size, starting
// from the byte offset after the last contiguously acknowledged Chunk (Req 7.8), and
// re-slicing at the new Transport's size when that is what changed (Req 3.5).
//
// It refuses once the retention window has lapsed, rather than quietly planning a
// Transfer whose state is no longer trustworthy.
func (s *TransferState) ResumePlan(chunkSize int) ([]ChunkRef, error) {
	if !s.Resendable() {
		return nil, fmt.Errorf("transfer %s is no longer resumable: state lapsed at %s",
			s.id, s.retainUntil.Format(time.RFC3339))
	}
	return PlanResume(s.offer.ByteSize, s.progress, chunkSize)
}

// RetainUntil is when resumable state lapses, and false while the Transfer is running.
func (s *TransferState) RetainUntil() (time.Time, bool) { return s.retainUntil, s.hasRetain }

// stop is the single exit point, so every cause starts the retention window and no
// path can stop the Transfer without doing so.
func (s *TransferState) stop(cause StopCause) {
	if s.stopped {
		return
	}
	s.stopped = true
	s.stopCause = cause
	s.retainUntil = s.clk.Now().Add(ResumeRetention)
	s.hasRetain = true
}
