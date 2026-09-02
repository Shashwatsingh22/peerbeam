package transfer

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// TestProperty29TransferTerminationStopsChunkSendingAndPreservesResumableState covers
// Property 29: Transfer termination stops Chunk sending and preserves resumable state.
//
// Validates: Requirements 7.7, 7.9, 7.11, 7.12, 7.13
func TestProperty29TransferTerminationStopsChunkSendingAndPreservesResumableState(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		clk := newManualClock()

		fileSize := int64(rapid.IntRange(1, 200).Draw(rt, "fileSize"))
		chunkSize := rapid.SampledFrom([]int{1, 7, 512}).Draw(rt, "chunkSize")
		offer := TransferOffer{
			TransferId: "tx-1",
			FileName:   "f.bin",
			ByteSize:   fileSize,
			SHA256:     make([]byte, 32),
		}
		state := NewTransferState(offer, clk)

		plan, err := PlanChunks(fileSize, 0, chunkSize)
		if err != nil {
			rt.Fatalf("planning: %v", err)
		}

		// Req 7.11, 7.12: nothing may be sent before the offer is accepted.
		if state.MaySendChunk() {
			rt.Fatal("chunks permitted before the offer was accepted")
		}

		outcome := rapid.SampledFrom([]OfferOutcome{
			{Accepted: true},
			{Declined: true},
			{TimedOut: true},
			{Unsupported: &UnsupportedFileSize{MeasuredBytes: 0, Min: FileMinBytes, Max: FileMaxBytes}},
		}).Draw(rt, "offerOutcome")

		if outcome.MaySendChunks() {
			state.Accept()
		} else {
			state.RejectOffer(outcome)
			// Req 7.11, 7.12: no Chunk is ever sent for a rejected offer.
			if state.MaySendChunk() {
				rt.Fatalf("%s permitted chunk sending", outcome.Kind())
			}
			cause, stopped := state.Stopped()
			if !stopped || cause != StopOfferRejected {
				rt.Fatalf("rejected offer left the transfer at %s/%v", cause, stopped)
			}
			if outcome.Kind() == OfferUnsupportedSize {
				// The rejection names the measured size and the range.
				reason := outcome.Reason()
				for _, want := range []string{"0", strconv.FormatInt(FileMaxBytes, 10)} {
					if !strings.Contains(reason, want) {
						rt.Fatalf("rejection %q omits %q", reason, want)
					}
				}
			}
			return
		}

		if !state.MaySendChunk() {
			rt.Fatal("accepted offer does not permit chunk sending")
		}

		// A generated schedule of acknowledgements, timeouts, and a possible cancel.
		type event struct {
			kind string
			ref  ChunkRef
		}
		var schedule []event
		steps := rapid.IntRange(1, 30).Draw(rt, "steps")
		for i := 0; i < steps; i++ {
			ref := plan[rapid.IntRange(0, len(plan)-1).Draw(rt, "chunk"+strconv.Itoa(i))]
			schedule = append(schedule, event{
				kind: rapid.SampledFrom([]string{"ack", "timeout", "timeout", "cancel"}).
					Draw(rt, "event"+strconv.Itoa(i)),
				ref: ref,
			})
		}

		// Independent model of resend counts per chunk offset.
		attempts := map[int64]int{}
		var cancelled bool

		for step, e := range schedule {
			switch e.kind {
			case "ack":
				wasStopped := func() bool { _, s := state.Stopped(); return s }()
				state.OnAck(e.ref.ByteOffset, e.ref.Length)
				if wasStopped {
					continue
				}
				// An acknowledged chunk has its resend counter cleared, so a later
				// timeout on the same offset starts from attempt 1 again. That is the
				// point of clearing: a chunk that arrived once and is retransmitted
				// later has not used up its five attempts.
				delete(attempts, e.ref.ByteOffset)

			case "timeout":
				before := attempts[e.ref.ByteOffset]
				mayHaveSent := state.MaySendChunk()

				attempt, ok := state.OnChunkTimeout(e.ref.ByteOffset, e.ref.ChunkIndex)

				if !mayHaveSent {
					// A stopped transfer resends nothing (Req 7.9, 7.13).
					if ok {
						rt.Fatalf("step %d: a stopped transfer authorised a resend", step)
					}
					continue
				}
				if before >= MaxResendAttempts {
					if ok {
						rt.Fatalf("step %d: resend %d authorised past the ceiling", step, attempt)
					}
					continue
				}

				// Req 7.7: a resend below the ceiling is authorised, and the
				// attempt number is the one the model predicted.
				if !ok {
					rt.Fatalf("step %d: resend %d of %d refused below the ceiling",
						step, before+1, MaxResendAttempts)
				}
				if attempt != before+1 {
					rt.Fatalf("step %d: attempt reported as %d, want %d",
						step, attempt, before+1)
				}
				attempts[e.ref.ByteOffset] = attempt
				if attempt > MaxResendAttempts {
					rt.Fatalf("step %d: chunk at %d reached attempt %d",
						step, e.ref.ByteOffset, attempt)
				}

			case "cancel":
				state.Cancel()
				cancelled = true
			}

			// Req 7.9: once cancelled, nothing may be sent again, ever.
			if cancelled && state.MaySendChunk() {
				rt.Fatalf("step %d: a cancelled transfer permitted chunk sending", step)
			}
		}

		cause, stopped := state.Stopped()

		if cancelled {
			if !stopped {
				rt.Fatal("a cancelled transfer is not stopped")
			}
			// Req 7.9: the receiver is told to release the partial content, but only
			// when the stop really was a cancel.
			if cause == StopCancelled {
				instruction, ok := state.ReleaseInstruction()
				if !ok {
					rt.Fatal("a cancelled transfer produced no release instruction")
				}
				if instruction.TransferId != offer.TransferId {
					rt.Fatalf("release instruction names %s, want %s",
						instruction.TransferId, offer.TransferId)
				}
			}
		}

		if cause == StopResendsExhausted {
			// Req 7.13: the failure names the transfer identifier and the chunk index.
			f := state.Failure()
			if f == nil {
				rt.Fatal("exhausted resends produced no failure report")
			}
			if f.TransferId != offer.TransferId {
				rt.Fatalf("failure names transfer %s, want %s", f.TransferId, offer.TransferId)
			}
			if f.Attempts != MaxResendAttempts {
				rt.Fatalf("failure names %d attempts, want %d", f.Attempts, MaxResendAttempts)
			}
			message := f.Error()
			for _, want := range []string{
				string(offer.TransferId),
				strconv.Itoa(f.ChunkIndex),
			} {
				if !strings.Contains(message, want) {
					rt.Fatalf("failure %q omits %q", message, want)
				}
			}

			// Req 7.13: acknowledged state is retained for 10 minutes and still yields
			// a valid resume plan.
			until, has := state.RetainUntil()
			if !has {
				rt.Fatal("stopped transfer has no retention deadline")
			}
			if want := clk.Now().Add(ResumeRetention); !until.Equal(want) {
				rt.Fatalf("retention until %s, want %s", until, want)
			}
			if !state.Resendable() {
				rt.Fatal("state is not resumable immediately after the failure")
			}
			resume, err := state.ResumePlan(chunkSize)
			if err != nil {
				rt.Fatalf("resume plan right after the failure: %v", err)
			}
			assertPlanShape(rt, resume, fileSize,
				state.Progress().ContiguousAckedThrough(), chunkSize)
		}

		// Every chunk the model saw stayed at or below the ceiling. Independence
		// between chunks is pinned separately by TestResendTrackerKeysOnOffsetNotIndex,
		// where two legs at different chunk sizes share an index but not an offset.
		for offset, count := range attempts {
			if count > MaxResendAttempts {
				rt.Fatalf("chunk at offset %d reached %d attempts, ceiling is %d",
					offset, count, MaxResendAttempts)
			}
		}
	})
}

// TestResendTrackerCountsPerChunkAndStopsAtFive pins Req 7.7 on its own: five resends
// for one chunk, no more, and counters that do not bleed between chunks.
//
// Requirements: 7.7
func TestResendTrackerCountsPerChunkAndStopsAtFive(t *testing.T) {
	r := NewResendTracker()
	if r.MaxAttempts() != 5 {
		t.Fatalf("ceiling is %d, want 5", r.MaxAttempts())
	}

	for attempt := 1; attempt <= MaxResendAttempts; attempt++ {
		got, ok := r.RegisterResend(0)
		if !ok {
			t.Fatalf("attempt %d refused", attempt)
		}
		if got != attempt {
			t.Fatalf("attempt reported as %d, want %d", got, attempt)
		}
	}
	// The sixth is refused, and asking again does not run the counter away.
	for i := 0; i < 3; i++ {
		got, ok := r.RegisterResend(0)
		if ok {
			t.Fatal("a sixth resend was authorised")
		}
		if got != MaxResendAttempts {
			t.Fatalf("refused attempt reported as %d, want %d", got, MaxResendAttempts)
		}
	}
	if !r.Exhausted(0) {
		t.Fatal("chunk at offset 0 is not reported exhausted")
	}

	// A different chunk is untouched by all of that.
	if r.Attempts(512) != 0 {
		t.Fatalf("chunk at offset 512 has %d attempts", r.Attempts(512))
	}
	if r.Exhausted(512) {
		t.Fatal("an untouched chunk is reported exhausted")
	}
	if got, ok := r.RegisterResend(512); !ok || got != 1 {
		t.Fatalf("first resend of another chunk got (%d, %v)", got, ok)
	}

	// An acknowledgement clears the counter, so a long transfer does not accumulate
	// an entry per chunk for its whole life.
	r.Clear(0)
	if r.Attempts(0) != 0 || r.Exhausted(0) {
		t.Fatal("clearing did not reset the counter")
	}
}

// TestResendTrackerKeysOnOffsetNotIndex is why the tracker is keyed by byte offset: a
// chunk size change renumbers indices, and a tracker keyed by index would merge the
// counts of two unrelated chunks after a rebind.
//
// Requirements: 7.7, 3.5
func TestResendTrackerKeysOnOffsetNotIndex(t *testing.T) {
	lanLeg, _ := PlanChunks(200_000, 0, 65_536)
	btLeg, _ := PlanChunks(200_000, 0, 512)

	// Index 1 is a different chunk on each transport.
	if lanLeg[1].ByteOffset == btLeg[1].ByteOffset {
		t.Fatal("the two legs agree on chunk 1's offset, which defeats the test")
	}

	r := NewResendTracker()
	for i := 0; i < MaxResendAttempts; i++ {
		r.RegisterResend(lanLeg[1].ByteOffset)
	}
	if !r.Exhausted(lanLeg[1].ByteOffset) {
		t.Fatal("the LAN chunk is not exhausted")
	}
	// The Bluetooth chunk that happens to share index 1 starts fresh.
	if r.Exhausted(btLeg[1].ByteOffset) {
		t.Fatal("a different chunk inherited the exhausted count via its index")
	}
}

// TestTransferStateCancelStopsSendingAndInstructsRelease pins Req 7.9 end to end.
//
// Requirements: 7.9
func TestTransferStateCancelStopsSendingAndInstructsRelease(t *testing.T) {
	clk := newManualClock()
	state := NewTransferState(TransferOffer{TransferId: "tx-c", ByteSize: 1000}, clk)
	state.Accept()

	if _, ok := state.ReleaseInstruction(); ok {
		t.Fatal("a running transfer produced a release instruction")
	}

	state.Cancel()
	if state.MaySendChunk() {
		t.Fatal("a cancelled transfer still permits chunk sending")
	}
	cause, stopped := state.Stopped()
	if !stopped || cause != StopCancelled {
		t.Fatalf("state is %s/%v, want cancelled", cause, stopped)
	}

	instruction, ok := state.ReleaseInstruction()
	if !ok {
		t.Fatal("no release instruction after a cancel")
	}
	if instruction.TransferId != "tx-c" || instruction.Reason == "" {
		t.Fatalf("release instruction is %+v", instruction)
	}

	// A resend request after the cancel is refused (Req 7.9: stop sending Chunks).
	if _, ok := state.OnChunkTimeout(0, 0); ok {
		t.Fatal("a cancelled transfer authorised a resend")
	}
	// And Req 2 of the cancel: acknowledged state is still retained for a resume.
	if !state.Resendable() {
		t.Fatal("a cancelled transfer is immediately unresumable")
	}
}

// TestTransferStateCompletionDoesNotInstructRelease guards the gate on
// ReleaseInstruction: a completed transfer must not tell the receiver to throw away a
// file it just verified.
//
// Requirements: 7.9
func TestTransferStateCompletionDoesNotInstructRelease(t *testing.T) {
	state := NewTransferState(TransferOffer{TransferId: "tx-done", ByteSize: 100}, newManualClock())
	state.Accept()
	state.OnAck(0, 100)

	cause, stopped := state.Stopped()
	if !stopped || cause != StopCompleted {
		t.Fatalf("state is %s/%v, want completed", cause, stopped)
	}
	if _, ok := state.ReleaseInstruction(); ok {
		t.Fatal("a completed transfer instructed the receiver to release the content")
	}
	if state.MaySendChunk() {
		t.Fatal("a completed transfer still permits chunk sending")
	}
}

// TestTransferStateResumeWindowLapsesAtTenMinutes pins the retention window of Req 7.8
// and 7.13.
//
// Requirements: 7.8, 7.13
func TestTransferStateResumeWindowLapsesAtTenMinutes(t *testing.T) {
	clk := newManualClock()
	state := NewTransferState(TransferOffer{TransferId: "tx-r", ByteSize: 1000}, clk)
	state.Accept()
	state.OnAck(0, 400)

	// Exhaust one chunk's resends to stop the transfer.
	for i := 0; i <= MaxResendAttempts; i++ {
		state.OnChunkTimeout(400, 4)
	}
	cause, stopped := state.Stopped()
	if !stopped || cause != StopResendsExhausted {
		t.Fatalf("state is %s/%v, want resends exhausted", cause, stopped)
	}

	// Just inside the window the resume plan still works, and starts where the
	// acknowledgements ended.
	clk.advance(ResumeRetention - time.Nanosecond)
	if !state.Resendable() {
		t.Fatal("state lapsed one nanosecond early")
	}
	plan, err := state.ResumePlan(512)
	if err != nil {
		t.Fatalf("resume plan inside the window: %v", err)
	}
	if len(plan) == 0 || plan[0].ByteOffset != 400 {
		t.Fatalf("resume plan starts at %+v, want offset 400", plan)
	}

	// At exactly the window it lapses, and planning refuses rather than producing a
	// plan from state that is no longer trustworthy.
	clk.advance(time.Nanosecond)
	if state.Resendable() {
		t.Fatal("state is still resumable at exactly 10 minutes")
	}
	if _, err := state.ResumePlan(512); err == nil {
		t.Fatal("planning succeeded past the retention window")
	}
	if ResumeRetention != 10*time.Minute {
		t.Fatalf("resume retention is %s, want 10m", ResumeRetention)
	}
}

// TestTransferStateRejectsChunksBeforeAcceptance is the shared precondition of Req 7.11
// and 7.12: an offer that was never accepted sends nothing.
//
// Requirements: 7.11, 7.12
func TestTransferStateRejectsChunksBeforeAcceptance(t *testing.T) {
	state := NewTransferState(TransferOffer{TransferId: "tx-p", ByteSize: 100}, newManualClock())

	if state.MaySendChunk() {
		t.Fatal("a fresh transfer permits chunk sending")
	}
	if _, ok := state.OnChunkTimeout(0, 0); ok {
		t.Fatal("an unaccepted transfer authorised a resend")
	}

	// An accepted offer that is then rejected is a contradiction the state ignores,
	// so a late decline cannot resurrect sending.
	state.Accept()
	state.RejectOffer(OfferOutcome{Declined: true})
	if state.MaySendChunk() {
		t.Fatal("a declined transfer permits chunk sending")
	}
	// Accepting after a stop does not restart it.
	state.Accept()
	if state.MaySendChunk() {
		t.Fatal("accepting after a stop restarted chunk sending")
	}
}
