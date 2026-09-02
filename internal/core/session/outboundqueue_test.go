package session

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// testQueueLimit stands in for the 64 MiB of Req 3.6 in the generated cases. The
// budget arithmetic does not care about the magnitude, and a small limit means the
// property reaches the rejection branch constantly instead of once in a hundred
// runs. TestOutboundQueueEnforcesTheRealSixtyFourMebibyteLimit pins the real
// constant separately.
const testQueueLimit int64 = 4096

// TestProperty17DisconnectedQueueRespectsBudgetOrderAndRetention covers
// Property 17: The disconnected outbound queue respects its budget, order, and
// retention.
//
// Validates: Requirements 3.6, 3.7, 3.9, 3.10
func TestProperty17DisconnectedQueueRespectsBudgetOrderAndRetention(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		clk := newManualClock()
		q := newOutboundQueueWithLimit(clk, testQueueLimit)

		// A model of what the queue should hold: sequence -> queued-at time.
		type modelEntry struct {
			sequence uint64
			size     int64
			queuedAt time.Time
		}
		var model []modelEntry
		var modelBytes int64

		steps := rapid.IntRange(1, 40).Draw(rt, "steps")
		nextSequence := uint64(0)

		for step := 0; step < steps; step++ {
			switch rapid.SampledFrom([]string{
				"submit", "submit", "submit", "advance", "expire", "flush",
			}).Draw(rt, "op") {

			case "submit":
				size := rapid.SampledFrom([]int{0, 1, 100, 1000, 3000, 5000}).
					Draw(rt, "payloadSize")
				sequence := nextSequence
				nextSequence++

				bytesBefore := q.ByteCount()
				lenBefore := q.Len()
				sequencesBefore := q.Sequences()

				got := q.Submit(QueuedMessage{
					Type:     1,
					Sequence: sequence,
					Payload:  bytes.Repeat([]byte{byte(step)}, size),
				})

				wantRejected := modelBytes+int64(size) > testQueueLimit
				switch {
				case wantRejected:
					// Req 3.10: rejected, naming the limit, queue unchanged.
					if got.Queued || got.Rejected == nil {
						rt.Fatalf("step %d: %d bytes over budget was accepted", step, size)
					}
					if *got.Rejected != testQueueLimit {
						rt.Fatalf("step %d: rejection names limit %d, want %d",
							step, *got.Rejected, testQueueLimit)
					}
					if !strings.Contains(got.Reason(), "retention limit") {
						rt.Fatalf("step %d: reason %q does not name the retention limit",
							step, got.Reason())
					}
					if q.ByteCount() != bytesBefore || q.Len() != lenBefore {
						rt.Fatalf("step %d: rejection changed the queue: %d/%d -> %d/%d",
							step, lenBefore, bytesBefore, q.Len(), q.ByteCount())
					}
					assertSequencesEqual(rt, q.Sequences(), sequencesBefore,
						"queue contents after a rejection")

				default:
					if !got.Queued || got.Rejected != nil {
						rt.Fatalf("step %d: %d bytes within budget was rejected", step, size)
					}
					model = append(model, modelEntry{sequence, int64(size), clk.Now()})
					modelBytes += int64(size)
				}

			case "advance":
				clk.advance(rapid.SampledFrom([]time.Duration{
					time.Second, time.Minute, QueueRetention / 2, QueueRetention,
				}).Draw(rt, "advance"))

			case "expire":
				// Req 3.9: exactly the Messages past retention are discarded, and
				// their sequence numbers are reported.
				var wantDiscarded []uint64
				var kept []modelEntry
				var keptBytes int64
				for _, e := range model {
					if clk.Now().Sub(e.queuedAt) >= QueueRetention {
						wantDiscarded = append(wantDiscarded, e.sequence)
						continue
					}
					kept = append(kept, e)
					keptBytes += e.size
				}
				got := q.DiscardExpired()
				assertSequencesEqual(rt, got, wantDiscarded, "discarded sequence numbers")
				model, modelBytes = kept, keptBytes

			case "flush":
				// Req 3.7: everything retained, in ascending sequence order, and
				// the queue is emptied.
				got := q.DrainForFlush()
				if len(got) != len(model) {
					rt.Fatalf("step %d: flushed %d messages, want %d", step, len(got), len(model))
				}
				for i := 1; i < len(got); i++ {
					if got[i].Sequence <= got[i-1].Sequence {
						rt.Fatalf("step %d: flush order %d after %d is not ascending",
							step, got[i].Sequence, got[i-1].Sequence)
					}
				}
				wantSequences := make([]uint64, 0, len(model))
				for _, e := range model {
					wantSequences = append(wantSequences, e.sequence)
				}
				assertSequencesEqual(rt, sequencesOfQueued(got), wantSequences, "flushed messages")
				if q.Len() != 0 || q.ByteCount() != 0 {
					rt.Fatalf("step %d: flush left %d messages / %d bytes",
						step, q.Len(), q.ByteCount())
				}
				model, modelBytes = nil, 0
			}

			// Req 3.6: the budget is never exceeded, whatever the sequence of ops.
			if q.ByteCount() > testQueueLimit {
				rt.Fatalf("step %d: queue holds %d bytes, limit is %d",
					step, q.ByteCount(), testQueueLimit)
			}
			if q.ByteCount() != modelBytes {
				rt.Fatalf("step %d: queue holds %d bytes, model says %d",
					step, q.ByteCount(), modelBytes)
			}
			if q.Len() != len(model) {
				rt.Fatalf("step %d: queue holds %d messages, model says %d",
					step, q.Len(), len(model))
			}
			if q.RemainingBytes() != testQueueLimit-q.ByteCount() {
				rt.Fatalf("step %d: remaining %d, want %d",
					step, q.RemainingBytes(), testQueueLimit-q.ByteCount())
			}
		}
	})
}

// TestOutboundQueueEnforcesTheRealSixtyFourMebibyteLimit pins the constant from
// Req 3.6 and 3.10 against the actual budget, which the property test deliberately
// shrinks.
//
// Requirements: 3.6, 3.10
func TestOutboundQueueEnforcesTheRealSixtyFourMebibyteLimit(t *testing.T) {
	clk := newManualClock()
	q := NewOutboundQueue(clk)

	if q.LimitBytes() != 64*1024*1024 {
		t.Fatalf("limit is %d bytes, want 64 MiB", q.LimitBytes())
	}

	// Fill the budget exactly, in 8 MiB pieces.
	const piece = 8 * 1024 * 1024
	payload := make([]byte, piece)
	for i := 0; i < 8; i++ {
		if got := q.Submit(QueuedMessage{Sequence: uint64(i), Payload: payload}); !got.Queued {
			t.Fatalf("piece %d rejected at %d bytes held", i, q.ByteCount())
		}
	}
	if q.ByteCount() != QueueByteLimit {
		t.Fatalf("queue holds %d bytes, want exactly the limit", q.ByteCount())
	}

	// One more byte is refused, and the queue is untouched.
	got := q.Submit(QueuedMessage{Sequence: 99, Payload: []byte{0}})
	if got.Queued || got.Rejected == nil {
		t.Fatal("submission past the limit was accepted")
	}
	if *got.Rejected != QueueByteLimit {
		t.Fatalf("rejection names %d bytes, want %d", *got.Rejected, QueueByteLimit)
	}
	if q.Len() != 8 || q.ByteCount() != QueueByteLimit {
		t.Fatalf("rejection changed the queue: %d messages / %d bytes", q.Len(), q.ByteCount())
	}
}

// TestOutboundQueueRetentionIsPerMessage documents the reading of Req 3.9 the
// implementation takes: each Message keeps its own 10-minute window, so a Message
// queued late in an outage is not discarded early.
//
// Requirements: 3.9
func TestOutboundQueueRetentionIsPerMessage(t *testing.T) {
	clk := newManualClock()
	q := newOutboundQueueWithLimit(clk, testQueueLimit)

	q.Submit(QueuedMessage{Sequence: 1, Payload: []byte("early")})
	clk.advance(9 * time.Minute)
	q.Submit(QueuedMessage{Sequence: 2, Payload: []byte("late")})

	// At t=9m nothing has aged out.
	if got := q.DiscardExpired(); len(got) != 0 {
		t.Fatalf("discarded %v after 9 minutes", got)
	}

	// At t=10m only the first Message has.
	clk.advance(time.Minute)
	got := q.DiscardExpired()
	if len(got) != 1 || got[0] != 1 {
		t.Fatalf("discarded %v, want just sequence 1", got)
	}
	if q.Len() != 1 || q.Sequences()[0] != 2 {
		t.Fatalf("queue holds %v, want just sequence 2", q.Sequences())
	}

	// The second Message ages out ten minutes after *it* was queued.
	clk.advance(9 * time.Minute)
	if got := q.DiscardExpired(); len(got) != 1 || got[0] != 2 {
		t.Fatalf("discarded %v, want sequence 2", got)
	}
	if q.Len() != 0 || q.ByteCount() != 0 {
		t.Fatalf("queue not empty: %d messages / %d bytes", q.Len(), q.ByteCount())
	}
}

// TestOutboundQueueFlushSortsOutOfOrderSubmissions checks Req 3.7 against the case
// that makes sorting necessary: a group send fans out concurrently, so submissions
// can arrive with their sequence numbers out of order.
//
// Requirements: 3.7
func TestOutboundQueueFlushSortsOutOfOrderSubmissions(t *testing.T) {
	q := newOutboundQueueWithLimit(newManualClock(), testQueueLimit)
	for _, seq := range []uint64{5, 1, 4, 0, 3} {
		if got := q.Submit(QueuedMessage{Sequence: seq, Payload: []byte{byte(seq)}}); !got.Queued {
			t.Fatalf("sequence %d rejected", seq)
		}
	}
	got := q.DrainForFlush()
	assertSequencesEqual(t, sequencesOfQueued(got), []uint64{0, 1, 3, 4, 5}, "flush order")
	if q.Len() != 0 {
		t.Fatal("flush left messages behind")
	}
	if q.DrainForFlush() != nil {
		t.Fatal("second flush returned messages")
	}
}

// TestOutboundQueueCopiesPayloads checks that a caller reusing its buffer cannot
// alter retained bytes.
//
// Requirements: 3.6
func TestOutboundQueueCopiesPayloads(t *testing.T) {
	q := newOutboundQueueWithLimit(newManualClock(), testQueueLimit)
	payload := []byte("original")
	q.Submit(QueuedMessage{Sequence: 0, Payload: payload})
	copy(payload, "MUTATED!")

	got := q.DrainForFlush()
	if len(got) != 1 || string(got[0].Payload) != "original" {
		t.Fatalf("retained payload is %q, want %q", got[0].Payload, "original")
	}
}

// TestOutboundQueueStampsQueuedAtFromTheClock checks that the retention window is
// measured from when the node took the Message, not from a value the caller supplied.
//
// Requirements: 3.9
func TestOutboundQueueStampsQueuedAtFromTheClock(t *testing.T) {
	clk := newManualClock()
	q := newOutboundQueueWithLimit(clk, testQueueLimit)

	// A caller claiming the Message is an hour old must not shorten its retention.
	q.Submit(QueuedMessage{
		Sequence: 0,
		Payload:  []byte("x"),
		QueuedAt: baseTime.Add(-time.Hour),
	})
	if got := q.DiscardExpired(); len(got) != 0 {
		t.Fatalf("discarded %v immediately", got)
	}
	got := q.DrainForFlush()
	if !got[0].QueuedAt.Equal(baseTime) {
		t.Fatalf("QueuedAt is %s, want the clock's %s", got[0].QueuedAt, baseTime)
	}
}

func sequencesOfQueued(items []QueuedMessage) []uint64 {
	out := make([]uint64, 0, len(items))
	for _, m := range items {
		out = append(out, m.Sequence)
	}
	return out
}

func assertSequencesEqual(t rapid.TB, got, want []uint64, what string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %v (%d), want %v (%d)", what, got, len(got), want, len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s: got %v, want %v", what, got, want)
		}
	}
}
