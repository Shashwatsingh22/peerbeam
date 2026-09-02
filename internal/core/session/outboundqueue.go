package session

import (
	"fmt"
	"sort"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/clock"
)

// Retention bounds for a disconnected Session, fixed by Requirements 3.6 and 3.9.
const (
	// QueueByteLimit is the payload budget per Session, 64 MiB (Req 3.6, 3.10).
	// It counts payload bytes only: frame headers are added at send time, so
	// counting them here would make the budget depend on how the queue is later
	// drained.
	QueueByteLimit int64 = 64 * 1024 * 1024
	// QueueRetention is how long queued payload survives (Req 3.6, 3.9).
	QueueRetention = 10 * time.Minute
)

// QueuedMessage is one retained outbound Message. The sequence number is assigned
// before queueing, not at flush time, because Req 3.7 flushes in ascending sequence
// order and Req 3.9 names discarded sequence numbers: both need the number to exist
// while the Session is still disconnected.
type QueuedMessage struct {
	Type     uint8
	Sequence uint64
	Payload  []byte
	// Control marks a Message that should overtake bulk traffic once the Session
	// reconnects (Req 4.6). It does not affect flush order, which Req 3.7 fixes as
	// ascending sequence.
	Control  bool
	QueuedAt time.Time
}

// Bytes is the payload size this Message charges against the budget.
func (m QueuedMessage) Bytes() int64 { return int64(len(m.Payload)) }

// QueueResult is a tagged result: exactly one of Queued / Rejected is set.
// Rejected carries the limit so the Req 3.10 error can name it.
type QueueResult struct {
	Queued   bool
	Rejected *int64 // Req 3.10: the retention limit in bytes
}

// Reason renders a rejection for a report, or "" when the Message was queued.
func (r QueueResult) Reason() string {
	if r.Rejected == nil {
		return ""
	}
	return fmt.Sprintf("retention limit of %d bytes reached", *r.Rejected)
}

// OutboundQueue retains outbound payload while a Session is disconnected
// (Req 3.6, 3.7, 3.9, 3.10). It is pure state plus an injected Clock: the 10-minute
// retention is testable without waiting.
//
// Not safe for concurrent use. One Session owns one queue.
type OutboundQueue struct {
	limitBytes int64
	retention  time.Duration
	clk        clock.Clock

	items []QueuedMessage
	bytes int64
}

// NewOutboundQueue returns a queue at the Req 3.6 budget of 64 MiB and retention of
// 10 minutes.
func NewOutboundQueue(clk clock.Clock) *OutboundQueue {
	return newOutboundQueueWithLimit(clk, QueueByteLimit)
}

// newOutboundQueueWithLimit is the seam tests use to exercise the budget rules
// without allocating 64 MiB per generated case. Production always goes through
// NewOutboundQueue, so the limit is never anything but QueueByteLimit outside tests.
func newOutboundQueueWithLimit(clk clock.Clock, limitBytes int64) *OutboundQueue {
	if clk == nil {
		clk = clock.NewRealClock()
	}
	return &OutboundQueue{
		limitBytes: limitBytes,
		retention:  QueueRetention,
		clk:        clk,
	}
}

// Submit retains a Message, or rejects it when it would take the queue over budget.
//
// The test is `held + incoming > limit`, so a submission is rejected when it would
// exceed the budget rather than only when the queue is already exactly full. The
// alternative reading of Req 3.10, rejecting only once 64 MiB is already held, would
// let a single large Message carry the queue arbitrarily far past its own limit.
//
// A rejection leaves the queue byte-identical: nothing is trimmed to make room, and
// no partial payload is stored. Req 3.10 says the queue is unchanged, and the
// caller still holds the Message, so dropping something already accepted to admit
// something newer would lose work the node had promised to keep.
//
// QueuedAt is stamped here from the Clock, ignoring any value the caller set, so
// the retention window in Req 3.9 always measures from when the node took
// responsibility for the Message.
func (q *OutboundQueue) Submit(m QueuedMessage) QueueResult {
	if q.bytes+m.Bytes() > q.limitBytes {
		limit := q.limitBytes
		return QueueResult{Rejected: &limit} // Req 3.10
	}
	// Copy the payload so a caller reusing its buffer cannot alter retained bytes.
	stored := m
	stored.Payload = append([]byte(nil), m.Payload...)
	stored.QueuedAt = q.clk.Now()

	q.items = append(q.items, stored)
	q.bytes += stored.Bytes()
	return QueueResult{Queued: true}
}

// DrainForFlush empties the queue and returns everything it held in ascending
// sequence number order (Req 3.7).
//
// Draining and returning are one operation because a reconnected Session sends what
// it gets back; a caller that could read without draining would be one retry away
// from sending the same Message twice.
//
// Sorting happens here rather than at insert time because Req 3.7 is a statement
// about flush order, and a group send fans out concurrently, so submissions can
// legitimately arrive out of order.
func (q *OutboundQueue) DrainForFlush() []QueuedMessage {
	if len(q.items) == 0 {
		return nil
	}
	out := q.items
	q.items = nil
	q.bytes = 0

	sort.SliceStable(out, func(i, j int) bool { return out[i].Sequence < out[j].Sequence })
	return out
}

// DiscardExpired drops Messages past the retention window and returns their
// sequence numbers in ascending order, so the Req 3.9 delivery failure can name
// each one.
//
// Retention is per Message, measured from when it was queued. Req 3.9 phrases the
// window as a property of the Session ("remains in a disconnected state for 10
// minutes"), but a Message submitted nine minutes into an outage has not itself
// been retained for ten, and discarding it at the Session's deadline would drop it
// early. Per-Message expiry keeps every Message its full window; the caller still
// reports one delivery failure naming all of them.
func (q *OutboundQueue) DiscardExpired() []uint64 {
	if len(q.items) == 0 {
		return nil
	}
	now := q.clk.Now()

	kept := q.items[:0]
	var discarded []uint64
	var keptBytes int64
	for _, m := range q.items {
		if now.Sub(m.QueuedAt) >= q.retention {
			discarded = append(discarded, m.Sequence)
			continue
		}
		kept = append(kept, m)
		keptBytes += m.Bytes()
	}
	q.items = kept
	q.bytes = keptBytes

	sort.Slice(discarded, func(i, j int) bool { return discarded[i] < discarded[j] })
	return discarded
}

// ByteCount is the payload currently retained, which is what the budget applies to.
func (q *OutboundQueue) ByteCount() int64 { return q.bytes }

// Len is the number of retained Messages.
func (q *OutboundQueue) Len() int { return len(q.items) }

// LimitBytes is the retention budget.
func (q *OutboundQueue) LimitBytes() int64 { return q.limitBytes }

// RemainingBytes is how much more payload the queue can accept.
func (q *OutboundQueue) RemainingBytes() int64 { return q.limitBytes - q.bytes }

// Sequences lists retained sequence numbers in ascending order, for status output
// and tests.
func (q *OutboundQueue) Sequences() []uint64 {
	out := make([]uint64, 0, len(q.items))
	for _, m := range q.items {
		out = append(out, m.Sequence)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
