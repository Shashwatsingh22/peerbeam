package session

import (
	"sort"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/clock"
)

// ReorderHold is how long a Message that follows a gap waits for the missing
// Message before being presented anyway (Req 5.7).
const ReorderHold = 10 * time.Second

// ReorderBuffer presents received items in ascending sequence order, holding an
// item that follows a missing sequence number for at most ReorderHold before
// releasing it regardless (Req 5.7).
//
// It is generic over the item type so this package does not depend on
// internal/core/text. The reordering rule is about sequence numbers and arrival
// times, and knows nothing about what is being reordered; text, clipboard parts,
// and transfer chunks can all use it.
//
// Not safe for concurrent use: one Session, one goroutine.
type ReorderBuffer[T any] struct {
	hold time.Duration
	clk  clock.Clock

	// nextExpected is the sequence number that would be presented immediately.
	// It advances past a gap only when the hold expires, which is exactly the
	// "presenting it once 10 seconds have elapsed" clause of Req 5.7.
	nextExpected uint64
	pending      map[uint64]held[T]
}

type held[T any] struct {
	item      T
	arrivedAt time.Time
}

// NewReorderBuffer returns a buffer at the Req 5.7 hold of 10 seconds, expecting
// firstExpected as its first sequence number.
//
// firstExpected is a parameter rather than always 0 because a Session that rebinds
// mid-stream resumes from wherever it had reached; the buffer's notion of "in
// order" has to start where the Session actually is.
func NewReorderBuffer[T any](clk clock.Clock, firstExpected uint64) *ReorderBuffer[T] {
	if clk == nil {
		clk = clock.NewRealClock()
	}
	return &ReorderBuffer[T]{
		hold:         ReorderHold,
		clk:          clk,
		nextExpected: firstExpected,
		pending:      map[uint64]held[T]{},
	}
}

// Offer hands an item to the buffer and returns everything now presentable, in
// ascending sequence order.
//
// Three cases, and only three:
//
//   - sequence == nextExpected: the item is presented immediately, together with
//     any held items that are now contiguous behind it.
//   - sequence > nextExpected: there is a gap, so the item is held and nothing is
//     returned. DrainExpired releases it if the gap never fills.
//   - sequence < nextExpected: the buffer already moved past this number, because
//     a hold expired and the gap was declared lost. The straggler is presented
//     immediately, on its own.
//
// That last case is a deliberate choice between two imperfect options. Once the
// 10-second hold of Req 5.7 has expired and later Messages have been presented,
// a straggler can no longer be presented in ascending order relative to them. The
// options are to drop it or to present it late. Nothing in Requirement 5 authorises
// discarding a Message that is not a duplicate, and dropping it would lose text the
// user sent with no report, so it is presented. Property 22 asks for ascending order
// "within each contiguous run", and a straggler simply begins a new run.
//
// This is not the duplicate rule. SequenceTracker.AcceptInbound implements Req 5.10
// and runs before this; an item reaching here twice means the caller skipped it.
func (b *ReorderBuffer[T]) Offer(sequence uint64, item T) []T {
	switch {
	case sequence < b.nextExpected:
		return []T{item}
	case sequence > b.nextExpected:
		// Keep the first arrival time if the same sequence is offered twice, so a
		// repeat cannot extend the hold indefinitely.
		if _, already := b.pending[sequence]; !already {
			b.pending[sequence] = held[T]{item: item, arrivedAt: b.clk.Now()}
		}
		return nil
	default:
		out := []T{item}
		b.nextExpected++
		return append(out, b.drainContiguous()...)
	}
}

// DrainExpired releases held items whose hold has elapsed, in ascending sequence
// order, along with anything that becomes contiguous once they are released
// (Req 5.7). It returns nil when nothing has waited long enough.
//
// The trigger is "any held item has waited out its hold", but the release always
// starts from the lowest held sequence number, and those two are not the same item.
// Consider a gap at 2, item 5 arriving at t=0, and item 3 arriving at t=5. At t=10
// item 5 has waited its full 10 seconds, so something must be presented; but
// presenting 5 before 3 would break ascending order. So the buffer releases 3
// first, early, and then 5. Cutting a hold short is allowed - Req 5.7 says "up to
// 10 seconds" - whereas exceeding one is not.
//
// The loop repeats because one gap can sit behind another, and a caller that
// drained a single gap per call would have to know how many times to call.
func (b *ReorderBuffer[T]) DrainExpired() []T {
	if len(b.pending) == 0 {
		return nil
	}
	now := b.clk.Now()
	var out []T
	for b.anyExpired(now) {
		lowest, found := b.lowestPending()
		if !found {
			break
		}
		entry := b.pending[lowest]
		delete(b.pending, lowest)
		out = append(out, entry.item)
		// Skip the gap: everything below `lowest` is now considered lost.
		b.nextExpected = lowest + 1
		out = append(out, b.drainContiguous()...)
	}
	return out
}

// anyExpired reports whether some held item has waited at least the full hold. It
// scans every entry rather than only the lowest, because the item whose deadline
// has passed is not necessarily the one that has to be presented first.
func (b *ReorderBuffer[T]) anyExpired(now time.Time) bool {
	for _, entry := range b.pending {
		if now.Sub(entry.arrivedAt) >= b.hold {
			return true
		}
	}
	return false
}

// drainContiguous pulls held items that sit immediately at nextExpected, advancing
// as it goes. It is the step that makes a late arrival fill a gap and release
// everything queued behind it in one go.
func (b *ReorderBuffer[T]) drainContiguous() []T {
	var out []T
	for {
		entry, found := b.pending[b.nextExpected]
		if !found {
			return out
		}
		delete(b.pending, b.nextExpected)
		out = append(out, entry.item)
		b.nextExpected++
	}
}

func (b *ReorderBuffer[T]) lowestPending() (uint64, bool) {
	if len(b.pending) == 0 {
		return 0, false
	}
	first := true
	var lowest uint64
	for seq := range b.pending {
		if first || seq < lowest {
			lowest, first = seq, false
		}
	}
	return lowest, true
}

// NextExpected is the sequence number the buffer is waiting on.
func (b *ReorderBuffer[T]) NextExpected() uint64 { return b.nextExpected }

// PendingCount is how many items are held behind a gap.
func (b *ReorderBuffer[T]) PendingCount() int { return len(b.pending) }

// PendingSequences lists held sequence numbers in ascending order, for status
// output and tests.
func (b *ReorderBuffer[T]) PendingSequences() []uint64 {
	out := make([]uint64, 0, len(b.pending))
	for seq := range b.pending {
		out = append(out, seq)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// DeadlineFor reports when a held item will be released if its gap never fills, and
// false when that sequence is not held. The Session's timer goroutine uses the
// earliest of these to decide when to call DrainExpired.
func (b *ReorderBuffer[T]) DeadlineFor(sequence uint64) (time.Time, bool) {
	entry, found := b.pending[sequence]
	if !found {
		return time.Time{}, false
	}
	return entry.arrivedAt.Add(b.hold), true
}

// NextDeadline is the earliest release deadline among held items, and false when
// nothing is held. It is the minimum over every entry rather than the deadline of
// the lowest sequence number, for the same reason DrainExpired scans them all: the
// first deadline to pass can belong to any held item.
func (b *ReorderBuffer[T]) NextDeadline() (time.Time, bool) {
	var earliest time.Time
	first := true
	for _, entry := range b.pending {
		deadline := entry.arrivedAt.Add(b.hold)
		if first || deadline.Before(earliest) {
			earliest, first = deadline, false
		}
	}
	return earliest, !first
}
