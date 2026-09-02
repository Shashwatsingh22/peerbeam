package session

import (
	"testing"
	"time"

	"pgregory.net/rapid"
)

// inbound is the item the reorder buffer carries in these tests. Req 5.3 names the
// three things a text Message must have to be displayed, so the test double carries
// them rather than a bare sequence number.
type inbound struct {
	Sequence   uint64
	Content    string
	SenderName string
	ReceivedAt time.Time
}

// TestProperty22PresentationIsOrderedGapTolerantAndDuplicateFree covers
// Property 22: Presentation is ordered, gap-tolerant, and duplicate-free.
//
// The pipeline under test is the one a Session actually runs: SequenceTracker
// decides duplicates (Req 5.10), then ReorderBuffer decides presentation order
// (Req 5.7).
//
// Validates: Requirements 5.7, 5.10
func TestProperty22PresentationIsOrderedGapTolerantAndDuplicateFree(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		clk := newManualClock()
		tracker := NewSequenceTracker()
		buffer := NewReorderBuffer[inbound](clk, 0)

		// A stream of distinct sequence numbers, then a permutation of it: the
		// arrival order is arbitrary, which is the whole point of the buffer.
		// Numbers are drawn from a window with holes in it, so permanent gaps and
		// stragglers both occur.
		population := rapid.SliceOfNDistinct(
			rapid.Uint64Range(0, 15), 0, 10,
			func(u uint64) uint64 { return u },
		).Draw(rt, "sequences")
		arrivals := rapid.Permutation(population).Draw(rt, "arrivalOrder")

		// Duplicates are injected by replaying some arrivals.
		var stream []uint64
		for i, seq := range arrivals {
			stream = append(stream, seq)
			if len(arrivals) > 0 && rapid.Bool().Draw(rt, "replay"+string(rune('a'+i))) {
				stream = append(stream, seq)
			}
		}

		presentedCount := map[uint64]int{}
		acknowledged := map[uint64]int{}
		duplicatesSeen := 0

		present := func(items []inbound, what string) {
			// Every batch a single call returns is ascending, which is the
			// "ascending within a contiguous run" half of the property.
			for i := 1; i < len(items); i++ {
				if items[i].Sequence <= items[i-1].Sequence {
					rt.Fatalf("%s returned %d after %d, want ascending",
						what, items[i].Sequence, items[i-1].Sequence)
				}
			}
			for _, item := range items {
				presentedCount[item.Sequence]++
				if item.Content == "" || item.SenderName == "" || item.ReceivedAt.IsZero() {
					rt.Fatalf("%s presented an incomplete item: %+v", what, item)
				}
			}
		}

		for step, seq := range stream {
			// Req 5.10: a duplicate is always acknowledged, and never presented a
			// second time.
			accepted := tracker.AcceptInbound(seq)
			acknowledged[seq]++
			if !accepted {
				duplicatesSeen++
				continue
			}

			present(buffer.Offer(seq, inbound{
				Sequence:   seq,
				Content:    "payload",
				SenderName: "peer",
				ReceivedAt: clk.Now(),
			}), "Offer")

			// Time passes between arrivals, sometimes past the hold.
			clk.advance(rapid.SampledFrom([]time.Duration{
				0, time.Second, ReorderHold / 2, ReorderHold, 2 * ReorderHold,
			}).Draw(rt, "gap"+string(rune('a'+step%26))))

			present(buffer.DrainExpired(), "DrainExpired")

			// Req 5.7: nothing is withheld for longer than the hold. After a drain
			// at this instant, no held item may already be past its deadline.
			for _, held := range buffer.PendingSequences() {
				deadline, ok := buffer.DeadlineFor(held)
				if !ok {
					rt.Fatalf("step %d: pending sequence %d has no deadline", step, held)
				}
				if clk.Now().After(deadline) {
					rt.Fatalf("step %d: sequence %d withheld past its %s deadline",
						step, held, ReorderHold)
				}
			}
		}

		// Close the stream: once the hold has certainly expired, everything held
		// must come out.
		clk.advance(2 * ReorderHold)
		present(buffer.DrainExpired(), "final DrainExpired")

		if buffer.PendingCount() != 0 {
			rt.Fatalf("%d items still held after the hold expired: %v",
				buffer.PendingCount(), buffer.PendingSequences())
		}

		// Every distinct arrival is presented exactly once, duplicates included.
		for _, seq := range population {
			if presentedCount[seq] != 1 {
				rt.Fatalf("sequence %d presented %d times, want exactly 1",
					seq, presentedCount[seq])
			}
		}
		if len(presentedCount) != len(population) {
			rt.Fatalf("presented %d distinct sequences, want %d",
				len(presentedCount), len(population))
		}
		// Every arrival was acknowledged, duplicate or not (Req 5.10).
		for _, seq := range stream {
			if acknowledged[seq] == 0 {
				rt.Fatalf("sequence %d was never acknowledged", seq)
			}
		}
		if tracker.InboundCount() != len(population) {
			rt.Fatalf("tracker accepted %d sequences, want %d",
				tracker.InboundCount(), len(population))
		}
	})
}

// TestReorderBufferInOrderStreamIsNeverWithheld is the common case: a stream with no
// gaps is presented as it arrives, with nothing held and no clock involved.
//
// Requirements: 5.7
func TestReorderBufferInOrderStreamIsNeverWithheld(t *testing.T) {
	clk := newManualClock()
	b := NewReorderBuffer[inbound](clk, 0)

	for seq := uint64(0); seq < 5; seq++ {
		got := b.Offer(seq, inbound{Sequence: seq})
		if len(got) != 1 || got[0].Sequence != seq {
			t.Fatalf("sequence %d presented %v, want just itself", seq, got)
		}
		if b.PendingCount() != 0 {
			t.Fatalf("sequence %d was held despite arriving in order", seq)
		}
	}
	if b.NextExpected() != 5 {
		t.Fatalf("next expected is %d, want 5", b.NextExpected())
	}
}

// TestReorderBufferHoldsAGapThenReleasesAtTenSeconds pins the exact boundary of
// Req 5.7: held at 9.999s, released at 10s.
//
// Requirements: 5.7
func TestReorderBufferHoldsAGapThenReleasesAtTenSeconds(t *testing.T) {
	clk := newManualClock()
	b := NewReorderBuffer[inbound](clk, 0)

	// Sequence 1 arrives while 0 is missing.
	if got := b.Offer(1, inbound{Sequence: 1}); len(got) != 0 {
		t.Fatalf("sequence 1 presented %v while 0 was missing", got)
	}
	if b.PendingCount() != 1 {
		t.Fatal("sequence 1 was not held")
	}

	clk.advance(ReorderHold - time.Nanosecond)
	if got := b.DrainExpired(); len(got) != 0 {
		t.Fatalf("released %v one nanosecond before the hold elapsed", got)
	}

	clk.advance(time.Nanosecond)
	got := b.DrainExpired()
	if len(got) != 1 || got[0].Sequence != 1 {
		t.Fatalf("at exactly %s got %v, want sequence 1", ReorderHold, got)
	}
	if b.NextExpected() != 2 {
		t.Fatalf("next expected is %d, want 2 after skipping the gap", b.NextExpected())
	}
}

// TestReorderBufferLateArrivalFillsTheGapAndReleasesTheBacklog is the case the hold
// exists for: the missing Message shows up inside the window, so everything behind it
// is presented in ascending order at once.
//
// Requirements: 5.7
func TestReorderBufferLateArrivalFillsTheGapAndReleasesTheBacklog(t *testing.T) {
	clk := newManualClock()
	b := NewReorderBuffer[inbound](clk, 0)

	for _, seq := range []uint64{3, 1, 2} {
		if got := b.Offer(seq, inbound{Sequence: seq}); len(got) != 0 {
			t.Fatalf("sequence %d presented %v while 0 was missing", seq, got)
		}
	}
	clk.advance(ReorderHold / 2)

	got := b.Offer(0, inbound{Sequence: 0})
	if len(got) != 4 {
		t.Fatalf("filling the gap presented %d items, want 4", len(got))
	}
	for i, item := range got {
		if item.Sequence != uint64(i) {
			t.Fatalf("presented %d at position %d, want %d", item.Sequence, i, i)
		}
	}
	if b.PendingCount() != 0 {
		t.Fatal("items still held after the gap was filled")
	}
}

// TestReorderBufferHoldIsPerItemNotPerGap covers the case that makes DrainExpired
// scan every held item: the item whose deadline passes first is not the one that has
// to be presented first.
//
// Requirements: 5.7
func TestReorderBufferHoldIsPerItemNotPerGap(t *testing.T) {
	clk := newManualClock()
	b := NewReorderBuffer[inbound](clk, 0)

	// 5 arrives at t=0 behind a gap at 0.
	b.Offer(5, inbound{Sequence: 5})
	// 3 arrives at t=5s, so its own deadline is t=15s.
	clk.advance(5 * time.Second)
	b.Offer(3, inbound{Sequence: 3})

	// At t=10s sequence 5 has waited its full hold, so something must come out. It
	// cannot be 5 first without breaking ascending order, so 3 is released early.
	clk.advance(5 * time.Second)
	got := b.DrainExpired()
	if len(got) != 2 || got[0].Sequence != 3 || got[1].Sequence != 5 {
		t.Fatalf("got %v, want sequences 3 then 5", sequencesOf(got))
	}
	if b.PendingCount() != 0 {
		t.Fatal("items still held")
	}
}

// TestReorderBufferPresentsAStragglerRatherThanDroppingIt documents the choice made
// in Offer: a Message arriving after its gap was declared lost is still presented,
// because no requirement authorises discarding a non-duplicate.
//
// Requirements: 5.7
func TestReorderBufferPresentsAStragglerRatherThanDroppingIt(t *testing.T) {
	clk := newManualClock()
	b := NewReorderBuffer[inbound](clk, 0)

	b.Offer(1, inbound{Sequence: 1})
	clk.advance(ReorderHold)
	if got := b.DrainExpired(); len(got) != 1 {
		t.Fatalf("got %v, want sequence 1 released", sequencesOf(got))
	}

	// Sequence 0 finally arrives, long after the buffer moved past it.
	got := b.Offer(0, inbound{Sequence: 0})
	if len(got) != 1 || got[0].Sequence != 0 {
		t.Fatalf("straggler presented as %v, want sequence 0", sequencesOf(got))
	}
}

// TestReorderBufferStartsWhereTheSessionIs checks the firstExpected parameter, which
// is what lets a rebound Session resume mid-stream.
//
// Requirements: 3.4, 5.7
func TestReorderBufferStartsWhereTheSessionIs(t *testing.T) {
	clk := newManualClock()
	b := NewReorderBuffer[inbound](clk, 100)

	if got := b.Offer(100, inbound{Sequence: 100}); len(got) != 1 {
		t.Fatalf("got %v, want sequence 100 presented immediately", sequencesOf(got))
	}
	if got := b.Offer(102, inbound{Sequence: 102}); len(got) != 0 {
		t.Fatalf("got %v, want sequence 102 held behind the gap at 101", sequencesOf(got))
	}
	if _, ok := b.NextDeadline(); !ok {
		t.Fatal("no release deadline while an item is held")
	}
}

func sequencesOf(items []inbound) []uint64 {
	out := make([]uint64, 0, len(items))
	for _, i := range items {
		out = append(out, i.Sequence)
	}
	return out
}
