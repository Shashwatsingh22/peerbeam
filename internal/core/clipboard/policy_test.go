package clipboard

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"pgregory.net/rapid"
)

var baseTime = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

// manualClock is the injected time source. The 10-minute retention window of Req 6.3
// and 6.9 is checked by advancing it rather than waiting.
type manualClock struct{ now time.Time }

func newManualClock() *manualClock             { return &manualClock{now: baseTime} }
func (c *manualClock) Now() time.Time          { return c.now }
func (c *manualClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// TestProperty25InboundClipboardDispositionAndPendingLifecycle covers
// Property 25: Inbound clipboard disposition and the pending-entry lifecycle.
//
// Validates: Requirements 6.2, 6.3, 6.4, 6.9, 6.10
func TestProperty25InboundClipboardDispositionAndPendingLifecycle(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		clk := newManualClock()
		c := NewSessionClipboard(clk)
		c.SetAutoApply(rapid.Bool().Draw(rt, "autoApply"))

		// The clipboard the user would see, so "leave the local clipboard
		// unchanged" is checked against something rather than asserted.
		localClipboard := []byte("untouched")

		steps := rapid.IntRange(1, 20).Draw(rt, "steps")
		for step := 0; step < steps; step++ {
			switch rapid.SampledFrom([]string{
				"receive", "receive", "receive", "confirm", "decline", "advance", "toggle",
			}).Draw(rt, "op") {

			case "receive":
				payload := rapid.OneOf(
					rapid.SliceOfN(rapid.Byte(), 0, 32),
					rapid.Custom(func(t *rapid.T) []byte {
						return []byte(rapid.StringN(1, 32, -1).Draw(t, "text"))
					}),
					rapid.SampledFrom([][]byte{
						nil,
						[]byte("hello"),
						{0xff, 0xfe},
						bytes.Repeat([]byte{'a'}, ClipboardMaxBytes+1),
					}),
				).Draw(rt, "payload")

				sequence := uint64(step)
				hadPending := c.Pending()
				clipboardBefore := append([]byte(nil), localClipboard...)

				got := c.Dispose(sequence, payload, "laptop")

				// Exactly one branch.
				set := 0
				if got.ApplyNow != nil {
					set++
				}
				if got.HoldPending != nil {
					set++
				}
				if got.DiscardAsEcho {
					set++
				}
				if got.Reject != nil {
					set++
				}
				if set != 1 {
					rt.Fatalf("step %d: %d branches set in %+v", step, set, got)
				}

				switch got.Kind() {
				case DisposeReject:
					// Req 6.10: names the sequence number, clipboard untouched.
					if got.Reject.Sequence != sequence {
						rt.Fatalf("step %d: rejection names sequence %d, want %d",
							step, got.Reject.Sequence, sequence)
					}
					if !strings.Contains(got.Reject.Error(),
						strconv.FormatUint(sequence, 10)) {
						rt.Fatalf("step %d: error %q does not name the sequence",
							step, got.Reject.Error())
					}
					// Only an invalid payload is rejected.
					if len(payload) > 0 && len(payload) <= ClipboardMaxBytes &&
						utf8Valid(payload) {
						rt.Fatalf("step %d: valid %d-byte payload rejected: %s",
							step, len(payload), got.Reject.Reason)
					}

				case DisposeApplyNow:
					// Req 6.2: replaces the entire clipboard.
					if !c.AutoApply() {
						rt.Fatalf("step %d: applied while auto-apply was off", step)
					}
					localClipboard = append([]byte(nil), got.ApplyNow...)
					if !bytes.Equal(localClipboard, payload) {
						rt.Fatalf("step %d: applied content differs from the payload", step)
					}
					if c.Pending() != nil {
						rt.Fatalf("step %d: an entry is pending after an auto-apply", step)
					}

				case DisposeHoldPending:
					// Req 6.3: one entry, prompt carries sender and timestamp.
					if c.AutoApply() {
						rt.Fatalf("step %d: held an entry while auto-apply was on", step)
					}
					entry := got.HoldPending.Entry
					if entry.Sequence != sequence {
						rt.Fatalf("step %d: held entry names sequence %d, want %d",
							step, entry.Sequence, sequence)
					}
					if entry.SenderName != "laptop" {
						rt.Fatalf("step %d: prompt names sender %q", step, entry.SenderName)
					}
					if !entry.ReceivedAt.Equal(clk.Now()) {
						rt.Fatalf("step %d: prompt timestamp is %s, want %s",
							step, entry.ReceivedAt, clk.Now())
					}
					// Any earlier entry was discarded and reported.
					if hadPending != nil {
						if !got.HoldPending.ReplacedEarlier {
							rt.Fatalf("step %d: replaced an entry without reporting it", step)
						}
						if got.HoldPending.ReplacedSequence != hadPending.Sequence {
							rt.Fatalf("step %d: reported replacing %d, want %d",
								step, got.HoldPending.ReplacedSequence, hadPending.Sequence)
						}
					} else if got.HoldPending.ReplacedEarlier {
						rt.Fatalf("step %d: reported replacing an entry that did not exist", step)
					}

				case DisposeDiscardAsEcho:
					// Req 6.6: no prompt, clipboard untouched.
					if got.Prompts() {
						rt.Fatalf("step %d: an echo raised a prompt", step)
					}
				}

				// Only the apply branch may change the clipboard.
				if !got.ChangesClipboard() && !bytes.Equal(localClipboard, clipboardBefore) {
					rt.Fatalf("step %d: %s changed the clipboard", step, got.Kind())
				}

			case "confirm":
				pending := c.Pending()
				clipboardBefore := append([]byte(nil), localClipboard...)
				content, outcome := c.ConfirmPending()

				switch outcome {
				case PendingApplied:
					// Req 6.4: replaces the whole clipboard and clears the entry.
					if pending == nil {
						rt.Fatalf("step %d: applied with nothing pending", step)
					}
					if !bytes.Equal(content, pending.Content) {
						rt.Fatalf("step %d: applied content is not the held content", step)
					}
					if !clk.Now().Before(pending.ExpiresAt()) {
						rt.Fatalf("step %d: applied an entry past its window", step)
					}
					localClipboard = append([]byte(nil), content...)
				case PendingExpired:
					// Req 6.9: clipboard untouched.
					if content != nil {
						rt.Fatalf("step %d: expired outcome returned content", step)
					}
					if !bytes.Equal(localClipboard, clipboardBefore) {
						rt.Fatalf("step %d: expiry changed the clipboard", step)
					}
				case PendingNone:
					if pending != nil {
						rt.Fatalf("step %d: reported no entry while one was pending", step)
					}
				}
				if c.Pending() != nil {
					rt.Fatalf("step %d: an entry is still pending after a decision", step)
				}

			case "decline":
				pending := c.Pending()
				clipboardBefore := append([]byte(nil), localClipboard...)
				outcome := c.DeclinePending()

				if pending == nil && outcome != PendingNone {
					rt.Fatalf("step %d: declining nothing returned %s", step, outcome)
				}
				if pending != nil && outcome != PendingDeclined {
					rt.Fatalf("step %d: declining returned %s", step, outcome)
				}
				// Req 6.9: clipboard unchanged, no further prompt.
				if !bytes.Equal(localClipboard, clipboardBefore) {
					rt.Fatalf("step %d: declining changed the clipboard", step)
				}
				if c.Pending() != nil {
					rt.Fatalf("step %d: an entry survived a decline", step)
				}

			case "advance":
				clk.advance(rapid.SampledFrom([]time.Duration{
					time.Second, time.Minute, PendingRetention / 2, PendingRetention,
				}).Draw(rt, "advance"))

			case "toggle":
				c.SetAutoApply(rapid.Bool().Draw(rt, "newAutoApply"))
			}

			// Req 6.3: no Session ever holds more than one pending entry. The state
			// holds a single pointer, so the check that means something is that a
			// held entry is always inside its window once expiry has been applied.
			if p := c.Pending(); p != nil {
				if _, expired := c.ExpirePending(); expired {
					// Expiry is the caller's timer, so a lapsed entry here is
					// allowed; what must not happen is applying one.
					if content, outcome := c.ConfirmPending(); outcome == PendingApplied {
						rt.Fatalf("step %d: applied %d bytes from a lapsed entry",
							step, len(content))
					}
				}
			}
		}
	})
}

// TestProperty26ClipboardEchoSuppressionPreventsLoops covers
// Property 26: Clipboard echo suppression prevents loops.
//
// Validates: Requirements 6.5, 6.6
func TestProperty26ClipboardEchoSuppressionPreventsLoops(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		clk := newManualClock()
		c := NewSessionClipboard(clk)
		c.SetAutoApply(true)
		c.SetContinuousSync(true)

		applied := rapid.SampledFrom([][]byte{nil, []byte("applied"), []byte("shared")}).
			Draw(rt, "lastApplied")
		sent := rapid.SampledFrom([][]byte{nil, []byte("sent"), []byte("shared")}).
			Draw(rt, "lastSent")
		if applied != nil {
			c.RecordApplied(applied)
		}
		if sent != nil {
			c.RecordSent(sent)
		}

		content := rapid.SampledFrom([][]byte{
			nil, []byte("applied"), []byte("sent"), []byte("shared"), []byte("brand new"),
		}).Draw(rt, "content")

		// Inbound: an echo of either digest is discarded silently.
		inbound := c.Dispose(1, content, "laptop")
		isEcho := (applied != nil && bytes.Equal(content, applied)) ||
			(sent != nil && bytes.Equal(content, sent))

		if len(content) == 0 {
			if inbound.Kind() != DisposeReject {
				rt.Fatalf("empty payload got %s, want rejected", inbound.Kind())
			}
		} else if isEcho {
			if inbound.Kind() != DisposeDiscardAsEcho {
				rt.Fatalf("echo of %q got %s, want discarded", content, inbound.Kind())
			}
			if inbound.ChangesClipboard() || inbound.Prompts() {
				rt.Fatal("an echo changed the clipboard or prompted")
			}
		} else if inbound.Kind() != DisposeApplyNow {
			rt.Fatalf("new content got %s, want applied", inbound.Kind())
		}

		// Outbound: continuous sync sends exactly when the content matches neither
		// digest. Re-read the state, since applying inbound content updates it.
		state := c.State()
		digest := DigestOf(content)
		nowEcho := digest.Equal(state.LastAppliedDigest) || digest.Equal(state.LastSentDigest)

		decision := c.DecideSend(content)
		switch {
		case len(content) == 0:
			if decision.Send != nil || decision.Check.Kind() != SendUnsupported {
				rt.Fatalf("empty clipboard produced %+v", decision)
			}
		case nowEcho:
			if decision.Send != nil {
				rt.Fatalf("content matching a digest was sent")
			}
			if !decision.Suppressed {
				rt.Fatal("suppressed content was not reported as suppressed")
			}
		default:
			if decision.Send == nil {
				rt.Fatalf("content matching neither digest was not sent")
			}
			if !bytes.Equal(decision.Send, content) {
				rt.Fatal("sent content differs from the clipboard")
			}
		}
	})
}

// TestEchoSuppressionTerminatesATwoNodeLoop is the scenario Req 6.6 exists for, walked
// end to end: two nodes with continuous sync and auto-apply both on must exchange the
// content once and then stop.
//
// Requirements: 6.5, 6.6
func TestEchoSuppressionTerminatesATwoNodeLoop(t *testing.T) {
	a := NewSessionClipboard(newManualClock())
	b := NewSessionClipboard(newManualClock())
	for _, c := range []*SessionClipboard{a, b} {
		c.SetAutoApply(true)
		c.SetContinuousSync(true)
	}

	content := []byte("a link the user copied")

	// A's clipboard changes, so A sends.
	decision := a.DecideSend(content)
	if decision.Send == nil {
		t.Fatal("A did not send a fresh clipboard change")
	}
	a.RecordSent(decision.Send)

	// B receives and applies it.
	got := b.Dispose(1, decision.Send, "A")
	if got.Kind() != DisposeApplyNow {
		t.Fatalf("B got %s, want apply", got.Kind())
	}

	// B's own poll now sees the applied content. It must not send it back.
	if back := b.DecideSend(got.ApplyNow); back.Send != nil {
		t.Fatal("B echoed the content it had just applied")
	}

	// And if B did send it anyway, A would discard it rather than re-apply.
	if again := a.Dispose(2, content, "B"); again.Kind() != DisposeDiscardAsEcho {
		t.Fatalf("A got %s for its own content coming back, want discarded", again.Kind())
	}

	// A's poll on its own unchanged clipboard stays quiet too.
	if quiet := a.DecideSend(content); quiet.Send != nil {
		t.Fatal("A re-sent content it had already sent")
	}
}

// TestPendingEntryWindowBoundaries pins the exact 10-minute window of Req 6.3, 6.4,
// and 6.9.
//
// Requirements: 6.3, 6.4, 6.9
func TestPendingEntryWindowBoundaries(t *testing.T) {
	t.Run("confirmed one nanosecond before the window closes", func(t *testing.T) {
		clk := newManualClock()
		c := NewSessionClipboard(clk)
		c.Dispose(1, []byte("held"), "laptop")

		clk.advance(PendingRetention - time.Nanosecond)
		content, outcome := c.ConfirmPending()
		if outcome != PendingApplied {
			t.Fatalf("got %s, want applied", outcome)
		}
		if string(content) != "held" {
			t.Fatalf("applied %q, want %q", content, "held")
		}
	})

	t.Run("expired at exactly the window", func(t *testing.T) {
		clk := newManualClock()
		c := NewSessionClipboard(clk)
		c.Dispose(1, []byte("held"), "laptop")

		clk.advance(PendingRetention)
		if _, expired := c.ExpirePending(); !expired {
			t.Fatal("entry did not expire at exactly 10 minutes")
		}
		if c.Pending() != nil {
			t.Fatal("expired entry is still pending")
		}
		if _, outcome := c.ConfirmPending(); outcome != PendingNone {
			t.Fatalf("confirming after expiry got %s, want none", outcome)
		}
	})

	t.Run("confirming a lapsed entry applies nothing", func(t *testing.T) {
		clk := newManualClock()
		c := NewSessionClipboard(clk)
		c.Dispose(1, []byte("held"), "laptop")

		// No expiry sweep ran; the confirm itself must notice.
		clk.advance(PendingRetention + time.Second)
		content, outcome := c.ConfirmPending()
		if outcome != PendingExpired {
			t.Fatalf("got %s, want expired", outcome)
		}
		if content != nil {
			t.Fatal("expired confirm returned content")
		}
	})
}

// TestPendingEntryIsReplacedNotAccumulated pins the single-entry rule of Req 6.3.
//
// Requirements: 6.3
func TestPendingEntryIsReplacedNotAccumulated(t *testing.T) {
	c := NewSessionClipboard(newManualClock())

	first := c.Dispose(1, []byte("first"), "laptop")
	if first.HoldPending.ReplacedEarlier {
		t.Fatal("the first entry reported replacing something")
	}

	second := c.Dispose(2, []byte("second"), "laptop")
	if !second.HoldPending.ReplacedEarlier {
		t.Fatal("the second entry did not report replacing the first")
	}
	if second.HoldPending.ReplacedSequence != 1 {
		t.Fatalf("reported replacing sequence %d, want 1", second.HoldPending.ReplacedSequence)
	}

	// Confirming applies the newer entry, and there is only ever one.
	content, outcome := c.ConfirmPending()
	if outcome != PendingApplied || string(content) != "second" {
		t.Fatalf("applied %q with outcome %s, want \"second\" applied", content, outcome)
	}
	if c.Pending() != nil {
		t.Fatal("an entry survived the confirmation")
	}
}

// TestDisposeExpiresALapsedEntryBeforeReporting checks that a new arrival is not
// reported as replacing an entry that had already timed out.
//
// Requirements: 6.3, 6.9
func TestDisposeExpiresALapsedEntryBeforeReporting(t *testing.T) {
	clk := newManualClock()
	c := NewSessionClipboard(clk)
	c.Dispose(1, []byte("stale"), "laptop")

	clk.advance(PendingRetention + time.Minute)
	got := c.Dispose(2, []byte("fresh"), "laptop")

	if got.HoldPending == nil {
		t.Fatalf("got %s, want held", got.Kind())
	}
	if got.HoldPending.ReplacedEarlier {
		t.Fatal("reported replacing an entry that had already lapsed")
	}
}

// TestConfirmPendingRecordsTheAppliedDigest checks that a confirmed entry feeds echo
// suppression, so a manually confirmed clipboard does not get sent straight back.
//
// Requirements: 6.4, 6.6
func TestConfirmPendingRecordsTheAppliedDigest(t *testing.T) {
	c := NewSessionClipboard(newManualClock())
	c.SetContinuousSync(true)
	c.Dispose(1, []byte("held"), "laptop")

	content, outcome := c.ConfirmPending()
	if outcome != PendingApplied {
		t.Fatalf("got %s, want applied", outcome)
	}
	if decision := c.DecideSend(content); decision.Send != nil {
		t.Fatal("confirmed content was sent straight back")
	}
}

// TestStateReturnsACopy checks that a caller cannot reach through the snapshot and
// change the pending entry behind the state machine.
//
// Requirements: 6.3
func TestStateReturnsACopy(t *testing.T) {
	c := NewSessionClipboard(newManualClock())
	c.Dispose(1, []byte("held"), "laptop")

	snapshot := c.State()
	snapshot.Pending.Content[0] = 'X'
	snapshot.Pending.Sequence = 99

	if got := c.Pending(); got.Sequence != 1 || string(got.Content) != "held" {
		t.Fatalf("state was mutated through the snapshot: %+v", got)
	}
}

// utf8Valid is the property's own statement of "is this text", used to predict the
// rejection branch of Req 6.10.
func utf8Valid(b []byte) bool { return utf8.Valid(b) }
