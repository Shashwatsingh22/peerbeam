package clipboard

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/peerbeam/peerbeam/internal/core/clock"
)

// PendingRetention is how long a pending clipboard entry survives without a user
// decision (Req 6.3, 6.9).
const PendingRetention = 10 * time.Minute

// SyncPollInterval is how often continuous sync reads the local clipboard. Req 6.5
// requires a change to be sent within 1 second, so the poll runs at twice that rate
// to leave room for the read and the send.
const SyncPollInterval = 500 * time.Millisecond

// Digest is a SHA-256 of clipboard content. Echo suppression compares digests rather
// than content (Req 6.6): a 1 MiB comparison on every poll of every Session would be
// the most expensive thing in the node, and a digest answers the same question in 32
// bytes.
type Digest []byte

// DigestOf returns the digest of content, or nil for empty content so that "nothing
// applied yet" and "applied an empty clipboard" stay distinguishable.
func DigestOf(content []byte) Digest {
	if len(content) == 0 {
		return nil
	}
	sum := sha256.Sum256(content)
	return sum[:]
}

// Equal compares two digests. A nil digest equals nothing, including another nil, so
// an unset LastAppliedDigest never suppresses anything.
func (d Digest) Equal(other Digest) bool {
	if len(d) == 0 || len(other) == 0 {
		return false
	}
	return bytes.Equal(d, other)
}

// PendingClipboardEntry is content held for a user decision (Req 6.3). It carries the
// sender's display name and the receipt timestamp because the prompt must show both.
type PendingClipboardEntry struct {
	Sequence    uint64
	Content     []byte
	SenderName  string
	ReceivedAt  time.Time
	PromptShown bool
}

// ExpiresAt is when the entry lapses without a decision (Req 6.9).
func (e PendingClipboardEntry) ExpiresAt() time.Time {
	return e.ReceivedAt.Add(PendingRetention)
}

// ClipboardSessionState is the per-Session clipboard policy state that
// DisposeInboundClipboard reads. It is passed by value so the decision is a pure
// function of it: the caller applies the resulting transition.
type ClipboardSessionState struct {
	// AutoApply switches between Req 6.2 (replace immediately) and Req 6.3 (hold
	// for confirmation).
	AutoApply bool
	// ContinuousSync is the opt-in poll-and-send loop of Req 6.5.
	ContinuousSync bool
	// LastAppliedDigest and LastSentDigest are the two things Req 6.6 compares
	// against to suppress an echo.
	LastAppliedDigest Digest
	LastSentDigest    Digest
	// Pending is the at-most-one entry per Session of Req 6.3.
	Pending *PendingClipboardEntry
}

// ClipboardReject reports a Message refused because of its payload (Req 6.10). The
// sequence number is a field because the requirement makes the error name it.
type ClipboardReject struct {
	Sequence uint64
	Reason   string
}

func (r *ClipboardReject) Error() string {
	return fmt.Sprintf("clipboard message %d rejected: %s", r.Sequence, r.Reason)
}

// HoldPending is the Req 6.3 branch: one entry retained, a prompt raised, and any
// earlier entry of the same Session discarded.
type HoldPending struct {
	Entry PendingClipboardEntry
	// ReplacedEarlier reports that an earlier pending entry was discarded to make
	// room for this one. The caller stops prompting for the old entry.
	ReplacedEarlier bool
	// ReplacedSequence is the discarded entry's sequence number, valid only when
	// ReplacedEarlier is true.
	ReplacedSequence uint64
}

// ClipboardDisposition is a tagged result: exactly one of ApplyNow / HoldPending /
// DiscardAsEcho / Reject is set.
type ClipboardDisposition struct {
	ApplyNow      []byte // Req 6.2: replace the entire clipboard with these bytes
	HoldPending   *HoldPending
	DiscardAsEcho bool // Req 6.6: silent, no prompt, clipboard untouched
	Reject        *ClipboardReject
}

// DispositionKind names the branch a disposition took.
type DispositionKind uint8

const (
	DisposeApplyNow DispositionKind = iota
	DisposeHoldPending
	DisposeDiscardAsEcho
	DisposeReject
	// DisposeInvalid means no branch was set. DisposeInboundClipboard never returns
	// it.
	DisposeInvalid
)

func (k DispositionKind) String() string {
	switch k {
	case DisposeApplyNow:
		return "apply now"
	case DisposeHoldPending:
		return "held pending"
	case DisposeDiscardAsEcho:
		return "discarded as echo"
	case DisposeReject:
		return "rejected"
	default:
		return "invalid"
	}
}

// Kind reports which single branch of the disposition holds.
func (d ClipboardDisposition) Kind() DispositionKind {
	switch {
	case d.ApplyNow != nil:
		return DisposeApplyNow
	case d.HoldPending != nil:
		return DisposeHoldPending
	case d.DiscardAsEcho:
		return DisposeDiscardAsEcho
	case d.Reject != nil:
		return DisposeReject
	default:
		return DisposeInvalid
	}
}

// ChangesClipboard reports whether this disposition writes to the local clipboard.
// Only ApplyNow does: Req 6.6, 6.9, and 6.10 all require the clipboard to be left
// alone, and holding an entry does not touch it either.
func (d ClipboardDisposition) ChangesClipboard() bool { return d.ApplyNow != nil }

// Prompts reports whether the user is asked to decide. Only the hold branch prompts;
// Req 6.6 is explicit that an echo raises no prompt.
func (d ClipboardDisposition) Prompts() bool { return d.HoldPending != nil }

// DisposeInboundClipboard decides what happens to one received clipboard Message. It
// is pure: it writes no clipboard, raises no prompt, and mutates no state, so
// "leave the local clipboard unchanged" in Req 6.6, 6.9, and 6.10 holds by
// construction. The caller performs the transition, and ApplyState records it.
//
// The checks run in a fixed order, and the order is the contract:
//
//  1. Payload validity (Req 6.10): over 1 MiB or not valid UTF-8. Checked first
//     because a payload that cannot be put on a clipboard is not worth comparing
//     against anything.
//  2. Echo (Req 6.6): identical to what this Session most recently applied or most
//     recently sent. Checked before the apply/hold split because the requirement
//     says an echo raises no prompt, so it must not reach the hold branch.
//  3. Auto-apply on (Req 6.2) or off (Req 6.3).
//
// Echo suppression is what stops two nodes with continuous sync enabled from
// bouncing one clipboard between them forever: A sends, B applies and records the
// digest as applied, B's poll sees the change, and the digest match stops it there.
func DisposeInboundClipboard(
	sequence uint64,
	payload []byte,
	state ClipboardSessionState,
	senderDisplayName string,
	receivedAt time.Time,
) ClipboardDisposition {
	// 1. Req 6.10: reject and name the sequence number.
	if len(payload) > ClipboardMaxBytes {
		return ClipboardDisposition{Reject: &ClipboardReject{
			Sequence: sequence,
			Reason: fmt.Sprintf("payload is %d bytes, maximum accepted is %d bytes",
				len(payload), ClipboardMaxBytes),
		}}
	}
	if len(payload) == 0 {
		// Nothing to apply. Reported as a rejection rather than silently ignored,
		// so the sender learns its Message was not usable.
		return ClipboardDisposition{Reject: &ClipboardReject{
			Sequence: sequence,
			Reason:   "payload carries no content",
		}}
	}
	if !utf8.Valid(payload) {
		return ClipboardDisposition{Reject: &ClipboardReject{
			Sequence: sequence,
			Reason:   "payload is not valid UTF-8",
		}}
	}

	// 2. Req 6.6: an echo of what we just applied or just sent on this Session.
	incoming := DigestOf(payload)
	if incoming.Equal(state.LastAppliedDigest) || incoming.Equal(state.LastSentDigest) {
		return ClipboardDisposition{DiscardAsEcho: true}
	}

	// Copy the payload: the caller's buffer may be a reused read buffer, and both
	// remaining branches hand these bytes on to be applied later.
	content := append([]byte(nil), payload...)

	// 3a. Req 6.2: replace the entire clipboard.
	if state.AutoApply {
		return ClipboardDisposition{ApplyNow: content}
	}

	// 3b. Req 6.3: hold exactly one entry per Session and prompt.
	hold := &HoldPending{Entry: PendingClipboardEntry{
		Sequence:   sequence,
		Content:    content,
		SenderName: senderDisplayName,
		ReceivedAt: receivedAt,
	}}
	if state.Pending != nil {
		hold.ReplacedEarlier = true
		hold.ReplacedSequence = state.Pending.Sequence
	}
	return ClipboardDisposition{HoldPending: hold}
}

// PendingOutcome is the result of resolving a pending entry.
type PendingOutcome uint8

const (
	// PendingApplied means the entry was confirmed inside its retention window and
	// the clipboard is replaced (Req 6.4).
	PendingApplied PendingOutcome = iota
	// PendingDeclined means the user declined; the entry is discarded and the
	// clipboard untouched (Req 6.9).
	PendingDeclined
	// PendingExpired means the retention window elapsed without a decision; same
	// effect as declining (Req 6.9).
	PendingExpired
	// PendingNone means there was no pending entry to resolve.
	PendingNone
)

func (o PendingOutcome) String() string {
	switch o {
	case PendingApplied:
		return "applied"
	case PendingDeclined:
		return "declined"
	case PendingExpired:
		return "expired"
	default:
		return "none"
	}
}

// SessionClipboard owns one Session's clipboard policy state and applies the
// transitions that DisposeInboundClipboard decides. The pure decision and the
// stateful application are separate so the rule table can be property-tested without
// a clipboard, and so the state machine has exactly one place that mutates it.
//
// Not safe for concurrent use: one Session, one goroutine.
type SessionClipboard struct {
	state ClipboardSessionState
	clk   clock.Clock
}

// NewSessionClipboard returns clipboard state with auto-apply and continuous sync
// both off, which is the safe default: nothing writes the user's clipboard and
// nothing leaves the machine until they ask.
func NewSessionClipboard(clk clock.Clock) *SessionClipboard {
	if clk == nil {
		clk = clock.NewRealClock()
	}
	return &SessionClipboard{clk: clk}
}

// State returns a copy of the current policy state, for DisposeInboundClipboard and
// for status output. It is a copy so a caller cannot reach in and change the pending
// entry behind the state machine's back.
func (c *SessionClipboard) State() ClipboardSessionState {
	snapshot := c.state
	if c.state.Pending != nil {
		entry := *c.state.Pending
		entry.Content = append([]byte(nil), c.state.Pending.Content...)
		snapshot.Pending = &entry
	}
	return snapshot
}

// SetAutoApply switches between Req 6.2 and Req 6.3 behaviour.
func (c *SessionClipboard) SetAutoApply(on bool) { c.state.AutoApply = on }

// SetContinuousSync enables or disables the Req 6.5 poll-and-send loop.
func (c *SessionClipboard) SetContinuousSync(on bool) { c.state.ContinuousSync = on }

// AutoApply reports whether received content is applied without a prompt.
func (c *SessionClipboard) AutoApply() bool { return c.state.AutoApply }

// ContinuousSync reports whether the poll-and-send loop is enabled.
func (c *SessionClipboard) ContinuousSync() bool { return c.state.ContinuousSync }

// Pending returns the held entry, or nil. Expiry is not applied here; call
// ExpirePending on the timer so the lapse is reported once rather than discovered
// silently by a reader.
func (c *SessionClipboard) Pending() *PendingClipboardEntry {
	return c.State().Pending
}

// Dispose decides on a received Message and records the resulting state change. It
// returns the same disposition DisposeInboundClipboard would, so the caller still
// knows what to do with the clipboard and the prompt.
//
// The ApplyNow branch records the applied digest here rather than making the caller
// remember to: forgetting it would break echo suppression and re-send the content
// straight back, and that is exactly the loop Req 6.6 exists to prevent.
func (c *SessionClipboard) Dispose(sequence uint64, payload []byte, senderDisplayName string) ClipboardDisposition {
	now := c.clk.Now()
	// Expire a lapsed entry first, so a new arrival is never reported as replacing
	// an entry that had already timed out.
	c.ExpirePending()

	d := DisposeInboundClipboard(sequence, payload, c.state, senderDisplayName, now)
	switch d.Kind() {
	case DisposeApplyNow:
		c.state.LastAppliedDigest = DigestOf(d.ApplyNow)
		c.state.Pending = nil
	case DisposeHoldPending:
		entry := d.HoldPending.Entry
		entry.PromptShown = true
		c.state.Pending = &entry
	}
	return d
}

// ConfirmPending applies the held entry if it is still inside its retention window
// (Req 6.4), or reports that it expired (Req 6.9). The returned content is what the
// caller writes to the clipboard, and is nil on every outcome except PendingApplied.
func (c *SessionClipboard) ConfirmPending() ([]byte, PendingOutcome) {
	if c.state.Pending == nil {
		return nil, PendingNone
	}
	if !c.clk.Now().Before(c.state.Pending.ExpiresAt()) {
		c.state.Pending = nil
		return nil, PendingExpired
	}
	content := c.state.Pending.Content
	c.state.Pending = nil
	c.state.LastAppliedDigest = DigestOf(content)
	return content, PendingApplied
}

// DeclinePending discards the held entry and leaves the clipboard alone (Req 6.9).
func (c *SessionClipboard) DeclinePending() PendingOutcome {
	if c.state.Pending == nil {
		return PendingNone
	}
	c.state.Pending = nil
	return PendingDeclined
}

// ExpirePending discards a held entry whose retention window has elapsed (Req 6.9)
// and reports the sequence number it dropped, so the caller can stop prompting for
// it. It returns false when nothing expired.
func (c *SessionClipboard) ExpirePending() (uint64, bool) {
	if c.state.Pending == nil {
		return 0, false
	}
	if c.clk.Now().Before(c.state.Pending.ExpiresAt()) {
		return 0, false
	}
	sequence := c.state.Pending.Sequence
	c.state.Pending = nil
	return sequence, true
}

// SendDecision is what continuous sync concluded about the current local clipboard.
type SendDecision struct {
	// Send is the content to send, or nil when nothing should be sent.
	Send []byte
	// Suppressed reports that content was present and valid but matched a digest,
	// so sending it would echo (Req 6.6).
	Suppressed bool
	// Check is the validity verdict, so a caller can report Req 6.7 or Req 6.11
	// without re-running the check.
	Check SendCheck
}

// DecideSend is the continuous-sync decision (Req 6.5): send the local clipboard only
// when it is valid, sendable, and differs from both the last content applied on this
// Session and the last content sent on it.
//
// Comparing against *both* digests is what makes the loop terminate. Comparing only
// against the applied digest would let a node re-send its own outbound content after
// a round trip; comparing only against the sent digest would let it echo back content
// it had just applied.
func (c *SessionClipboard) DecideSend(content []byte) SendDecision {
	check := CheckClipboardSend(content)
	if check.Kind() != SendValid {
		return SendDecision{Check: check}
	}
	digest := DigestOf(content)
	if digest.Equal(c.state.LastAppliedDigest) || digest.Equal(c.state.LastSentDigest) {
		return SendDecision{Suppressed: true, Check: check}
	}
	return SendDecision{Send: append([]byte(nil), content...), Check: check}
}

// RecordSent records content the node has sent on this Session, so the same content
// coming back is recognised as an echo (Req 6.6).
func (c *SessionClipboard) RecordSent(content []byte) {
	c.state.LastSentDigest = DigestOf(content)
}

// RecordApplied records content written to the local clipboard from this Session, for
// the same reason.
func (c *SessionClipboard) RecordApplied(content []byte) {
	c.state.LastAppliedDigest = DigestOf(content)
}
