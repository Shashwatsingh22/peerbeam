package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/clipboard"
	"github.com/peerbeam/peerbeam/internal/core/codec"
	"github.com/peerbeam/peerbeam/internal/core/report"
	"github.com/peerbeam/peerbeam/internal/core/session"
	"github.com/peerbeam/peerbeam/internal/core/transport"
	"github.com/peerbeam/peerbeam/internal/platform/clip"
)

// TestRouterAcknowledgesAndPresentsText covers Req 5.3, 5.5, and 5.7 at the router level: a received
// text is acknowledged with its exact sequence number and presented with all three required values.
//
// Requirements: 5.3, 5.5, 5.7
func TestRouterAcknowledgesAndPresentsText(t *testing.T) {
	node := newTestNode(t)
	display := NewMemoryTextDisplay()
	node.display = display

	s, b, _ := newWiredSession(t, node)
	reorder := session.NewReorderBuffer[InboundText](node.clk, 0)

	node.route(s, b, session.Message{
		Type:     uint8(codec.MsgText),
		Sequence: 0,
		Payload:  []byte("hello there"),
	}, reorder)

	// Req 5.3: presented with content, sender name, and receipt timestamp together.
	shown := display.Shown()
	if len(shown) != 1 {
		t.Fatalf("presented %d messages, want 1", len(shown))
	}
	if shown[0].Content != "hello there" {
		t.Fatalf("presented %q", shown[0].Content)
	}
	if shown[0].SenderName != s.DisplayName {
		t.Fatalf("presented sender %q, want %q", shown[0].SenderName, s.DisplayName)
	}
	if shown[0].ReceivedAt.IsZero() {
		t.Fatal("presented with no receipt timestamp")
	}

	// Req 5.5: an acknowledgement carrying that exact sequence number is queued.
	ack := drainControl(t, s)
	if len(ack) != 1 {
		t.Fatalf("queued %d control messages, want 1", len(ack))
	}
	if ack[0].Type != uint8(codec.MsgDeliveryAck) {
		t.Fatalf("queued type %d, want a delivery acknowledgement", ack[0].Type)
	}
	if ack[0].Sequence != 0 {
		t.Fatalf("the acknowledgement names sequence %d, want 0", ack[0].Sequence)
	}
	if !ack[0].Control {
		t.Fatal("the acknowledgement is not marked as control traffic")
	}
}

// TestRouterDiscardsADuplicateButStillAcknowledges covers Req 5.10.
//
// Requirements: 5.10
func TestRouterDiscardsADuplicateButStillAcknowledges(t *testing.T) {
	node := newTestNode(t)
	display := NewMemoryTextDisplay()
	node.display = display

	s, b, _ := newWiredSession(t, node)
	reorder := session.NewReorderBuffer[InboundText](node.clk, 0)

	message := session.Message{
		Type: uint8(codec.MsgText), Sequence: 0, Payload: []byte("once"),
	}
	node.route(s, b, message, reorder)
	node.route(s, b, message, reorder) // the same sequence again

	// Displayed once only.
	if shown := display.Shown(); len(shown) != 1 {
		t.Fatalf("presented %d times, want once", len(shown))
	}
	// Acknowledged both times, so the sender stops waiting either way.
	acks := drainControl(t, s)
	if len(acks) != 2 {
		t.Fatalf("queued %d acknowledgements, want 2", len(acks))
	}
	for i, ack := range acks {
		if ack.Type != uint8(codec.MsgDeliveryAck) || ack.Sequence != 0 {
			t.Fatalf("acknowledgement %d is %+v", i, ack)
		}
	}
}

// TestRouterPresentsInOrderAndReleasesAfterTheHold covers Req 5.7: a Message following a gap is
// withheld, and released once the hold elapses.
//
// Requirements: 5.7
func TestRouterPresentsInOrderAndReleasesAfterTheHold(t *testing.T) {
	node := newTestNode(t)
	display := NewMemoryTextDisplay()
	node.display = display

	s, b, _ := newWiredSession(t, node)
	reorder := session.NewReorderBuffer[InboundText](node.clk, 0)

	// Sequence 1 arrives while 0 is missing, so it is held.
	node.route(s, b, session.Message{
		Type: uint8(codec.MsgText), Sequence: 1, Payload: []byte("second"),
	}, reorder)
	if shown := display.Shown(); len(shown) != 0 {
		t.Fatalf("presented %v while sequence 0 was missing", shown)
	}
	// It is still acknowledged, because Req 5.5 does not wait for ordering.
	if acks := drainControl(t, s); len(acks) != 1 {
		t.Fatalf("queued %d acknowledgements for a held message", len(acks))
	}

	// The gap fills, so both are presented in order.
	node.route(s, b, session.Message{
		Type: uint8(codec.MsgText), Sequence: 0, Payload: []byte("first"),
	}, reorder)

	shown := display.Shown()
	if len(shown) != 2 {
		t.Fatalf("presented %d messages, want 2", len(shown))
	}
	if shown[0].Content != "first" || shown[1].Content != "second" {
		t.Fatalf("presented out of order: %q then %q", shown[0].Content, shown[1].Content)
	}
}

// TestRouterAnswersAKeepaliveAndMeasuresTheRoundTrip covers Req 3.1 and 2.7.
//
// Until the router existed nothing answered a keepalive, which meant a live link would trip the
// three-strike counter of Req 3.2 on its own. This is the test that would have caught that.
//
// Requirements: 2.7, 3.1, 3.2
func TestRouterAnswersAKeepaliveAndMeasuresTheRoundTrip(t *testing.T) {
	node := newTestNode(t)
	s, b, _ := newWiredSession(t, node)
	reorder := session.NewReorderBuffer[InboundText](node.clk, 0)

	// An inbound keepalive is answered with an acknowledgement carrying the same sequence number,
	// which is what lets the far side measure its round trip.
	node.route(s, b, session.Message{Type: uint8(codec.MsgKeepalive), Sequence: 42}, reorder)

	replies := drainControl(t, s)
	if len(replies) != 1 {
		t.Fatalf("queued %d replies to a keepalive, want 1", len(replies))
	}
	if replies[0].Type != uint8(codec.MsgKeepaliveAck) {
		t.Fatalf("replied with type %d, want a keepalive acknowledgement", replies[0].Type)
	}
	if replies[0].Sequence != 42 {
		t.Fatalf("the reply names sequence %d, want 42", replies[0].Sequence)
	}

	// An acknowledgement to a keepalive we sent clears the strike count and records the RTT.
	b.keepalive.OnTimeout()
	b.keepalive.OnTimeout()
	if b.keepalive.Misses() != 2 {
		t.Fatalf("the tracker holds %d misses", b.keepalive.Misses())
	}

	sentAt := node.clk.Now().Add(-30 * time.Millisecond)
	b.noteKeepaliveSent(7, sentAt)
	node.route(s, b, session.Message{Type: uint8(codec.MsgKeepaliveAck), Sequence: 7}, reorder)

	if b.keepalive.Misses() != 0 {
		t.Fatalf("an acknowledgement left %d misses counted", b.keepalive.Misses())
	}
	millis, measured := b.metrics.RTTMillis()
	if !measured {
		t.Fatal("no round-trip time was recorded")
	}
	if millis < 25 || millis > 40 {
		t.Fatalf("recorded a round trip of %d ms, want about 30", millis)
	}

	// An acknowledgement for a keepalive we never sent records nothing, rather than a nonsense
	// duration measured from the zero time.
	before, _ := b.metrics.RTTMillis()
	node.route(s, b, session.Message{Type: uint8(codec.MsgKeepaliveAck), Sequence: 999}, reorder)
	after, _ := b.metrics.RTTMillis()
	if before != after {
		t.Fatal("an unsolicited acknowledgement changed the round-trip measurement")
	}
}

// TestRouterAppliesClipboardContent covers Req 6.2 through the router: content arrives, is
// reassembled, and replaces the clipboard when auto-apply is on.
//
// Requirements: 6.2, 6.8
func TestRouterAppliesClipboardContent(t *testing.T) {
	node := newTestNode(t)
	s, b, _ := newWiredSession(t, node)
	reorder := session.NewReorderBuffer[InboundText](node.clk, 0)

	clipPort := node.Clipboard().(*clip.MemoryClipboardPort)
	node.ClipboardFor(s.Fingerprint).SetAutoApply(true)

	const content = "a link the peer copied"
	parts := clipboard.SplitClipboard([]byte(content))
	if len(parts) != 1 {
		t.Fatalf("%d bytes split into %d parts, want 1", len(content), len(parts))
	}

	node.route(s, b, session.Message{
		Type: uint8(codec.MsgClipboard), Sequence: 3, Payload: parts[0],
	}, reorder)

	// Req 6.2: the entire clipboard is replaced.
	got, hasText, err := clipPort.ReadText(context.Background())
	if err != nil {
		t.Fatalf("reading the clipboard: %v", err)
	}
	if !hasText || got != content {
		t.Fatalf("the clipboard holds (%q, %v), want %q", got, hasText, content)
	}
	// And it is acknowledged.
	if acks := drainControl(t, s); len(acks) != 1 || acks[0].Type != uint8(codec.MsgDeliveryAck) {
		t.Fatalf("queued %v, want one delivery acknowledgement", acks)
	}

	// Req 6.6: the same content coming back is discarded as an echo, and the clipboard is not
	// rewritten.
	writesBefore := clipPort.Writes()
	node.route(s, b, session.Message{
		Type: uint8(codec.MsgClipboard), Sequence: 4, Payload: parts[0],
	}, reorder)
	if clipPort.Writes() != writesBefore {
		t.Fatal("an echo rewrote the clipboard")
	}
}

// TestRouterHoldsClipboardForConfirmationWhenAutoApplyIsOff covers Req 6.3: the content is held, the
// clipboard is untouched, and a prompt is possible.
//
// Requirements: 6.3
func TestRouterHoldsClipboardForConfirmationWhenAutoApplyIsOff(t *testing.T) {
	node := newTestNode(t)
	s, b, _ := newWiredSession(t, node)
	reorder := session.NewReorderBuffer[InboundText](node.clk, 0)

	clipPort := node.Clipboard().(*clip.MemoryClipboardPort)
	clipPort.Set("original")
	// Auto-apply is off by default, which is the safe default: nothing writes the user's
	// clipboard until they ask.
	state := node.ClipboardFor(s.Fingerprint)
	if state.AutoApply() {
		t.Fatal("auto-apply defaults to on")
	}

	parts := clipboard.SplitClipboard([]byte("from the peer"))
	node.route(s, b, session.Message{
		Type: uint8(codec.MsgClipboard), Sequence: 1, Payload: parts[0],
	}, reorder)

	// Req 6.3: held as the single pending entry, with the sender's name and the receipt time.
	pending := state.Pending()
	if pending == nil {
		t.Fatal("nothing is pending after a clipboard message arrived")
	}
	if string(pending.Content) != "from the peer" {
		t.Fatalf("the pending entry holds %q", pending.Content)
	}
	if pending.SenderName != s.DisplayName {
		t.Fatalf("the pending entry names sender %q", pending.SenderName)
	}
	if pending.ReceivedAt.IsZero() {
		t.Fatal("the pending entry has no receipt time")
	}

	// The clipboard is untouched until the user confirms.
	got, _, _ := clipPort.ReadText(context.Background())
	if got != "original" {
		t.Fatalf("the clipboard changed to %q before confirmation", got)
	}
}

// TestRouterAcknowledgesChunksWithAbsoluteOffsets covers Req 7.2 and 7.3: a received chunk is recorded
// at its absolute offset and acknowledged with that offset, which is what makes a resume across a
// chunk-size change possible.
//
// Requirements: 3.5, 7.2, 7.3
func TestRouterAcknowledgesChunksWithAbsoluteOffsets(t *testing.T) {
	node := newTestNode(t)
	s, b, _ := newWiredSession(t, node)
	reorder := session.NewReorderBuffer[InboundText](node.clk, 0)

	chunkSize := b.transport.ChunkSizeBytes()
	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i)
	}

	// Chunk index 2 sits at two chunk sizes into the file.
	node.route(s, b, session.Message{
		Type: uint8(codec.MsgChunk), Sequence: 2, Payload: payload,
	}, reorder)

	chunks := b.ReceivedChunks()
	wantOffset := int64(2) * int64(chunkSize)
	stored, found := chunks[wantOffset]
	if !found {
		t.Fatalf("no chunk recorded at offset %d; recorded %v", wantOffset, keysOfChunks(chunks))
	}
	if len(stored) != len(payload) {
		t.Fatalf("the chunk is %d bytes, want %d", len(stored), len(payload))
	}
	if b.ReceivedBytes() != int64(len(payload)) {
		t.Fatalf("counted %d received bytes, want %d", b.ReceivedBytes(), len(payload))
	}

	// The acknowledgement carries the absolute offset and the length.
	acks := drainControl(t, s)
	if len(acks) != 1 || acks[0].Type != uint8(codec.MsgChunkAck) {
		t.Fatalf("queued %v, want one chunk acknowledgement", acks)
	}
	offset, length, ok := parseChunkAck(acks[0].Payload)
	if !ok {
		t.Fatalf("the acknowledgement payload is %d bytes", len(acks[0].Payload))
	}
	if offset != wantOffset {
		t.Fatalf("the acknowledgement names offset %d, want %d", offset, wantOffset)
	}
	if length != len(payload) {
		t.Fatalf("the acknowledgement names %d bytes, want %d", length, len(payload))
	}
}

func keysOfChunks(chunks map[int64][]byte) []int64 {
	out := make([]int64, 0, len(chunks))
	for offset := range chunks {
		out = append(out, offset)
	}
	return out
}

// TestRouterSkipsAnUnrecognisedTypeAndKeepsTheSessionActive covers Req 8.8 at the routing level.
//
// Requirements: 8.8
func TestRouterSkipsAnUnrecognisedTypeAndKeepsTheSessionActive(t *testing.T) {
	node := newTestNode(t)
	s, b, _ := newWiredSession(t, node)
	reorder := session.NewReorderBuffer[InboundText](node.clk, 0)

	node.route(s, b, session.Message{Type: 200, Sequence: 1, Payload: []byte("who knows")}, reorder)

	if !s.IsActive() {
		t.Fatal("an unrecognised message type closed the session")
	}
	// It is recorded, so an operator can see a newer peer is sending something this build does not
	// understand.
	entries := node.ports.Events.(*report.MemoryEventSink).Entries()
	found := false
	for _, entry := range entries {
		if strings.Contains(entry.Outcome, "unrecognised message type 200") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no event recorded the unrecognised type; events are %v", entries)
	}
}

// TestRouterRejectsKeyExchangeAfterTheHandshake covers the converse of Req 10.9: the keys are settled
// and a rebind reuses them (Req 10.4), so a late key exchange message is a protocol violation.
//
// Requirements: 10.4, 10.9
func TestRouterRejectsKeyExchangeAfterTheHandshake(t *testing.T) {
	node := newTestNode(t)
	s, b, _ := newWiredSession(t, node)
	reorder := session.NewReorderBuffer[InboundText](node.clk, 0)

	before := string(s.Keys)
	node.route(s, b, session.Message{
		Type: uint8(codec.MsgKeyExchangeInit), Sequence: 1, Payload: make([]byte, 160),
	}, reorder)

	// Req 10.4: the keys are unchanged; there is no re-key path.
	if string(s.Keys) != before {
		t.Fatal("a late key exchange message changed the session keys")
	}
	if !s.IsActive() {
		t.Fatal("the session closed instead of reporting a violation")
	}
}

// TestGoodputIsMeasuredNotZero covers Req 2.7: the sample reports the bytes moved in that second.
//
// Until the counters were wired the sampler recorded a hardcoded zero, which meant the status line's
// goodput column was always 0 B/s and the pending state was never reached honestly.
//
// Requirements: 2.7, 13.1
func TestGoodputIsMeasuredNotZero(t *testing.T) {
	node := newTestNode(t)
	_, b, _ := newWiredSession(t, node)

	// Nothing moved yet.
	if got := b.takeThroughput(); got != 0 {
		t.Fatalf("an idle binding reports %d bytes moved", got)
	}

	b.noteWritten(1000)
	b.recordChunk(0, make([]byte, 500))

	// The first sample reports everything since the start.
	if got := b.takeThroughput(); got != 1500 {
		t.Fatalf("reported %d bytes moved, want 1500", got)
	}
	// The window resets, so a sample is a rate rather than a running total.
	if got := b.takeThroughput(); got != 0 {
		t.Fatalf("a second sample with no traffic reports %d bytes", got)
	}

	b.noteWritten(200)
	if got := b.takeThroughput(); got != 200 {
		t.Fatalf("reported %d bytes in the second window, want 200", got)
	}
}

// TestPinIsStoredAndOverridesTheSwitchDecision covers Req 2.10 and 2.11: a pin is remembered and a
// pinned Session goes disconnected rather than rebinding.
//
// Until the pin was stored, `peerbeam pin` printed a confirmation and changed nothing.
//
// Requirements: 2.10, 2.11
func TestPinIsStoredAndOverridesTheSwitchDecision(t *testing.T) {
	node := newTestNode(t)
	fingerprint := strings.Repeat("ab", 32)

	if got := node.pinnedTransport(fingerprint); got != "" {
		t.Fatalf("a fresh node reports a pin of %q", got)
	}

	if err := node.SetPin(fingerprint, transport.NameBT); err != nil {
		t.Fatalf("pinning: %v", err)
	}
	if got := node.pinnedTransport(fingerprint); got != transport.NameBT {
		t.Fatalf("the pin is %q, want %s", got, transport.NameBT)
	}
	if got := node.Pins()[fingerprint]; got != transport.NameBT {
		t.Fatalf("Pins() reports %q", got)
	}

	// An unknown transport is refused rather than stored.
	if err := node.SetPin(fingerprint, "MC_Transport"); err == nil {
		t.Fatal("an unknown transport was accepted as a pin")
	}
	if got := node.pinnedTransport(fingerprint); got != transport.NameBT {
		t.Fatalf("a refused pin changed the stored one to %q", got)
	}

	// Req 2.11: with the pin set, an unavailable active Transport disconnects rather than
	// rebinding, and the reason names the pinned Transport.
	decision := transport.DecideSwitch(transport.SwitchInputs{
		ActiveTransportName:     transport.NameBT,
		ActiveExpectedGoodput:   transport.BTExpectedGoodput,
		BestCandidateName:       transport.NameLAN,
		BestCandidateGoodput:    transport.LANExpectedGoodput,
		PinnedTransportName:     node.pinnedTransport(fingerprint),
		ActiveIsAvailable:       false,
		ActiveUnavailableReason: "keepalive missed three times",
		Now:                     baseTime,
	})
	if decision.Kind() != transport.DecisionGoDisconnected {
		t.Fatalf("a pinned session got %s, want disconnect", decision.Kind())
	}
	if !strings.Contains(decision.GoDisconnected, transport.NameBT) {
		t.Fatalf("the reason %q does not name the pinned transport", decision.GoDisconnected)
	}

	// Releasing the pin restores rank-based switching.
	if err := node.SetPin(fingerprint, ""); err != nil {
		t.Fatalf("releasing: %v", err)
	}
	if got := node.pinnedTransport(fingerprint); got != "" {
		t.Fatalf("the pin survived a release as %q", got)
	}
}

// TestEnqueueControlDropsRatherThanBlocking checks the choice made when a control channel is full:
// dropping one acknowledgement is recoverable because the sender retries, whereas a blocked router
// would stop every other inbound message on that Session including its keepalives.
//
// Requirements: 4.6
func TestEnqueueControlDropsRatherThanBlocking(t *testing.T) {
	node := newTestNode(t)
	s, _, _ := newWiredSession(t, node)

	for len(s.Control) < cap(s.Control) {
		s.Control <- session.Message{Type: uint8(codec.MsgChunk), Control: true}
	}

	done := make(chan struct{})
	go func() {
		node.enqueueControl(s, codec.MsgDeliveryAck, 1, nil)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("enqueueControl blocked on a full channel")
	}

	// A closed session queues nothing rather than panicking on a closed channel.
	node.Sessions().Close(s.Id, "test")
	node.enqueueControl(s, codec.MsgDeliveryAck, 2, nil)
}

// drainControl reads everything queued on a Session's control channel.
func drainControl(t *testing.T, s *session.Session) []session.Message {
	t.Helper()
	var out []session.Message
	for {
		select {
		case message := <-s.Control:
			out = append(out, message)
		default:
			return out
		}
	}
}
