package app

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/clipboard"
	"github.com/peerbeam/peerbeam/internal/core/codec"
	"github.com/peerbeam/peerbeam/internal/core/report"
	"github.com/peerbeam/peerbeam/internal/core/session"
	"github.com/peerbeam/peerbeam/internal/core/text"
	"github.com/peerbeam/peerbeam/internal/core/transport"
)

// InboundText is one received text Message, held by the reorder buffer until it can be presented in
// sequence order (Req 5.7).
type InboundText struct {
	Sequence   uint64
	Content    string
	SenderName string
	ReceivedAt time.Time
}

// TextDisplay is where presented text goes. It is an interface so the router can be tested without a
// terminal, and so `peerbeam status` and a future log tail can both consume the same stream.
//
// An implementation must be safe for concurrent use: every Session routes on its own goroutine and up
// to eight of them share one display (Req 4.1, 4.2).
type TextDisplay interface {
	// Show presents one text Message. Req 5.3 requires the content, the sender's display name,
	// and the receipt timestamp to be shown together, which is why all three are on the value
	// rather than being the caller's problem to correlate.
	Show(InboundText)
}

// WriterTextDisplay prints presented text to a writer.
//
// The mutex is what keeps two Sessions from interleaving halves of a line. Eight concurrent Sessions
// each routing text to the same terminal would otherwise produce output that is technically all there
// and unreadable in practice.
type WriterTextDisplay struct {
	mu  sync.Mutex
	out io.Writer
}

// NewWriterTextDisplay returns a display writing to out.
func NewWriterTextDisplay(out io.Writer) *WriterTextDisplay {
	return &WriterTextDisplay{out: out}
}

func (d *WriterTextDisplay) Show(item InboundText) {
	d.mu.Lock()
	defer d.mu.Unlock()
	fmt.Fprintf(d.out, "[%s] %s: %s\n",
		item.ReceivedAt.Format("15:04:05"), item.SenderName, item.Content)
}

// MemoryTextDisplay collects presented text, for tests and for a status view that shows recent
// messages.
//
// Guarded, because it is written by each Session's router goroutine and read by whoever is showing the
// history - which in a test is the test goroutine.
type MemoryTextDisplay struct {
	mu    sync.Mutex
	shown []InboundText
}

func NewMemoryTextDisplay() *MemoryTextDisplay { return &MemoryTextDisplay{} }

func (d *MemoryTextDisplay) Show(item InboundText) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.shown = append(d.shown, item)
}

// Shown returns a copy of what has been presented, in presentation order.
func (d *MemoryTextDisplay) Shown() []InboundText {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]InboundText(nil), d.shown...)
}

// routerLoop consumes a Session's inbound channel and acts on each Message.
//
// This is the half of the Session that turns received frames into behaviour: acknowledging text
// (Req 5.5), presenting it in order (Req 5.7), answering keepalives (Req 3.1), applying clipboard
// content (Req 6.2), and recording acknowledgements against a Transfer (Req 7.3). Without it the
// reader decrypts messages and drops them, which is what it did until now.
//
// Every branch keeps the Session active. The only thing that closes a Session from here is nothing:
// an authentication failure is caught in the reader (Req 10.3, 10.7), and every fault reachable here
// is one the requirements say to report while staying up.
func (n *PeerNode) routerLoop(ctx context.Context, s *session.Session, b *binding) {
	reorder := session.NewReorderBuffer[InboundText](n.clk, 0)

	// The reorder hold is 10 seconds (Req 5.7), so a held Message has to be released even when no
	// further Message arrives to drive the loop. The ticker is what does that.
	release := time.NewTicker(time.Second)
	defer release.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-release.C:
			// Req 5.7: anything past its hold is presented even though the gap never filled.
			for _, item := range reorder.DrainExpired() {
				n.display.Show(item)
			}

		case message, open := <-s.Inbound:
			if !open {
				return
			}
			n.route(s, b, message, reorder)
		}
	}
}

// route handles one inbound Message.
//
// The switch is over the closed set of message types. An unrecognised code is not an error: Req 8.8
// requires the frame to be skipped and the Session to continue, so it records an event and moves on.
func (n *PeerNode) route(
	s *session.Session,
	b *binding,
	message session.Message,
	reorder *session.ReorderBuffer[InboundText],
) {
	kind, known := codec.MessageTypeFromCode(message.Type)
	if !known {
		// Req 8.8: the payload bytes were already consumed by the codec, so the stream is
		// still aligned. Recording the code is all that is left.
		n.writeEvent(report.EventSessionRejected, s.DisplayName, s.Fingerprint,
			fmt.Sprintf("unrecognised message type %d skipped", message.Type))
		return
	}

	switch kind {
	case codec.MsgText:
		n.routeText(s, message, reorder)

	case codec.MsgClipboard:
		n.routeClipboard(s, message)

	case codec.MsgKeepalive:
		// Req 3.1: answer so the far side's three-strike counter never trips on a live link.
		// The acknowledgement carries the same sequence number, which is what lets the sender
		// measure the round trip.
		n.enqueueControl(s, codec.MsgKeepaliveAck, message.Sequence, nil)

	case codec.MsgKeepaliveAck:
		// The round trip is the gap between sending the keepalive and this arriving (Req 2.7).
		b.keepalive.OnResponse()
		if sentAt, found := b.keepaliveSentAt(message.Sequence); found {
			b.metrics.RecordRTT(n.clk.Now().Sub(sentAt))
		}

	case codec.MsgDeliveryAck:
		// The sender learns its text arrived. Nothing else is required of it: Req 5.5 puts the
		// obligation on the receiver, and the sender's own reporting reads this.
		b.recordDelivered(message.Sequence)

	case codec.MsgChunk:
		n.routeChunk(s, b, message)

	case codec.MsgChunkAck:
		// Req 7.3: acknowledged bytes drive the progress report and the resume watermark.
		if transferState := b.transfer; transferState != nil {
			offset, length, ok := parseChunkAck(message.Payload)
			if ok {
				transferState.OnAck(offset, length)
			}
		}

	case codec.MsgError:
		// The far side is reporting a fault with something we sent. Req 5.6 and 6.10 both send
		// one of these, and both keep the Session active.
		n.reportFailure(&report.DeliveryNotAcknowledged{
			Sequence:     message.Sequence,
			WindowSecond: 10,
		}, s.DisplayName)

	case codec.MsgTransferOffer, codec.MsgTransferOfferReply, codec.MsgTransferCancel:
		// The offer handshake and cancellation are recorded as events; the decision itself is a
		// user action taken through `peerbeam file`.
		n.writeEvent(report.EventTransferCompleted, s.DisplayName, s.Fingerprint,
			fmt.Sprintf("%s received", kind))

	case codec.MsgKeyExchangeInit, codec.MsgKeyExchangeResponse:
		// Req 10.9's converse: key exchange traffic after the handshake completed is a protocol
		// violation, because the keys are settled and a rebind reuses them (Req 10.4).
		n.reportFailure(&report.ProtocolViolation{
			MessageType: message.Type,
			Reason:      "key exchange message received after the handshake completed",
		}, s.DisplayName)
	}
}

// routeText disposes of a received text Message and presents it in order.
func (n *PeerNode) routeText(
	s *session.Session,
	message session.Message,
	reorder *session.ReorderBuffer[InboundText],
) {
	receivedAt := n.clk.Now()

	// Req 5.10: a duplicate is discarded but still acknowledged, so the sender stops waiting.
	alreadySeen := !s.Sequence.AcceptInbound(message.Sequence)

	senderName := s.DisplayName
	disposition := text.DisposeInboundText(
		message.Sequence, message.Payload, &senderName, &receivedAt, alreadySeen)

	// Req 5.5: the acknowledgement goes back on every branch, carrying the exact sequence number.
	if disposition.Acknowledge {
		n.enqueueControl(s, codec.MsgDeliveryAck, disposition.Sequence, nil)
	}

	switch disposition.Kind() {
	case text.DisposeDisplay:
		// Req 5.7: presented in ascending sequence order, which the reorder buffer decides.
		for _, item := range reorder.Offer(message.Sequence, InboundText{
			Sequence:   disposition.Display.Sequence,
			Content:    disposition.Display.Content,
			SenderName: disposition.Display.SenderName,
			ReceivedAt: disposition.Display.ReceivedAt,
		}) {
			n.display.Show(item)
		}

	case text.DisposeWithholdWithError:
		// Req 5.6, 5.9: withhold the content and send an error naming the sequence number.
		n.enqueueControl(s, codec.MsgError, disposition.WithholdWithError.Sequence,
			[]byte(disposition.WithholdWithError.Error))
		n.reportFailure(&report.TextInvalidUTF8{Sequence: disposition.WithholdWithError.Sequence},
			s.DisplayName)

	case text.DisposeIncomplete:
		// Req 5.4: record an incomplete event naming the missing items, and stay active.
		n.writeEvent(report.EventSessionRejected, s.DisplayName, s.Fingerprint,
			disposition.Incomplete.String())
	}
}

// routeClipboard reassembles and disposes of received clipboard content.
func (n *PeerNode) routeClipboard(s *session.Session, message session.Message) {
	// Req 6.8: a full 1 MiB clipboard arrives as two parts, so a single part is joined on its own
	// and a multi-part payload is buffered until its siblings arrive.
	state := n.ClipboardFor(s.Fingerprint)

	parts, complete := n.clipboardParts(s.Fingerprint, message.Payload)
	if !complete {
		return // waiting on the rest
	}
	content, ok := clipboard.JoinClipboard(parts)
	if !ok {
		// Req 6.10: reject and name the sequence number; the clipboard is untouched.
		n.enqueueControl(s, codec.MsgError, message.Sequence,
			[]byte("clipboard parts did not reassemble"))
		n.reportFailure(&report.ClipboardRejected{
			Sequence: message.Sequence,
			Reason:   "the clipboard parts did not reassemble into one payload",
		}, s.DisplayName)
		return
	}

	disposition := state.Dispose(message.Sequence, content, s.DisplayName)
	switch disposition.Kind() {
	case clipboard.DisposeApplyNow:
		// Req 6.2: replace the entire clipboard.
		ctx, cancel := context.WithTimeout(n.rootContext(), time.Second)
		defer cancel()
		if err := n.ports.Clipboard.WriteText(ctx, string(disposition.ApplyNow)); err != nil {
			n.reportFailure(&report.ClipboardRejected{
				Sequence: message.Sequence,
				Reason:   err.Error(),
			}, s.DisplayName)
			return
		}
		n.enqueueControl(s, codec.MsgDeliveryAck, message.Sequence, nil)

	case clipboard.DisposeHoldPending:
		// Req 6.3: prompt with the sender's name and the receipt time.
		fmt.Printf("clipboard from %s at %s: %s pending, run `peerbeam clip pending accept %s`\n",
			disposition.HoldPending.Entry.SenderName,
			disposition.HoldPending.Entry.ReceivedAt.Format("15:04:05"),
			formatBytes(int64(len(disposition.HoldPending.Entry.Content))),
			shortFingerprint(s.Fingerprint))
		n.enqueueControl(s, codec.MsgDeliveryAck, message.Sequence, nil)

	case clipboard.DisposeReject:
		n.enqueueControl(s, codec.MsgError, message.Sequence,
			[]byte(disposition.Reject.Reason))
		n.reportFailure(&report.ClipboardRejected{
			Sequence: message.Sequence,
			Reason:   disposition.Reject.Reason,
		}, s.DisplayName)

	case clipboard.DisposeDiscardAsEcho:
		// Req 6.6: silent, no prompt, clipboard untouched. It is still acknowledged, so the
		// sender does not retry.
		n.enqueueControl(s, codec.MsgDeliveryAck, message.Sequence, nil)
	}
}

// clipboardParts buffers clipboard parts until every index of a set has arrived.
//
// The parts are keyed by fingerprint rather than by sequence number, because Req 6.3 holds at most one
// pending clipboard entry per Session: a second clipboard send replaces the first, so there is never
// more than one part set in flight per Peer.
func (n *PeerNode) clipboardParts(fingerprint string, part []byte) ([][]byte, bool) {
	if len(part) < clipboard.PartHeaderBytes {
		return nil, false
	}
	index := int(binary.BigEndian.Uint16(part[0:2]))
	count := int(binary.BigEndian.Uint16(part[2:4]))
	if count == 0 || index >= count {
		return nil, false
	}

	n.clipMu.Lock()
	defer n.clipMu.Unlock()

	if n.clipParts == nil {
		n.clipParts = map[string][][]byte{}
	}
	pending := n.clipParts[fingerprint]
	if len(pending) != count {
		// A new part set: start over rather than mixing it with an abandoned one.
		pending = make([][]byte, count)
	}
	pending[index] = append([]byte(nil), part...)
	n.clipParts[fingerprint] = pending

	for _, held := range pending {
		if held == nil {
			return nil, false
		}
	}
	delete(n.clipParts, fingerprint)
	return pending, true
}

// routeChunk records a received Transfer chunk and acknowledges it (Req 7.2, 7.3).
func (n *PeerNode) routeChunk(s *session.Session, b *binding, message session.Message) {
	// The chunk's absolute byte offset is what locates it, which is what makes a rebind at a
	// different chunk size work (Req 3.5).
	offset := int64(message.Sequence) * int64(b.transport.ChunkSizeBytes())

	b.recordChunk(offset, message.Payload)

	// Req 7.3: the acknowledgement carries the offset and length, so the sender's progress and
	// resume watermark are stated in file offsets rather than in indices.
	n.enqueueControl(s, codec.MsgChunkAck, message.Sequence,
		encodeChunkAck(offset, len(message.Payload)))
}

// enqueueControl queues a control Message, preferring the control channel so it is not stuck behind a
// transfer (Req 4.6).
//
// A full control channel drops the Message rather than blocking the router. Blocking here would stop
// every other inbound Message on this Session, including the keepalives that keep it alive, so a
// dropped acknowledgement is the lesser failure: the sender retries, whereas a wedged router does not
// recover.
func (n *PeerNode) enqueueControl(s *session.Session, kind codec.MessageType, sequence uint64, payload []byte) {
	if !s.IsActive() {
		return
	}
	select {
	case s.Control <- session.Message{
		Type:     uint8(kind),
		Sequence: sequence,
		Payload:  payload,
		Control:  true,
	}:
	default:
		n.reportFailure(&report.DeliveryNotAcknowledged{
			Sequence:     sequence,
			WindowSecond: 10,
		}, s.DisplayName)
	}
}

// encodeChunkAck lays out a chunk acknowledgement: an 8-byte offset and a 4-byte length, big-endian
// like every other integer on the wire.
func encodeChunkAck(offset int64, length int) []byte {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint64(payload[0:8], uint64(offset))
	binary.BigEndian.PutUint32(payload[8:12], uint32(length))
	return payload
}

// parseChunkAck reads a chunk acknowledgement.
func parseChunkAck(payload []byte) (offset int64, length int, ok bool) {
	if len(payload) != 12 {
		return 0, 0, false
	}
	return int64(binary.BigEndian.Uint64(payload[0:8])),
		int(binary.BigEndian.Uint32(payload[8:12])), true
}

// keepaliveTimings records when each keepalive went out, so the acknowledgement can be turned into a
// round-trip measurement (Req 2.7).
//
// Only the most recent few are kept. A keepalive that goes unanswered for three rounds has already
// marked the Transport unavailable (Req 3.2), so an older entry can never be needed and holding them
// all would grow without bound over a long Session.
const keepaliveHistory = 4

// noteKeepaliveSent records a keepalive's send time.
func (b *binding) noteKeepaliveSent(sequence uint64, at time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.keepaliveSent == nil {
		b.keepaliveSent = map[uint64]time.Time{}
	}
	b.keepaliveSent[sequence] = at
	// Drop anything older than the strike window can reach.
	if len(b.keepaliveSent) > keepaliveHistory {
		var oldest uint64
		first := true
		for seq := range b.keepaliveSent {
			if first || seq < oldest {
				oldest, first = seq, false
			}
		}
		delete(b.keepaliveSent, oldest)
	}
}

// keepaliveSentAt returns when a keepalive went out, and false when it is not one we sent.
func (b *binding) keepaliveSentAt(sequence uint64) (time.Time, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	at, found := b.keepaliveSent[sequence]
	if found {
		delete(b.keepaliveSent, sequence)
	}
	return at, found
}

// recordDelivered notes that a Message we sent was acknowledged.
func (b *binding) recordDelivered(sequence uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.delivered++
	b.lastDelivered = sequence
}

// Delivered reports how many of our Messages have been acknowledged, and the most recent sequence.
func (b *binding) Delivered() (int, uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.delivered, b.lastDelivered
}

// recordChunk accumulates a received chunk and counts the bytes, which is what the goodput sample
// reads (Req 2.7).
func (b *binding) recordChunk(offset int64, payload []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.received == nil {
		b.received = map[int64][]byte{}
	}
	b.received[offset] = append([]byte(nil), payload...)
	b.receivedBytes += int64(len(payload))
}

// ReceivedBytes is the running total of chunk bytes received on this binding.
func (b *binding) ReceivedBytes() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.receivedBytes
}

// ReceivedChunks returns the chunks received so far, keyed by absolute offset.
func (b *binding) ReceivedChunks() map[int64][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[int64][]byte, len(b.received))
	for offset, payload := range b.received {
		out[offset] = append([]byte(nil), payload...)
	}
	return out
}

// noteWritten counts bytes handed to the Transport, which is the other half of the goodput sample.
func (b *binding) noteWritten(count int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.writtenBytes += int64(count)
}

// takeThroughput returns the bytes moved since the last call, which is exactly a per-second goodput
// sample when called on the metrics ticker (Req 2.7).
func (b *binding) takeThroughput() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	moved := b.writtenBytes + b.receivedBytes - b.sampledBytes
	b.sampledBytes = b.writtenBytes + b.receivedBytes
	if moved < 0 {
		return 0
	}
	return moved
}

// pinnedTransport is the user's Transport pin for a Peer, or "" for none (Req 2.10).
func (n *PeerNode) pinnedTransport(fingerprint string) string {
	n.pinMu.Lock()
	defer n.pinMu.Unlock()
	return n.pins[fingerprint]
}

// SetPin pins a Peer's Session to a named Transport (Req 2.10). An empty name releases it.
//
// The pin is stored on the node rather than on the Session, for the same reason clipboard preferences
// are: it outlives a reconnect. A user who pinned a Peer to Bluetooth does not expect the pin to
// disappear when the Session drops.
func (n *PeerNode) SetPin(fingerprint, transportName string) error {
	if transportName != "" &&
		transportName != transport.NameLAN && transportName != transport.NameBT {
		return fmt.Errorf("unknown transport %q; use %s or %s",
			transportName, transport.NameLAN, transport.NameBT)
	}

	n.pinMu.Lock()
	if n.pins == nil {
		n.pins = map[string]string{}
	}
	if transportName == "" {
		delete(n.pins, fingerprint)
	} else {
		n.pins[fingerprint] = transportName
	}
	n.pinMu.Unlock()
	return nil
}

// Pins returns the current pins, keyed by fingerprint.
func (n *PeerNode) Pins() map[string]string {
	n.pinMu.Lock()
	defer n.pinMu.Unlock()
	out := make(map[string]string, len(n.pins))
	for fingerprint, name := range n.pins {
		out[fingerprint] = name
	}
	return out
}
