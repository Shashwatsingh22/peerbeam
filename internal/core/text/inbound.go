package text

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// The three things Req 5.3 requires before a text Message may be displayed. They are
// named constants because Req 5.4 requires the incomplete event to name each missing
// item, and an operator reading that event should see the same words each time.
const (
	ItemContent    = "message content"
	ItemSenderName = "sender display name"
	ItemTimestamp  = "receipt timestamp"
)

// DisplayableText is a text Message cleared for display, carrying exactly the three
// items Req 5.3 requires to be shown together.
type DisplayableText struct {
	Sequence   uint64
	Content    string
	SenderName string
	ReceivedAt time.Time
}

// WithholdError reports a Message withheld because of a fault in the payload itself:
// invalid UTF-8 (Req 5.6) or a payload over the accepted size (Req 5.9). Both
// requirements make the error name the offending sequence number, so it is a field
// rather than something the caller has to remember to add.
type WithholdError struct {
	Sequence uint64
	Error    string
}

// IncompleteText reports a Message withheld because something around it was missing
// (Req 5.4). Missing names each unavailable item and is never empty.
type IncompleteText struct {
	Sequence uint64
	Missing  []string
}

func (i *IncompleteText) String() string {
	return fmt.Sprintf("message %d is incomplete: %s missing",
		i.Sequence, strings.Join(i.Missing, ", "))
}

// InboundTextDisposition is a tagged result: exactly one of Display /
// DuplicateDiscard / WithholdWithError / Incomplete is set.
//
// Acknowledge is not one of the branches, because it is not an alternative to them.
// It is true in every case, which is the point of Req 5.5, 5.6, 5.9 and 5.10 taken
// together: the sender learns its Message arrived whether or not the receiver could
// show it. Req 5.4 is silent on acknowledgement, and this implementation
// acknowledges there too. A sender left waiting on a Message the receiver has
// already decided to withhold would retry or time out over a Message that was in
// fact received, which serves nobody.
type InboundTextDisposition struct {
	Display           *DisplayableText
	DuplicateDiscard  bool            // Req 5.10
	WithholdWithError *WithholdError  // Req 5.6, 5.9
	Incomplete        *IncompleteText // Req 5.4

	// Acknowledge is always true, and Sequence always carries the exact sequence
	// number received, never a re-derived or clamped one (Req 5.5).
	Acknowledge bool
	Sequence    uint64
}

// DispositionKind names the branch a disposition took.
type DispositionKind uint8

const (
	DisposeDisplay DispositionKind = iota
	DisposeDuplicate
	DisposeWithholdWithError
	DisposeIncomplete
	// DisposeInvalid means no branch was set. DisposeInboundText never returns it.
	DisposeInvalid
)

func (k DispositionKind) String() string {
	switch k {
	case DisposeDisplay:
		return "display"
	case DisposeDuplicate:
		return "duplicate discarded"
	case DisposeWithholdWithError:
		return "withheld with error"
	case DisposeIncomplete:
		return "withheld as incomplete"
	default:
		return "invalid"
	}
}

// Kind reports which single branch of the disposition holds.
func (d InboundTextDisposition) Kind() DispositionKind {
	switch {
	case d.Display != nil:
		return DisposeDisplay
	case d.DuplicateDiscard:
		return DisposeDuplicate
	case d.WithholdWithError != nil:
		return DisposeWithholdWithError
	case d.Incomplete != nil:
		return DisposeIncomplete
	default:
		return DisposeInvalid
	}
}

// Displayed reports whether the content reaches the user. Everything except the
// Display branch withholds it.
func (d InboundTextDisposition) Displayed() bool { return d.Display != nil }

// DisposeInboundText decides what happens to one received text Message. It is a pure
// function: it displays nothing, sends nothing, and closes nothing, so "keep the
// Session active" in Req 5.4 and Req 5.9 holds by construction rather than by
// discipline. The caller performs the acknowledgement and the display.
//
// senderDisplayName and receivedAt are pointers because Req 5.4 distinguishes an
// item that is *unavailable* from one that is empty or zero. A nil pointer means the
// node could not determine it; an empty string or zero time means it determined
// something unusable, which is treated the same way.
//
// The checks run in a fixed order, and the order is the contract because several can
// hold at once:
//
//  1. Already seen (Req 5.10). A duplicate is discarded whatever else is true of it:
//     the content was displayed the first time, so re-examining it could only lead
//     to displaying it twice.
//  2. Payload too large (Req 5.9), then invalid UTF-8 (Req 5.6). These are faults in
//     the Message itself and produce an error naming the sequence number.
//  3. Missing items (Req 5.4). This produces an incomplete event rather than an
//     error, because nothing was wrong with what arrived; something around it was
//     absent.
//  4. Otherwise display (Req 5.3).
//
// Payload faults precede missing items because they are unambiguous protocol errors
// the sender can act on, whereas a missing display name or timestamp is a local
// bookkeeping gap. A Message that is both oversized and missing its sender name is
// reported as oversized, and the sender is told the one thing it can fix.
func DisposeInboundText(
	sequence uint64,
	payload []byte,
	senderDisplayName *string,
	receivedAt *time.Time,
	alreadySeen bool,
) InboundTextDisposition {
	// Every branch acknowledges the exact sequence number received.
	base := InboundTextDisposition{Acknowledge: true, Sequence: sequence}

	// 1. Req 5.10: discard the duplicate, acknowledge it, display once only.
	if alreadySeen {
		base.DuplicateDiscard = true
		return base
	}

	// 2a. Req 5.9: over the accepted payload size. The error names the sequence
	// number and the maximum, which is what the requirement asks for.
	if len(payload) > TextMaxBytes {
		base.WithholdWithError = &WithholdError{
			Sequence: sequence,
			Error: fmt.Sprintf("payload is %d bytes, maximum accepted is %d bytes",
				len(payload), TextMaxBytes),
		}
		return base
	}

	// 2b. Req 5.6: malformed UTF-8. Checked with utf8.Valid rather than by
	// converting, so nothing is silently repaired into replacement characters.
	// An empty payload is well-formed UTF-8 and falls through to the missing-items
	// check below, where Req 5.4 already has a name for it.
	if len(payload) > 0 && !utf8.Valid(payload) {
		base.WithholdWithError = &WithholdError{
			Sequence: sequence,
			Error:    "payload is not valid UTF-8",
		}
		return base
	}

	// 3. Req 5.4: any of the three items Req 5.3 needs is unavailable.
	var missing []string
	if len(payload) == 0 {
		missing = append(missing, ItemContent)
	}
	if senderDisplayName == nil || *senderDisplayName == "" {
		missing = append(missing, ItemSenderName)
	}
	if receivedAt == nil || receivedAt.IsZero() {
		missing = append(missing, ItemTimestamp)
	}
	if len(missing) > 0 {
		base.Incomplete = &IncompleteText{Sequence: sequence, Missing: missing}
		return base
	}

	// 4. Req 5.3: content, sender name, and timestamp are all present, and the
	// payload is valid UTF-8 within the accepted size. The conversion cannot fail
	// here, since utf8.Valid already passed.
	content, _ := DecodeStrictUTF8(payload)
	base.Display = &DisplayableText{
		Sequence:   sequence,
		Content:    content,
		SenderName: *senderDisplayName,
		ReceivedAt: *receivedAt,
	}
	return base
}
