package text

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

func ptr[T any](v T) *T { return &v }

// TestProperty21InboundTextIsAlwaysAcknowledgedAndDisplayedOnlyWhenValid covers
// Property 21: Inbound text is always acknowledged and displayed only when valid and
// complete.
//
// Validates: Requirements 5.3, 5.4, 5.5, 5.6, 5.9
func TestProperty21InboundTextIsAlwaysAcknowledgedAndDisplayedOnlyWhenValid(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		sequence := rapid.Uint64().Draw(rt, "sequence")

		payload := rapid.OneOf(
			rapid.SliceOfN(rapid.Byte(), 0, 64),
			rapid.Custom(func(t *rapid.T) []byte {
				return []byte(rapid.StringN(0, 64, -1).Draw(t, "text"))
			}),
			rapid.SampledFrom([][]byte{
				nil,
				[]byte("hello"),
				{0xff, 0xfe},                            // malformed
				bytes.Repeat([]byte{'x'}, TextMaxBytes), // at the limit
				bytes.Repeat([]byte{'x'}, TextMaxBytes+1), // over the limit
			}),
		).Draw(rt, "payload")

		// nil models "the node could not determine this item"; the empty and zero
		// values model "it determined something unusable". Req 5.4 treats both as
		// unavailable.
		senderName := rapid.SampledFrom([]*string{nil, ptr(""), ptr("laptop")}).
			Draw(rt, "senderName")
		receivedAt := rapid.SampledFrom([]*time.Time{nil, ptr(time.Time{}), ptr(baseTime)}).
			Draw(rt, "receivedAt")
		alreadySeen := rapid.Bool().Draw(rt, "alreadySeen")

		got := DisposeInboundText(sequence, payload, senderName, receivedAt, alreadySeen)

		// Req 5.5: an acknowledgement carrying that exact sequence number, always.
		if !got.Acknowledge {
			rt.Fatalf("sequence %d was not acknowledged (%s)", sequence, got.Kind())
		}
		if got.Sequence != sequence {
			rt.Fatalf("acknowledged sequence %d, want %d", got.Sequence, sequence)
		}

		// Exactly one branch is set.
		set := 0
		if got.Display != nil {
			set++
		}
		if got.DuplicateDiscard {
			set++
		}
		if got.WithholdWithError != nil {
			set++
		}
		if got.Incomplete != nil {
			set++
		}
		if set != 1 {
			rt.Fatalf("%d branches set in %+v, want exactly 1", set, got)
		}
		if got.Kind() == DisposeInvalid {
			rt.Fatalf("disposition %+v has no kind", got)
		}

		// The three conditions Req 5.3 requires for display.
		haveContent := len(payload) > 0
		haveName := senderName != nil && *senderName != ""
		haveTime := receivedAt != nil && !receivedAt.IsZero()
		withinSize := len(payload) <= TextMaxBytes
		wellFormed := utf8.Valid(payload)

		wantDisplay := !alreadySeen && haveContent && haveName && haveTime &&
			withinSize && wellFormed

		if got.Displayed() != wantDisplay {
			rt.Fatalf("displayed=%v, want %v (dup=%v content=%v name=%v time=%v size=%v utf8=%v)",
				got.Displayed(), wantDisplay,
				alreadySeen, haveContent, haveName, haveTime, withinSize, wellFormed)
		}

		switch got.Kind() {
		case DisposeDisplay:
			// All three items are shown together, and they are what arrived.
			if got.Display.Sequence != sequence {
				rt.Fatalf("displayed sequence %d, want %d", got.Display.Sequence, sequence)
			}
			if got.Display.Content != string(payload) {
				rt.Fatalf("displayed content %q, want %q", got.Display.Content, payload)
			}
			if got.Display.SenderName != *senderName {
				rt.Fatalf("displayed sender %q, want %q", got.Display.SenderName, *senderName)
			}
			if !got.Display.ReceivedAt.Equal(*receivedAt) {
				rt.Fatalf("displayed timestamp %s, want %s", got.Display.ReceivedAt, *receivedAt)
			}

		case DisposeDuplicate:
			// Req 5.10: only reachable for a Message already seen, and the content
			// is not carried anywhere.
			if !alreadySeen {
				rt.Fatal("duplicate branch taken for a first arrival")
			}

		case DisposeWithholdWithError:
			// Req 5.6, 5.9: the error names the sequence number and the fault.
			if got.WithholdWithError.Sequence != sequence {
				rt.Fatalf("error names sequence %d, want %d",
					got.WithholdWithError.Sequence, sequence)
			}
			if strings.TrimSpace(got.WithholdWithError.Error) == "" {
				rt.Fatal("withhold error carries no fault")
			}
			// Only a payload fault reaches this branch.
			if withinSize && wellFormed {
				rt.Fatalf("payload of %d valid bytes was withheld with error %q",
					len(payload), got.WithholdWithError.Error)
			}
			if !withinSize && !strings.Contains(got.WithholdWithError.Error,
				strconv.Itoa(TextMaxBytes)) {
				rt.Fatalf("oversize error %q does not name the maximum",
					got.WithholdWithError.Error)
			}

		case DisposeIncomplete:
			// Req 5.4: names the sequence number and exactly the unavailable items.
			if got.Incomplete.Sequence != sequence {
				rt.Fatalf("incomplete event names sequence %d, want %d",
					got.Incomplete.Sequence, sequence)
			}
			var wantMissing []string
			if !haveContent {
				wantMissing = append(wantMissing, ItemContent)
			}
			if !haveName {
				wantMissing = append(wantMissing, ItemSenderName)
			}
			if !haveTime {
				wantMissing = append(wantMissing, ItemTimestamp)
			}
			if len(wantMissing) == 0 {
				rt.Fatal("incomplete branch taken with nothing missing")
			}
			if len(got.Incomplete.Missing) != len(wantMissing) {
				rt.Fatalf("missing items %v, want %v", got.Incomplete.Missing, wantMissing)
			}
			for i := range wantMissing {
				if got.Incomplete.Missing[i] != wantMissing[i] {
					rt.Fatalf("missing items %v, want %v", got.Incomplete.Missing, wantMissing)
				}
			}
			if !strings.Contains(got.Incomplete.String(), strconv.FormatUint(sequence, 10)) {
				rt.Fatalf("rendered event %q does not name the sequence",
					got.Incomplete.String())
			}
		}

		// Determinism: nothing here reads a clock or any hidden state.
		again := DisposeInboundText(sequence, payload, senderName, receivedAt, alreadySeen)
		if again.Kind() != got.Kind() {
			rt.Fatalf("second call said %s, first said %s", again.Kind(), got.Kind())
		}
	})
}

// TestDisposeInboundTextPrecedence pins the order the checks run in, which decides
// what a Message failing several rules at once is reported as.
//
// Requirements: 5.4, 5.6, 5.9, 5.10
func TestDisposeInboundTextPrecedence(t *testing.T) {
	oversizeAndMalformed := append(bytes.Repeat([]byte{'x'}, TextMaxBytes), 0xff)

	cases := []struct {
		name       string
		payload    []byte
		senderName *string
		receivedAt *time.Time
		seen       bool
		want       DispositionKind
	}{
		{
			name:    "duplicate beats every other fault",
			payload: oversizeAndMalformed,
			seen:    true,
			want:    DisposeDuplicate,
		},
		{
			name:       "oversize beats malformed encoding",
			payload:    oversizeAndMalformed,
			senderName: ptr("laptop"),
			receivedAt: ptr(baseTime),
			want:       DisposeWithholdWithError,
		},
		{
			name:       "payload fault beats missing metadata",
			payload:    []byte{0xff, 0xfe},
			senderName: nil,
			receivedAt: nil,
			want:       DisposeWithholdWithError,
		},
		{
			name:       "missing metadata with a good payload is incomplete",
			payload:    []byte("hello"),
			senderName: nil,
			receivedAt: ptr(baseTime),
			want:       DisposeIncomplete,
		},
		{
			name:       "empty payload is reported as missing content",
			payload:    nil,
			senderName: ptr("laptop"),
			receivedAt: ptr(baseTime),
			want:       DisposeIncomplete,
		},
		{
			name:       "everything present displays",
			payload:    []byte("hello"),
			senderName: ptr("laptop"),
			receivedAt: ptr(baseTime),
			want:       DisposeDisplay,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DisposeInboundText(7, c.payload, c.senderName, c.receivedAt, c.seen)
			if got.Kind() != c.want {
				t.Fatalf("got %s, want %s", got.Kind(), c.want)
			}
			// Every case acknowledges sequence 7 and keeps the content off screen
			// unless it is the display case.
			if !got.Acknowledge || got.Sequence != 7 {
				t.Fatalf("acknowledgement is (%v, %d), want (true, 7)", got.Acknowledge, got.Sequence)
			}
			if (got.Kind() == DisposeDisplay) != got.Displayed() {
				t.Fatal("Displayed() disagrees with the branch")
			}
		})
	}
}

// TestDisposeInboundTextEmptyPayloadListsContentFirst pins the wording and order of
// the missing-items list, which Req 5.4 makes user-visible.
//
// Requirements: 5.4
func TestDisposeInboundTextEmptyPayloadListsContentFirst(t *testing.T) {
	got := DisposeInboundText(3, nil, nil, nil, false)
	if got.Incomplete == nil {
		t.Fatalf("got %s, want incomplete", got.Kind())
	}
	want := []string{ItemContent, ItemSenderName, ItemTimestamp}
	if len(got.Incomplete.Missing) != 3 {
		t.Fatalf("missing %v, want all three items", got.Incomplete.Missing)
	}
	for i, item := range want {
		if got.Incomplete.Missing[i] != item {
			t.Fatalf("missing[%d] = %q, want %q", i, got.Incomplete.Missing[i], item)
		}
	}
	if !strings.Contains(got.Incomplete.String(), ItemTimestamp) {
		t.Fatalf("rendered event %q omits an item", got.Incomplete.String())
	}
}

// TestDisposeInboundTextAtTheSizeBoundary checks that exactly 65,536 bytes is
// displayed and 65,537 is withheld, matching Req 5.2 against Req 5.9.
//
// Requirements: 5.2, 5.9
func TestDisposeInboundTextAtTheSizeBoundary(t *testing.T) {
	name, at := ptr("laptop"), ptr(baseTime)

	atLimit := DisposeInboundText(1, bytes.Repeat([]byte{'x'}, TextMaxBytes), name, at, false)
	if !atLimit.Displayed() {
		t.Fatalf("%d bytes got %s, want display", TextMaxBytes, atLimit.Kind())
	}

	overLimit := DisposeInboundText(2, bytes.Repeat([]byte{'x'}, TextMaxBytes+1), name, at, false)
	if overLimit.Kind() != DisposeWithholdWithError {
		t.Fatalf("%d bytes got %s, want withheld with error", TextMaxBytes+1, overLimit.Kind())
	}
	if !strings.Contains(overLimit.WithholdWithError.Error, "65536") {
		t.Fatalf("error %q does not name the maximum", overLimit.WithholdWithError.Error)
	}
	if !strings.Contains(overLimit.WithholdWithError.Error, "65537") {
		t.Fatalf("error %q does not name the offending size", overLimit.WithholdWithError.Error)
	}
}
