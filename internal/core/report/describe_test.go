package report

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// structFieldNames lists a struct's exported and unexported field names, so a test can assert
// that a type has nowhere to put content it must never carry.
func structFieldNames(v any) []string {
	t := reflect.TypeOf(v)
	out := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		out = append(out, t.Field(i).Name)
	}
	return out
}

// TestProperty40EveryFailureReportIsCompleteAndHarmsNoOtherSession covers
// Property 40: Every failure report is complete and harms no other Session.
//
// The "harms no other Session" half is structural rather than checked here: Describe is a
// pure function over one error value and has no access to a Session at all, so there is
// nothing it could touch. The session-isolation half is covered by Property 18 in
// internal/core/session, which walks a registry through failures and compares every other
// Session's state.
//
// Validates: Requirements 2.5, 2.9, 13.4, 13.7
func TestProperty40EveryFailureReportIsCompleteAndHarmsNoOtherSession(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		kinds := AllAppErrorKinds()
		err := rapid.SampledFrom(kinds).Draw(rt, "errorKind")
		peerName := rapid.SampledFrom([]string{"", "laptop", "デスクトップ"}).Draw(rt, "peerName")

		got := Describe(err, peerName)

		// Req 13.4: all four fields, every one non-empty.
		if !got.Complete() {
			rt.Fatalf("%T produced an incomplete failure, missing %v: %+v",
				err, got.Missing(), got)
		}

		// The peer is named even when no display name was known, so a report is never
		// anonymous.
		if peerName != "" && got.PeerDisplayName != peerName {
			rt.Fatalf("report names peer %q, want %q", got.PeerDisplayName, peerName)
		}
		if peerName == "" && got.PeerDisplayName != UnknownPeer {
			rt.Fatalf("report names peer %q, want %q", got.PeerDisplayName, UnknownPeer)
		}

		// The reason carries the error's own message, so nothing is lost in translation.
		if !strings.Contains(got.Reason, firstSentence(err.Error())) {
			rt.Fatalf("reason %q does not carry the error %q", got.Reason, err.Error())
		}

		// The remediation names a user action rather than restating the problem. Checked
		// as "it is not the reason again", which is the failure mode worth catching.
		if got.Remediation == got.Reason {
			rt.Fatalf("%T repeats its reason as the remediation", err)
		}

		// Rendering includes all four, so nothing is dropped at the display boundary.
		rendered := got.String()
		for _, want := range []string{got.Operation, got.PeerDisplayName, got.Reason, got.Remediation} {
			if !strings.Contains(rendered, want) {
				rt.Fatalf("rendered report omits %q:\n%s", want, rendered)
			}
		}

		// Determinism: Describe reads no clock and no state.
		if again := Describe(err, peerName); again != got {
			rt.Fatalf("Describe is not deterministic:\n%+v\n%+v", got, again)
		}
	})
}

// firstSentence trims an error message to its leading clause, so the containment check above
// tolerates a Describe branch that adds context around the error rather than requiring the
// whole string verbatim.
func firstSentence(s string) string {
	if i := strings.IndexAny(s, ":;"); i > 0 {
		return s[:i]
	}
	return s
}

// TestDescribeNamesEveryAttemptedTransportInOrder is the Req 2.5 half of Property 40: a
// connection failure lists each attempt, in the order they were made, with its reason.
//
// Requirements: 2.5, 13.4
func TestDescribeNamesEveryAttemptedTransportInOrder(t *testing.T) {
	err := &LadderAllFailed{Attempts: []TransportAttempt{
		{TransportName: "LAN_Transport", Reason: "did not connect within 3s"},
		{TransportName: "BT_Transport", Reason: "no bluetooth bridge is available"},
	}}

	got := Describe(err, "laptop")
	if !got.Complete() {
		t.Fatalf("incomplete failure: missing %v", got.Missing())
	}

	lanAt := strings.Index(got.Reason, "LAN_Transport")
	btAt := strings.Index(got.Reason, "BT_Transport")
	if lanAt < 0 || btAt < 0 {
		t.Fatalf("reason %q does not name both transports", got.Reason)
	}
	if lanAt > btAt {
		t.Fatalf("reason lists the transports out of attempt order: %q", got.Reason)
	}
	for _, reason := range []string{"did not connect within 3s", "no bluetooth bridge is available"} {
		if !strings.Contains(got.Reason, reason) {
			t.Fatalf("reason %q omits %q", got.Reason, reason)
		}
	}
}

// TestDescribeNamesBothTransportsOnASwitchFailure is the Req 2.9 half of Property 40.
//
// Requirements: 2.9, 13.4
func TestDescribeNamesBothTransportsOnASwitchFailure(t *testing.T) {
	got := Describe(&SwitchFailed{
		FromTransport: "BT_Transport",
		ToTransport:   "LAN_Transport",
		Reason:        "did not complete within 3s",
	}, "laptop")

	for _, want := range []string{"BT_Transport", "LAN_Transport", "did not complete within 3s"} {
		if !strings.Contains(got.Reason, want) {
			t.Fatalf("reason %q omits %q", got.Reason, want)
		}
	}
	// Req 2.9 keeps the session on its current transport, so the remediation must not tell
	// the user the session died.
	if !strings.Contains(got.Remediation, "stayed") {
		t.Fatalf("remediation %q does not say the session survived", got.Remediation)
	}
}

// TestDescribeCoversEveryKindWithoutTheFallback checks that no kind in the closed set reaches
// the default branch. Together with the exhaustive linter, this is what stands in for a
// compiler-checked exhaustive switch.
//
// Requirements: 13.4
func TestDescribeCoversEveryKindWithoutTheFallback(t *testing.T) {
	original := describeUnhandled
	t.Cleanup(func() { describeUnhandled = original })

	var unhandled []string
	describeUnhandled = func(err AppError, _ string) Failure {
		unhandled = append(unhandled, fmt.Sprintf("%T", err))
		return original(err, "")
	}

	for _, kind := range AllAppErrorKinds() {
		Describe(kind, "laptop")
	}
	if len(unhandled) > 0 {
		t.Fatalf("Describe has no branch for: %s", strings.Join(unhandled, ", "))
	}
}

// TestDescribeFallbackIsCompleteToo checks the safety net: an AppError kind that somehow has
// no branch still produces a complete, four-field report rather than a panic that would take
// down a node holding eight sessions.
//
// Requirements: 13.4
func TestDescribeFallbackIsCompleteToo(t *testing.T) {
	got := Describe(&unknownKind{}, "laptop")
	if !got.Complete() {
		t.Fatalf("the fallback produced an incomplete failure, missing %v", got.Missing())
	}
	if !strings.Contains(got.Reason, "unhandled") {
		t.Fatalf("the fallback reason %q does not say the kind was unhandled", got.Reason)
	}
}

type unknownKind struct{}

func (*unknownKind) isAppError()   {}
func (*unknownKind) Error() string { return "a kind added without a Describe branch" }

// TestProperty37LogsAndReportsNeverContainSecrets covers
// Property 37: Logs and reports never contain secrets.
//
// Validates: Requirements 10.6, 13.5
func TestProperty37LogsAndReportsNeverContainSecrets(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// A distinctive secret: payload bytes, clipboard content, file content, or key
		// material. The marker makes an accidental appearance unmistakable.
		secret := rapid.SampledFrom([]string{
			"SECRET-PAYLOAD-abc123",
			"SECRET-CLIPBOARD-https://internal.example/token?t=xyz",
			"SECRET-FILE-CONTENT-0xdeadbeef",
			"SECRET-SESSION-KEY-0123456789abcdef0123456789abcdef",
		}).Draw(rt, "secret")

		// An event entry describing an operation that handled that secret.
		entry := EventEntry{
			Timestamp:       baseTime,
			Type:            rapid.SampledFrom(allEventTypes()).Draw(rt, "eventType"),
			PeerDisplayName: "laptop",
			PeerFingerprint: strings.Repeat("ab", 32),
			Outcome:         rapid.SampledFrom([]string{"admitted", "rejected: peer not trusted", "completed"}).Draw(rt, "outcome"),
		}

		// Req 13.5: the entry carries all five required values.
		if !entry.Complete() {
			rt.Fatalf("entry is incomplete: %+v", entry)
		}
		rendered := entry.String()
		for _, want := range []string{
			entry.Type.String(), entry.PeerDisplayName, entry.PeerFingerprint, entry.Outcome,
		} {
			if !strings.Contains(rendered, want) {
				rt.Fatalf("rendered entry omits %q:\n%s", want, rendered)
			}
		}
		// Req 10.6 and 13.5: the secret is nowhere in it. It cannot be, since EventEntry
		// has no field for content, but the render is where a leak would surface.
		if strings.Contains(rendered, secret) {
			rt.Fatalf("rendered event entry contains the secret:\n%s", rendered)
		}

		// Req 10.6: per-Message detail is type, sequence, and length. Nothing else.
		trace := MessageTrace{
			MessageType:   "TEXT",
			Sequence:      rapid.Uint64().Draw(rt, "sequence"),
			PayloadLength: len(secret),
		}
		renderedTrace := trace.String()
		if strings.Contains(renderedTrace, secret) {
			rt.Fatalf("rendered message trace contains the secret:\n%s", renderedTrace)
		}
		// The length is present, which is what makes a trace useful, and a length is a
		// count rather than a byte.
		if !strings.Contains(renderedTrace, "len=") {
			rt.Fatalf("trace %q omits the payload length", renderedTrace)
		}

		// And no failure report built from any error kind leaks it either.
		for _, kind := range AllAppErrorKinds() {
			failure := Describe(kind, "laptop")
			if strings.Contains(failure.String(), secret) {
				rt.Fatalf("%T leaked the secret:\n%s", kind, failure.String())
			}
		}
	})
}

// TestEventEntryHasNoFieldForContent is the structural half of Req 10.6: the type has nowhere
// to put a payload, so a caller cannot leak one through it. If a content field is ever added,
// this test is where the decision gets challenged.
//
// Requirements: 10.6, 13.5
func TestEventEntryHasNoFieldForContent(t *testing.T) {
	fields := structFieldNames(EventEntry{})
	want := map[string]bool{
		"Timestamp": true, "Type": true,
		"PeerDisplayName": true, "PeerFingerprint": true, "Outcome": true,
	}
	if len(fields) != len(want) {
		t.Fatalf("EventEntry has fields %v; Req 10.6 permits only %v", fields, keysOf(want))
	}
	for _, f := range fields {
		if !want[f] {
			t.Fatalf("EventEntry has an unexpected field %q; Req 10.6 forbids payload content in a log entry", f)
		}
	}

	traceFields := structFieldNames(MessageTrace{})
	wantTrace := map[string]bool{"MessageType": true, "Sequence": true, "PayloadLength": true}
	if len(traceFields) != len(wantTrace) {
		t.Fatalf("MessageTrace has fields %v; Req 10.6 permits only %v",
			traceFields, keysOf(wantTrace))
	}
	for _, f := range traceFields {
		if !wantTrace[f] {
			t.Fatalf("MessageTrace has an unexpected field %q; Req 10.6 limits per-message detail to type, sequence, and length", f)
		}
	}
}

// TestEventLogWriteFailureReportsAndChangesNothing covers Req 13.7: a log write failure names
// the event type and the reason, and cannot touch Session state.
//
// Requirements: 13.7
func TestEventLogWriteFailureReportsAndChangesNothing(t *testing.T) {
	sink := NewMemoryEventSink()
	log := NewEventLog(sink)

	good := EventEntry{
		Timestamp:       baseTime,
		Type:            EventSessionEstablished,
		PeerDisplayName: "laptop",
		PeerFingerprint: strings.Repeat("ab", 32),
		Outcome:         "admitted",
	}
	if failure := log.Write(good); failure != nil {
		t.Fatalf("writing a good entry failed: %s", failure.Error())
	}
	if sink.Len() != 1 {
		t.Fatalf("sink holds %d entries, want 1", sink.Len())
	}

	// A failing sink produces the Req 13.7 report, naming the event type and the reason.
	sink.Fail(errors.New("disk full"))
	failure := log.Write(good)
	if failure == nil {
		t.Fatal("a failing sink reported success")
	}
	if failure.EventType != EventSessionEstablished {
		t.Fatalf("failure names event type %s, want %s", failure.EventType, EventSessionEstablished)
	}
	if !strings.Contains(failure.Error(), "disk full") {
		t.Fatalf("failure %q omits the reason", failure.Error())
	}
	if sink.Len() != 1 {
		t.Fatalf("a failed write changed the sink: %d entries", sink.Len())
	}

	// It renders as a complete four-field Failure like everything else.
	asFailure := failure.AsFailure("laptop")
	if !asFailure.Complete() {
		t.Fatalf("log write failure is incomplete, missing %v", asFailure.Missing())
	}

	// An incomplete entry is caught at the boundary rather than written half-formed.
	sink.Fail(nil)
	if got := log.Write(EventEntry{Type: EventTransferCompleted}); got == nil {
		t.Fatal("an entry missing every field was accepted")
	}
	if sink.Len() != 1 {
		t.Fatalf("an incomplete entry was written anyway: %d entries", sink.Len())
	}

	// An unconfigured log fails rather than pretending to succeed.
	if got := NewEventLog(nil).Write(good); got == nil {
		t.Fatal("a log with no sink reported success")
	}
}

// TestProperty41TransportChangeReasonsAreAClosedSet covers
// Property 41: A Transport change is reported with a closed set of reasons.
//
// Validates: Requirements 13.3
func TestProperty41TransportChangeReasonsAreAClosedSet(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		reason := rapid.SampledFrom(TransportChangeReasons()).Draw(rt, "reason")
		previous := rapid.SampledFrom([]string{"LAN_Transport", "BT_Transport"}).Draw(rt, "previous")
		next := rapid.SampledFrom([]string{"LAN_Transport", "BT_Transport"}).Draw(rt, "next")

		change := TransportChange{
			SessionId:         "s1",
			PeerDisplayName:   "laptop",
			PreviousTransport: previous,
			NewTransport:      next,
			Reason:            reason,
		}

		// Req 13.3: both transports and a reason from the set.
		if !change.Complete() {
			rt.Fatalf("change is incomplete: %+v", change)
		}
		if !reason.Valid() {
			rt.Fatalf("reason %d is outside the closed set", uint8(reason))
		}
		if reason.String() == "" {
			rt.Fatalf("reason %d renders as empty", uint8(reason))
		}

		rendered := change.String()
		for _, want := range []string{previous, next, reason.String()} {
			if !strings.Contains(rendered, want) {
				rt.Fatalf("rendered change omits %q:\n%s", want, rendered)
			}
		}
	})
}

// TestTransportChangeReasonSetIsExactlyThree pins the closed set of Req 13.3. An added reason
// has to be a deliberate change to the requirement, not an accident.
//
// Requirements: 13.3
func TestTransportChangeReasonSetIsExactlyThree(t *testing.T) {
	reasons := TransportChangeReasons()
	if len(reasons) != 3 {
		t.Fatalf("the reason set has %d members, want exactly 3", len(reasons))
	}

	seen := map[string]bool{}
	for _, r := range reasons {
		text := r.String()
		if text == "" {
			t.Fatalf("reason %d renders as empty", uint8(r))
		}
		if seen[text] {
			t.Fatalf("two reasons render identically as %q", text)
		}
		seen[text] = true
	}

	// A value outside the set is rejected rather than rendered as a number.
	outside := TransportChangeReason(9)
	if outside.Valid() {
		t.Fatal("a value outside the set reported itself as valid")
	}
	if outside.String() != "" {
		t.Fatalf("a value outside the set rendered as %q", outside.String())
	}
	// And a change carrying one is incomplete.
	change := TransportChange{PreviousTransport: "a", NewTransport: "b", Reason: outside}
	if change.Complete() {
		t.Fatal("a change with an invalid reason reported itself complete")
	}
}

func allEventTypes() []EventType {
	return []EventType{
		EventSessionEstablished,
		EventTransportChanged,
		EventTransferCompleted,
		EventSessionRejected,
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
