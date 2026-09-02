package report

import (
	"fmt"
	"time"
)

// EventType is the closed set of events that get a log entry (Req 13.5).
type EventType uint8

const (
	EventSessionEstablished EventType = iota
	EventTransportChanged
	EventTransferCompleted
	EventSessionRejected
)

func (t EventType) String() string {
	switch t {
	case EventSessionEstablished:
		return "session established"
	case EventTransportChanged:
		return "transport changed"
	case EventTransferCompleted:
		return "transfer completed"
	case EventSessionRejected:
		return "session rejected"
	default:
		return fmt.Sprintf("EventType(%d)", uint8(t))
	}
}

// EventEntry is one event log entry. It carries exactly the five things Req 13.5 requires
// and nothing else.
//
// There is deliberately no field for Message payload, clipboard content, file content, or
// key material. Req 10.6 and Req 13.5 both forbid those from appearing in a log, and the
// way to keep that true as the codebase grows is to give the type nowhere to put them:
// a caller cannot leak a payload through a struct with no payload field. Outcome is a
// short verdict like "admitted" or "rejected: peer not trusted", built by the caller from
// names and reasons, never from bytes that crossed the wire.
type EventEntry struct {
	Timestamp       time.Time
	Type            EventType
	PeerDisplayName string
	PeerFingerprint string
	Outcome         string
}

// Complete reports whether the entry carries all five required values (Req 13.5). An
// incomplete entry is a bug in the caller, and it is better caught at the log boundary
// than discovered later in a log that cannot answer what happened.
func (e EventEntry) Complete() bool {
	return !e.Timestamp.IsZero() &&
		e.PeerDisplayName != "" &&
		e.PeerFingerprint != "" &&
		e.Outcome != ""
}

// String renders the entry for the log. The format is one line per entry, fields
// separated so a reader can scan a column.
func (e EventEntry) String() string {
	return fmt.Sprintf("%s\t%s\tpeer=%s\tfingerprint=%s\toutcome=%s",
		e.Timestamp.UTC().Format(time.RFC3339), e.Type, e.PeerDisplayName,
		e.PeerFingerprint, e.Outcome)
}

// MessageTrace is the whole of what may be logged about an individual Message (Req 10.6):
// its type, its sequence number, and its payload length. Not the payload.
//
// Length is included because it is what makes a trace useful for diagnosing a framing or
// size problem, and because Req 10.6 names it explicitly as permitted. It says nothing
// about content: a length is a count, not a byte.
type MessageTrace struct {
	MessageType   string
	Sequence      uint64
	PayloadLength int
}

func (t MessageTrace) String() string {
	return fmt.Sprintf("%s seq=%d len=%d", t.MessageType, t.Sequence, t.PayloadLength)
}

// EventSink writes event log entries. It is an interface so internal/core stays free of
// file I/O, and so the Req 13.7 failure path can be exercised with a sink that refuses to
// write.
type EventSink interface {
	Write(entry EventEntry) error
}

// LogWriteFailure is the Req 13.7 report: the node could not write an entry. It names the
// event type and the reason, and records that no Session state changed.
type LogWriteFailure struct {
	EventType EventType
	Reason    string
}

func (f *LogWriteFailure) Error() string {
	return fmt.Sprintf("could not write %s event to the log: %s", f.EventType, f.Reason)
}

// AsFailure renders the log write failure as a user-facing Failure, so it goes through the
// same four-field contract as every other failure (Req 13.4).
func (f *LogWriteFailure) AsFailure(peerDisplayName string) Failure {
	return Failure{
		Operation:       "write event log entry",
		PeerDisplayName: peerDisplayName,
		Reason:          f.Error(),
		Remediation:     "check that the log directory exists and is writable, then retry",
	}
}

// EventLog writes entries to a sink and turns a write error into the Req 13.7 report.
//
// It exists so there is one place where a log write can fail, and that place is incapable
// of touching Session state: it holds no Sessions and has no way to reach one. Req 13.7's
// "keep every Session in its current state" is therefore structural rather than a promise.
type EventLog struct {
	sink EventSink
}

// NewEventLog returns a log over sink. A nil sink discards entries and reports every write
// as a failure, which is what an unconfigured log should do rather than pretend to succeed.
func NewEventLog(sink EventSink) *EventLog { return &EventLog{sink: sink} }

// Write records one entry. It returns the Req 13.7 failure on a sink error, or when the
// entry is missing a required field.
func (l *EventLog) Write(entry EventEntry) *LogWriteFailure {
	if !entry.Complete() {
		return &LogWriteFailure{
			EventType: entry.Type,
			Reason:    "entry is missing a required field (timestamp, peer, fingerprint, or outcome)",
		}
	}
	if l.sink == nil {
		return &LogWriteFailure{EventType: entry.Type, Reason: "no event log sink is configured"}
	}
	if err := l.sink.Write(entry); err != nil {
		return &LogWriteFailure{EventType: entry.Type, Reason: err.Error()}
	}
	return nil
}

// MemoryEventSink collects entries in memory. It is what tests and `peerbeam log tail` read
// from before a file sink is configured.
type MemoryEventSink struct {
	entries []EventEntry
	// failure, when set, makes every write fail, for exercising Req 13.7.
	failure error
}

// NewMemoryEventSink returns an empty sink.
func NewMemoryEventSink() *MemoryEventSink { return &MemoryEventSink{} }

// Fail makes subsequent writes fail. Passing nil clears it.
func (s *MemoryEventSink) Fail(err error) { s.failure = err }

// Write appends an entry.
func (s *MemoryEventSink) Write(entry EventEntry) error {
	if s.failure != nil {
		return s.failure
	}
	s.entries = append(s.entries, entry)
	return nil
}

// Entries returns the entries written so far, oldest first.
func (s *MemoryEventSink) Entries() []EventEntry {
	return append([]EventEntry(nil), s.entries...)
}

// Len is the number of entries held.
func (s *MemoryEventSink) Len() int { return len(s.entries) }
