package session

import (
	"errors"
	"time"

	"pgregory.net/rapid"
)

// baseTime anchors every generated timestamp, so a failing case is reproducible.
var baseTime = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

// manualClock is the injected time source for tests. It moves only when a test
// advances it, so the 10-second reorder hold and the 10-minute retention window are
// both checked without waiting.
type manualClock struct{ now time.Time }

func newManualClock() *manualClock { return &manualClock{now: baseTime} }

func (c *manualClock) Now() time.Time          { return c.now }
func (c *manualClock) advance(d time.Duration) { c.now = c.now.Add(d) }
func (c *manualClock) set(t time.Time)         { c.now = t }

// admissionFor builds a well-formed, trusted admission request. Tests that want a
// rejection change one field, which keeps the interesting difference visible at the
// call site.
func admissionFor(fingerprint string, keys ...byte) AdmissionRequest {
	key := []byte("long-term-key-" + fingerprint)
	material := KeyMaterial(keys)
	if len(material) == 0 {
		material = KeyMaterial("session-keys-" + fingerprint)
	}
	return AdmissionRequest{
		Fingerprint:  fingerprint,
		DisplayName:  "peer-" + fingerprint,
		PresentedKey: key,
		StoredKey:    key,
		Keys:         material,
	}
}

// mustAdmit admits a Session or fails the test, returning its id.
func mustAdmit(t rapid.TB, r *SessionRegistry, fingerprint string) SessionId {
	t.Helper()
	got := r.Admit(admissionFor(fingerprint))
	if got.Admitted == nil {
		t.Fatalf("admitting %s: %s", fingerprint, got.Reason())
	}
	return *got.Admitted
}

// sessionFacts is the snapshot Property 18 compares before and after an operation on
// some *other* Session. Req 4.3 names exactly these four things.
type sessionFacts struct {
	id              SessionId
	keys            string
	nextOutbound    uint64
	inboundCount    int
	activeTransport string
	state           State
	queueBytes      int64
}

func factsFor(s *Session) sessionFacts {
	return sessionFacts{
		id:              s.Id,
		keys:            string(s.Keys),
		nextOutbound:    s.Sequence.PeekNextSequence(),
		inboundCount:    s.Sequence.InboundCount(),
		activeTransport: s.ActiveTransportName,
		state:           s.State(),
		queueBytes:      s.Queue.ByteCount(),
	}
}

// errNoAcknowledgement stands in for a Session that accepted the send but was never
// acknowledged, so the dispatcher can distinguish it from an inactive Session.
var errNoAcknowledgement = errors.New("no acknowledgement")
