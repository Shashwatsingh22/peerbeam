package session

import (
	"bytes"
	"fmt"
	"sort"
	"sync"

	"github.com/peerbeam/peerbeam/internal/core/clock"
)

// MaxConcurrentSessions is the ceiling from Req 4.1, and the limit Req 4.9 makes
// the rejection name.
const MaxConcurrentSessions = 8

// AdmissionRequest is everything the registry needs to decide on a Session.
//
// StoredKey is passed in rather than looked up, and TrustedPeer is deliberately
// absent: this package must not import internal/core/trust, so that the trust
// model and the session registry stay independently testable. The caller reads the
// trust store and hands the answer over as bytes. A nil StoredKey means the Peer is
// not in the trust store at all (Req 9.6); a StoredKey that differs from
// PresentedKey is a key mismatch (Req 9.7).
type AdmissionRequest struct {
	Fingerprint  string
	DisplayName  string
	PresentedKey []byte
	StoredKey    []byte
	// Keys is the freshly derived per-Session key material (Req 4.1, 10.5). The
	// registry requires it to be non-empty but never inspects its contents.
	Keys KeyMaterial
}

// SessionAdmission is a tagged result: exactly one field is set. Go has no sealed
// sum type, so the invariant is stated rather than enforced; Kind reports which
// branch holds.
//
// DuplicateSession is not in the original four. Req 4.1 scopes the 8 Sessions to
// "distinct Peers", so a second request for a fingerprint that already holds a
// Session is neither an admission nor a limit breach nor a trust failure. Folding
// it into any of those would have made the report wrong, so it gets its own branch
// carrying the existing id.
type SessionAdmission struct {
	Admitted         *SessionId
	LimitReached     *int       // Req 4.9: carries the limit of 8
	PeerNotTrusted   string     // Req 9.6: fingerprint
	KeyMismatch      string     // Req 9.7: fingerprint
	DuplicateSession *SessionId // Req 4.1: fingerprint already holds this Session
	Failed           string     // entropy or wiring failure; no Session was created
}

// AdmissionKind names the branch a SessionAdmission took.
type AdmissionKind uint8

const (
	AdmissionAdmitted AdmissionKind = iota
	AdmissionLimitReached
	AdmissionPeerNotTrusted
	AdmissionKeyMismatch
	AdmissionDuplicateSession
	AdmissionFailed
	// AdmissionInvalid means no branch was set. Admit never returns it.
	AdmissionInvalid
)

func (k AdmissionKind) String() string {
	switch k {
	case AdmissionAdmitted:
		return "admitted"
	case AdmissionLimitReached:
		return "limit reached"
	case AdmissionPeerNotTrusted:
		return "peer not trusted"
	case AdmissionKeyMismatch:
		return "key mismatch"
	case AdmissionDuplicateSession:
		return "duplicate session"
	case AdmissionFailed:
		return "failed"
	default:
		return "invalid"
	}
}

// Kind reports which single branch of the admission holds.
func (a SessionAdmission) Kind() AdmissionKind {
	switch {
	case a.Admitted != nil:
		return AdmissionAdmitted
	case a.LimitReached != nil:
		return AdmissionLimitReached
	case a.PeerNotTrusted != "":
		return AdmissionPeerNotTrusted
	case a.KeyMismatch != "":
		return AdmissionKeyMismatch
	case a.DuplicateSession != nil:
		return AdmissionDuplicateSession
	case a.Failed != "":
		return AdmissionFailed
	default:
		return AdmissionInvalid
	}
}

// Reason renders the admission for a report. Req 4.9 wants the limit named, and
// Req 9.6 and 9.7 want the Peer named, so each branch says which value it carries.
func (a SessionAdmission) Reason() string {
	switch a.Kind() {
	case AdmissionAdmitted:
		return ""
	case AdmissionLimitReached:
		return fmt.Sprintf("concurrent session limit of %d reached", *a.LimitReached)
	case AdmissionPeerNotTrusted:
		return "peer " + a.PeerNotTrusted + " is not trusted; pairing required"
	case AdmissionKeyMismatch:
		return "peer " + a.KeyMismatch + " presented a key that differs from the stored key"
	case AdmissionDuplicateSession:
		return "peer already holds session " + a.DuplicateSession.String()
	case AdmissionFailed:
		return a.Failed
	default:
		return "invalid admission"
	}
}

// SessionRegistry owns every Session. It is the only shared state between Sessions,
// and its mutex guards the two maps and nothing else: it is never held across I/O,
// never held while a Session's channels are written, and never held inside a
// caller's callback. That is what makes Req 4.2 true, since a slow or stalled
// Session cannot block another Session's lookup.
type SessionRegistry struct {
	mu    sync.Mutex
	limit int
	clk   clock.Clock

	sessions map[SessionId]*Session
	// byFingerprint indexes the same Sessions by Peer, so a group send can find a
	// Session per selected Peer without scanning (Req 4.4). One fingerprint maps
	// to at most one Session (Req 4.1).
	byFingerprint map[string]*Session

	newId func() (SessionId, error)
}

// NewSessionRegistry returns a registry at the Req 4.1 limit of 8.
func NewSessionRegistry(clk clock.Clock) *SessionRegistry {
	if clk == nil {
		clk = clock.NewRealClock()
	}
	return &SessionRegistry{
		limit:         MaxConcurrentSessions,
		clk:           clk,
		sessions:      map[SessionId]*Session{},
		byFingerprint: map[string]*Session{},
		newId:         NewSessionId,
	}
}

// Admit decides on one Session request and, when it succeeds, creates the Session.
//
// The checks run in a fixed order, and the order is part of the contract because
// several can fail at once:
//
//  1. malformed request, which is a wiring bug rather than a peer's fault
//  2. not trusted (Req 9.6), then key mismatch (Req 9.7) - both are about *this*
//     Peer, and both are more actionable than a capacity message
//  3. duplicate Session for the fingerprint (Req 4.1)
//  4. concurrent Session limit (Req 4.9)
//
// Trust is checked before capacity on purpose: telling a user that an untrusted
// Peer hit the Session limit would send them looking at capacity when the real
// answer is that they never paired. Capacity is also the only check that depends
// on unrelated Sessions, so leaving it last keeps the failure closest to its cause.
//
// Every rejection leaves the existing Sessions exactly as they were, which is what
// Req 4.9 requires in as many words.
func (r *SessionRegistry) Admit(req AdmissionRequest) SessionAdmission {
	if req.Fingerprint == "" {
		return SessionAdmission{Failed: "admission request carries no fingerprint"}
	}
	if len(req.PresentedKey) == 0 {
		return SessionAdmission{Failed: "admission request carries no presented key"}
	}
	if len(req.Keys) == 0 {
		return SessionAdmission{Failed: "admission request carries no session key material"}
	}

	// Req 9.6: an unknown Peer is not admitted; the caller prompts for pairing.
	if len(req.StoredKey) == 0 {
		return SessionAdmission{PeerNotTrusted: req.Fingerprint}
	}
	// Req 9.7: byte-identical or nothing. The stored key is left untouched.
	if !bytes.Equal(req.PresentedKey, req.StoredKey) {
		return SessionAdmission{KeyMismatch: req.Fingerprint}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, found := r.byFingerprint[req.Fingerprint]; found {
		id := existing.Id
		return SessionAdmission{DuplicateSession: &id}
	}
	if len(r.sessions) >= r.limit {
		limit := r.limit
		return SessionAdmission{LimitReached: &limit} // Req 4.9
	}

	id, err := r.newId()
	if err != nil {
		return SessionAdmission{Failed: err.Error()}
	}
	// A collision is astronomically unlikely, but reusing an id would silently
	// merge two Peers' Sessions, so it is checked rather than assumed.
	if _, taken := r.sessions[id]; taken {
		return SessionAdmission{Failed: "generated session id collided with an active session"}
	}

	// Copy the key material so the caller cannot mutate a live Session's keys
	// through the slice it passed in.
	keys := make(KeyMaterial, len(req.Keys))
	copy(keys, req.Keys)

	s := newSession(id, req.Fingerprint, req.DisplayName, keys, r.clk)
	r.sessions[id] = s
	r.byFingerprint[req.Fingerprint] = s
	return SessionAdmission{Admitted: &id}
}

// Get returns the Session with this id, or nil.
func (r *SessionRegistry) Get(id SessionId) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[id]
}

// FindActive returns the active Session for a fingerprint, or nil when the Peer has
// no Session or its Session is disconnected. Req 4.4 sends only on active Sessions,
// and Req 4.8 queues for the rest, so the two cases have to be distinguishable.
func (r *SessionRegistry) FindActive(fingerprint string) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.byFingerprint[fingerprint]
	if s == nil || !s.IsActive() {
		return nil
	}
	return s
}

// Find returns the Session for a fingerprint whatever its state, or nil. A
// disconnected Session still has a retention queue to accept payload (Req 4.8).
func (r *SessionRegistry) Find(fingerprint string) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byFingerprint[fingerprint]
}

// Close removes a Session and releases its channels. Every other Session keeps its
// identifier, keys, sequence state, and active Transport, because nothing here
// touches them (Req 4.3).
//
// It returns false when no such Session exists, so a double close is detectable
// rather than silent. The Session is dropped from both maps before it is closed, so
// no lookup can hand out a Session whose channels are closing.
func (r *SessionRegistry) Close(id SessionId, reason string) bool {
	r.mu.Lock()
	s := r.sessions[id]
	if s == nil {
		r.mu.Unlock()
		return false
	}
	delete(r.sessions, id)
	// Only drop the fingerprint index if it still points at this Session.
	if indexed, found := r.byFingerprint[s.Fingerprint]; found && indexed == s {
		delete(r.byFingerprint, s.Fingerprint)
	}
	r.mu.Unlock()

	// Closed outside the lock: closing channels can wake other goroutines, and
	// the registry mutex must never be held while that happens.
	_ = reason // the reason belongs to the caller's report, not to the registry
	s.close()
	return true
}

// Active returns every Session currently in the active state, ordered by
// SessionId so the listing is stable across calls. Map iteration order would
// otherwise make any report built from this non-deterministic.
func (r *SessionRegistry) Active() []*Session {
	return r.snapshot(func(s *Session) bool { return s.IsActive() })
}

// All returns every Session the registry holds, active or disconnected, ordered by
// SessionId.
func (r *SessionRegistry) All() []*Session {
	return r.snapshot(func(*Session) bool { return true })
}

func (r *SessionRegistry) snapshot(keep func(*Session) bool) []*Session {
	r.mu.Lock()
	out := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		if keep(s) {
			out = append(out, s)
		}
	}
	r.mu.Unlock()

	sort.Slice(out, func(i, j int) bool { return out[i].Id < out[j].Id })
	return out
}

// Len is the number of Sessions held, which is what the Req 4.9 limit applies to.
// Disconnected Sessions count: they still hold an identifier, keys, and a retention
// queue, so they still occupy one of the 8 slots.
func (r *SessionRegistry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

// Limit is the concurrent Session ceiling.
func (r *SessionRegistry) Limit() int { return r.limit }
