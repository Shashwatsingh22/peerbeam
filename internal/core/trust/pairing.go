package trust

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/clock"
	"github.com/peerbeam/peerbeam/internal/core/crypto"
)

// PairingAttempt is one in-flight pairing. It holds the key received from the Peer
// without storing it anywhere, which is what makes Req 9.5's "discard the public key
// received during that attempt" cheap: abandoning the attempt drops the struct.
type PairingAttempt struct {
	// PeerFingerprint is derived from the received key, and is what a failure report
	// names (Req 9.5).
	PeerFingerprint string
	PeerDisplayName string
	// ReceivedKey is the Peer's public key, held only for the life of the attempt.
	ReceivedKey []byte
	// Code is the 6-digit code both nodes display (Req 9.3).
	Code string
	// DisplayedAt anchors the 120-second window (Req 9.3, 9.5).
	DisplayedAt time.Time

	localConfirmed bool
	peerConfirmed  bool
	mismatch       bool
}

// ExpiresAt is when the attempt's window closes.
func (a *PairingAttempt) ExpiresAt() time.Time {
	return crypto.VerificationCodeExpiry(a.DisplayedAt)
}

// PairingOutcome is a tagged result: exactly one of Paired / Failed is set.
type PairingOutcome struct {
	// Paired carries the entry that was added to the trust store (Req 9.4).
	Paired *TrustedPeer
	// Failed is Req 9.5: a reported mismatch or a missing confirmation. It names the
	// affected Peer.
	Failed *PairingFailure
	// Pending means neither: the attempt is still inside its window awaiting the
	// other side.
	Pending bool
}

// PairingFailure names the affected Peer and why pairing did not complete (Req 9.5).
type PairingFailure struct {
	PeerFingerprint string
	PeerDisplayName string
	Reason          string
}

func (f *PairingFailure) Error() string {
	name := f.PeerDisplayName
	if name == "" {
		name = f.PeerFingerprint
	}
	return fmt.Sprintf("pairing with %s failed: %s", name, f.Reason)
}

// PairingOutcomeKind names the branch an outcome took.
type PairingOutcomeKind uint8

const (
	PairingPaired PairingOutcomeKind = iota
	PairingPending
	PairingFailed
	PairingInvalid
)

func (k PairingOutcomeKind) String() string {
	switch k {
	case PairingPaired:
		return "paired"
	case PairingPending:
		return "pending"
	case PairingFailed:
		return "failed"
	default:
		return "invalid"
	}
}

// Kind reports which single branch of the outcome holds.
func (o PairingOutcome) Kind() PairingOutcomeKind {
	switch {
	case o.Paired != nil:
		return PairingPaired
	case o.Failed != nil:
		return PairingFailed
	case o.Pending:
		return PairingPending
	default:
		return PairingInvalid
	}
}

// AdmissionDecision is a tagged result for a Session request: exactly one field is set.
//
// It duplicates nothing from session.SessionAdmission. That type answers "may this
// Session exist given the eight already running", which is a capacity question; this one
// answers "is this Peer who it claims to be", which is a trust question. Keeping them
// apart is what lets internal/core/session avoid importing this package.
type AdmissionDecision struct {
	// Admit carries the stored entry the presented key matched.
	Admit *TrustedPeer
	// NotTrusted is Req 9.6: no entry for this fingerprint. The caller prompts for
	// pairing and delivers no payload.
	NotTrusted *NotTrusted
	// KeyMismatch is Req 9.7: an entry exists but the presented key differs. The
	// stored key is left alone.
	KeyMismatch *KeyMismatch
	// StoreFailed is Req 9.2 and 9.11: the key store or trust store is in a failed
	// state, so every request is rejected with the failing step named.
	StoreFailed *StoreFailure
}

// NotTrusted reports an unknown Peer (Req 9.6).
type NotTrusted struct {
	Fingerprint string
	// PromptPairing is always true: Req 9.6 requires the user to be prompted to start
	// pairing. It is a field rather than implied so a caller cannot forget it.
	PromptPairing bool
}

func (n *NotTrusted) Error() string {
	return fmt.Sprintf("peer %s is not trusted; pairing is required", n.Fingerprint)
}

// KeyMismatch reports a Trusted_Peer presenting a different key (Req 9.7).
type KeyMismatch struct {
	Fingerprint string
	// StoredKeyRetained is always true: Req 9.7 requires the stored key to be left
	// unchanged, and stating it in the report makes that auditable.
	StoredKeyRetained bool
}

func (m *KeyMismatch) Error() string {
	return fmt.Sprintf("peer %s presented a public key that differs from the stored key",
		m.Fingerprint)
}

// StoreFailure reports the key store or trust store being unusable (Req 9.2, 9.11).
// Step names which one failed, since the remediation differs.
type StoreFailure struct {
	Step   string
	Reason string
}

func (f *StoreFailure) Error() string {
	return fmt.Sprintf("%s failed: %s; every session request is rejected until it succeeds",
		f.Step, f.Reason)
}

// AdmissionKind names the branch a decision took.
type AdmissionKind uint8

const (
	AdmitTrusted AdmissionKind = iota
	AdmitNotTrusted
	AdmitKeyMismatch
	AdmitStoreFailed
	AdmitInvalid
)

func (k AdmissionKind) String() string {
	switch k {
	case AdmitTrusted:
		return "trusted"
	case AdmitNotTrusted:
		return "not trusted"
	case AdmitKeyMismatch:
		return "key mismatch"
	case AdmitStoreFailed:
		return "store failed"
	default:
		return "invalid"
	}
}

// Kind reports which single branch of the decision holds.
func (d AdmissionDecision) Kind() AdmissionKind {
	switch {
	case d.Admit != nil:
		return AdmitTrusted
	case d.NotTrusted != nil:
		return AdmitNotTrusted
	case d.KeyMismatch != nil:
		return AdmitKeyMismatch
	case d.StoreFailed != nil:
		return AdmitStoreFailed
	default:
		return AdmitInvalid
	}
}

// Admitted reports whether the Session may proceed. Everything else delivers no Message
// payload, which is what Req 9.6 requires in as many words.
func (d AdmissionDecision) Admitted() bool { return d.Admit != nil }

// Reason renders the decision for a report, or "" for an admission.
func (d AdmissionDecision) Reason() string {
	switch d.Kind() {
	case AdmitTrusted:
		return ""
	case AdmitNotTrusted:
		return d.NotTrusted.Error()
	case AdmitKeyMismatch:
		return d.KeyMismatch.Error()
	case AdmitStoreFailed:
		return d.StoreFailed.Error()
	default:
		return "invalid admission decision"
	}
}

// PairingService owns the trust store and decides both pairing and Session admission.
// It holds the in-flight attempts, the loaded entries, and the failed-state flags, so
// there is exactly one place that can answer "is this Peer trusted right now".
//
// Not safe for concurrent use; internal/app serialises access from the command path.
type PairingService struct {
	store TrustStore
	clk   clock.Clock

	// identity is this node's own key pair, needed to compute a verification code.
	identity IdentityKeyPair
	// loaded is the in-memory view of the trust store. It exists so Session admission
	// never touches the filesystem, which Req 9.6's 1-second budget makes necessary.
	loaded map[string]TrustedPeer

	// attempts holds in-flight pairings keyed by Peer fingerprint.
	attempts map[string]*PairingAttempt

	// keyStoreFailure and trustStoreFailure are the Req 9.2 and 9.11 states. While
	// either is set, every Session request is rejected.
	keyStoreFailure   *StoreFailure
	trustStoreFailure *StoreFailure
	// ready is false until Load has succeeded, so a Session request that arrives
	// before the store was read is rejected rather than silently treated as untrusted
	// (Req 9.10).
	ready bool
}

// NewPairingService returns a service over store. It is not usable until Load has run,
// which is what Req 9.10 means by loading entries before the first Session request.
func NewPairingService(store TrustStore, clk clock.Clock) *PairingService {
	if clk == nil {
		clk = clock.NewRealClock()
	}
	return &PairingService{
		store:    store,
		clk:      clk,
		loaded:   map[string]TrustedPeer{},
		attempts: map[string]*PairingAttempt{},
	}
}

// SetIdentity records this node's key pair, or the Req 9.2 failure when it could not be
// set up. A nil error with a zero key pair is treated as a failure, since a node with no
// identity cannot authenticate anything.
func (s *PairingService) SetIdentity(identity IdentityKeyPair, err error) {
	if err != nil {
		s.keyStoreFailure = &StoreFailure{Step: "key store setup", Reason: err.Error()}
		return
	}
	if len(identity.PublicKey) != PublicKeyBytes || len(identity.PrivateKey) == 0 {
		s.keyStoreFailure = &StoreFailure{
			Step:   "key store setup",
			Reason: "identity key pair is incomplete",
		}
		return
	}
	s.identity = identity
	s.keyStoreFailure = nil
}

// Identity is this node's key pair.
func (s *PairingService) Identity() IdentityKeyPair { return s.identity }

// Load reads the trust store into memory. On failure it records the Req 9.11 state and
// leaves the previously loaded view alone: the stored content is not modified, and every
// Session request is rejected until a later Load succeeds.
func (s *PairingService) Load() error {
	peers, err := s.store.Load()
	if err != nil {
		s.trustStoreFailure = &StoreFailure{Step: "trust store load", Reason: err.Error()}
		s.ready = false
		return err
	}

	loaded := make(map[string]TrustedPeer, len(peers))
	for _, p := range peers {
		if err := p.Validate(); err != nil {
			// A malformed entry means the store cannot be trusted as a whole. Failing
			// closed is the only safe reading of Req 9.11.
			s.trustStoreFailure = &StoreFailure{
				Step:   "trust store load",
				Reason: err.Error(),
			}
			s.ready = false
			return err
		}
		loaded[p.Fingerprint] = p
	}

	s.loaded = loaded
	s.trustStoreFailure = nil
	s.ready = true
	return nil
}

// Ready reports whether the trust store has been loaded successfully.
func (s *PairingService) Ready() bool { return s.ready }

// StoreFailure returns the active failure, or nil. The key store is reported before the
// trust store: without an identity there is nothing to authenticate with, so that is the
// step the user has to fix first.
func (s *PairingService) StoreFailure() *StoreFailure {
	if s.keyStoreFailure != nil {
		return s.keyStoreFailure
	}
	return s.trustStoreFailure
}

// Trusted returns the stored entry for a fingerprint, and false when there is none.
func (s *PairingService) Trusted(fingerprint string) (TrustedPeer, bool) {
	p, found := s.loaded[fingerprint]
	if !found {
		return TrustedPeer{}, false
	}
	return p.Clone(), true
}

// TrustedPeers lists every entry, ordered by fingerprint.
func (s *PairingService) TrustedPeers() []TrustedPeer {
	out := make([]TrustedPeer, 0, len(s.loaded))
	for _, p := range s.loaded {
		out = append(out, p.Clone())
	}
	sortPeers(out)
	return out
}

// BeginPairing starts an attempt with a Peer and returns the code both nodes display
// (Req 9.3). A second attempt with the same Peer replaces the first, since the code from
// the earlier attempt is no longer the one on screen.
func (s *PairingService) BeginPairing(receivedKey []byte, peerDisplayName string) (*PairingAttempt, error) {
	if failure := s.StoreFailure(); failure != nil {
		return nil, failure
	}
	if err := CheckPublicKey(receivedKey); err != nil {
		return nil, err
	}
	if len(s.identity.PublicKey) != PublicKeyBytes {
		return nil, &StoreFailure{
			Step:   "key store setup",
			Reason: "no local identity key pair",
		}
	}

	attempt := &PairingAttempt{
		PeerFingerprint: Fingerprint(receivedKey),
		PeerDisplayName: peerDisplayName,
		ReceivedKey:     append([]byte(nil), receivedKey...),
		Code:            crypto.VerificationCode(s.identity.PublicKey, receivedKey),
		DisplayedAt:     s.clk.Now(),
	}
	s.attempts[attempt.PeerFingerprint] = attempt
	return attempt, nil
}

// Attempt returns the in-flight attempt for a fingerprint, or nil.
func (s *PairingService) Attempt(fingerprint string) *PairingAttempt {
	return s.attempts[fingerprint]
}

// ConfirmLocal records that the local user confirmed the codes match, and ConfirmPeer
// records the same from the other node. Pairing completes only when both have confirmed
// inside the window (Req 9.4).
func (s *PairingService) ConfirmLocal(fingerprint string) PairingOutcome {
	return s.confirm(fingerprint, true, false)
}

// ConfirmPeer records the Peer's confirmation.
func (s *PairingService) ConfirmPeer(fingerprint string) PairingOutcome {
	return s.confirm(fingerprint, false, true)
}

func (s *PairingService) confirm(fingerprint string, local, peer bool) PairingOutcome {
	attempt := s.attempts[fingerprint]
	if attempt == nil {
		return PairingOutcome{Failed: &PairingFailure{
			PeerFingerprint: fingerprint,
			Reason:          "no pairing attempt is in progress for this peer",
		}}
	}
	if local {
		attempt.localConfirmed = true
	}
	if peer {
		attempt.peerConfirmed = true
	}
	return s.resolve(attempt)
}

// ReportMismatch records that a user said the codes differ, which abandons the attempt
// (Req 9.5).
func (s *PairingService) ReportMismatch(fingerprint string) PairingOutcome {
	attempt := s.attempts[fingerprint]
	if attempt == nil {
		return PairingOutcome{Failed: &PairingFailure{
			PeerFingerprint: fingerprint,
			Reason:          "no pairing attempt is in progress for this peer",
		}}
	}
	attempt.mismatch = true
	return s.resolve(attempt)
}

// ExpirePairings abandons attempts whose 120-second window has closed and returns one
// failure per abandoned attempt (Req 9.5). It is called from the pairing timer.
func (s *PairingService) ExpirePairings() []*PairingFailure {
	var failures []*PairingFailure
	now := s.clk.Now()
	for fingerprint, attempt := range s.attempts {
		if crypto.VerificationCodeValid(attempt.DisplayedAt, now) {
			continue
		}
		delete(s.attempts, fingerprint)
		failures = append(failures, &PairingFailure{
			PeerFingerprint: attempt.PeerFingerprint,
			PeerDisplayName: attempt.PeerDisplayName,
			Reason: fmt.Sprintf("confirmation not received on both nodes within %s",
				crypto.VerificationCodeValidity),
		})
	}
	sortFailures(failures)
	return failures
}

// resolve decides an attempt's fate. The order of checks is the contract: a reported
// mismatch is decided before the window, because a user who says the codes differ has
// answered whether or not there is time left; and the window is checked before the
// confirmations, because a confirmation arriving late must not pair.
//
// Every failure path deletes the attempt, so the received key is discarded and no entry
// is added, which is the whole of Req 9.5.
func (s *PairingService) resolve(attempt *PairingAttempt) PairingOutcome {
	if attempt.mismatch {
		delete(s.attempts, attempt.PeerFingerprint)
		return PairingOutcome{Failed: &PairingFailure{
			PeerFingerprint: attempt.PeerFingerprint,
			PeerDisplayName: attempt.PeerDisplayName,
			Reason:          "user reported that the verification codes do not match",
		}}
	}
	if !crypto.VerificationCodeValid(attempt.DisplayedAt, s.clk.Now()) {
		delete(s.attempts, attempt.PeerFingerprint)
		return PairingOutcome{Failed: &PairingFailure{
			PeerFingerprint: attempt.PeerFingerprint,
			PeerDisplayName: attempt.PeerDisplayName,
			Reason: fmt.Sprintf("confirmation not received on both nodes within %s",
				crypto.VerificationCodeValidity),
		}}
	}
	if !attempt.localConfirmed || !attempt.peerConfirmed {
		return PairingOutcome{Pending: true}
	}

	// Req 9.4: add the Peer's key, keeping one entry per fingerprint.
	peer, err := NewTrustedPeer(attempt.ReceivedKey, attempt.PeerDisplayName, s.clk.Now())
	if err != nil {
		delete(s.attempts, attempt.PeerFingerprint)
		return PairingOutcome{Failed: &PairingFailure{
			PeerFingerprint: attempt.PeerFingerprint,
			PeerDisplayName: attempt.PeerDisplayName,
			Reason:          err.Error(),
		}}
	}
	if err := s.store.Put(peer); err != nil {
		delete(s.attempts, attempt.PeerFingerprint)
		return PairingOutcome{Failed: &PairingFailure{
			PeerFingerprint: attempt.PeerFingerprint,
			PeerDisplayName: attempt.PeerDisplayName,
			Reason:          "trust store write failed: " + err.Error(),
		}}
	}

	s.loaded[peer.Fingerprint] = peer
	delete(s.attempts, attempt.PeerFingerprint)
	stored := peer.Clone()
	return PairingOutcome{Paired: &stored}
}

// Admit decides whether a Session request may proceed on trust grounds (Req 9.2, 9.6,
// 9.7, 9.11).
//
// The order of checks is the contract:
//
//  1. A failed key store or trust store rejects everything (Req 9.2, 9.11). This comes
//     first because while either is broken the node has no basis for any other answer:
//     an empty in-memory view would otherwise make every Peer look untrusted, which
//     reports the wrong problem.
//  2. Not loaded yet (Req 9.10), for the same reason.
//  3. No entry for the fingerprint: not trusted, prompt for pairing (Req 9.6).
//  4. Entry exists but the key differs: mismatch, stored key untouched (Req 9.7).
//  5. Otherwise admit.
//
// Nothing here writes to the store, so Req 9.7's "retain the stored public key
// unchanged" holds by construction rather than by discipline.
func (s *PairingService) Admit(fingerprint string, presentedKey []byte) AdmissionDecision {
	if failure := s.StoreFailure(); failure != nil {
		return AdmissionDecision{StoreFailed: failure}
	}
	if !s.ready {
		return AdmissionDecision{StoreFailed: &StoreFailure{
			Step:   "trust store load",
			Reason: "trust store has not been loaded yet",
		}}
	}

	stored, found := s.loaded[fingerprint]
	if !found {
		return AdmissionDecision{NotTrusted: &NotTrusted{
			Fingerprint:   fingerprint,
			PromptPairing: true,
		}}
	}
	if !bytes.Equal(stored.PublicKey, presentedKey) {
		return AdmissionDecision{KeyMismatch: &KeyMismatch{
			Fingerprint:       fingerprint,
			StoredKeyRetained: true,
		}}
	}

	admitted := stored.Clone()
	return AdmissionDecision{Admit: &admitted}
}

// RemovalOutcome is the result of a user removal request (Req 9.8).
type RemovalOutcome struct {
	// Removed is false when the Peer was not in the store.
	Removed bool
	// CloseSessionFor is the fingerprint whose Session the caller must close within 2
	// seconds (Req 9.8). Empty when nothing was removed.
	CloseSessionFor string
	// Err is a store failure; the entry is left in place when it is set.
	Err error
}

// RemoveTrustedPeer deletes a stored key at the user's request (Req 9.8, 9.9). It is the
// only method in this package that removes anything, which is how Req 9.9 - delete only
// on a user removal request - is enforced: no other code path can reach TrustStore.Remove
// through this service.
//
// It also drops any in-flight pairing attempt with that Peer, so a removal during
// pairing cannot complete a moment later and re-add the key the user just deleted.
func (s *PairingService) RemoveTrustedPeer(fingerprint string) RemovalOutcome {
	removed, err := s.store.Remove(fingerprint)
	if err != nil {
		return RemovalOutcome{Err: err}
	}
	delete(s.loaded, fingerprint)
	delete(s.attempts, fingerprint)
	if !removed {
		return RemovalOutcome{}
	}
	return RemovalOutcome{Removed: true, CloseSessionFor: fingerprint}
}

// Both listings are sorted by fingerprint so that any report built from them is
// deterministic; map iteration order would otherwise make the output shuffle between
// runs.
func sortPeers(peers []TrustedPeer) {
	sort.Slice(peers, func(i, j int) bool { return peers[i].Fingerprint < peers[j].Fingerprint })
}

func sortFailures(failures []*PairingFailure) {
	sort.Slice(failures, func(i, j int) bool {
		return failures[i].PeerFingerprint < failures[j].PeerFingerprint
	})
}
