package trust

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/peerbeam/peerbeam/internal/core/crypto"
)

var baseTime = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

// manualClock is the injected time source. The 120-second pairing window of Req 9.3 and
// 9.5 is checked by advancing it rather than waiting.
type manualClock struct{ now time.Time }

func newManualClock() *manualClock             { return &manualClock{now: baseTime} }
func (c *manualClock) Now() time.Time          { return c.now }
func (c *manualClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// keyFor builds a deterministic 32-byte public key from a seed, so a failing case names
// a key a reader can reproduce.
func keyFor(seed byte) []byte {
	key := make([]byte, PublicKeyBytes)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

// newService returns a loaded PairingService with an identity, which is the state a node
// is in once startup has succeeded.
func newService(t rapid.TB, clk *manualClock) (*PairingService, *MemoryTrustStore) {
	t.Helper()
	store := NewMemoryTrustStore()
	s := NewPairingService(store, clk)

	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating an identity: %v", err)
	}
	s.SetIdentity(IdentityKeyPair{PublicKey: public, PrivateKey: private}, nil)
	if err := s.Load(); err != nil {
		t.Fatalf("loading the trust store: %v", err)
	}
	return s, store
}

// pairFully drives a complete successful pairing and returns the stored entry.
func pairFully(t rapid.TB, s *PairingService, key []byte, name string) TrustedPeer {
	t.Helper()
	attempt, err := s.BeginPairing(key, name)
	if err != nil {
		t.Fatalf("beginning pairing: %v", err)
	}
	if got := s.ConfirmLocal(attempt.PeerFingerprint); got.Kind() != PairingPending {
		t.Fatalf("one-sided confirmation gave %s, want pending", got.Kind())
	}
	got := s.ConfirmPeer(attempt.PeerFingerprint)
	if got.Paired == nil {
		t.Fatalf("mutual confirmation gave %s: %v", got.Kind(), got.Failed)
	}
	return *got.Paired
}

// TestProperty32FailedPairingChangesNothing covers
// Property 32: Failed pairing changes nothing.
//
// Validates: Requirements 9.5
func TestProperty32FailedPairingChangesNothing(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		clk := newManualClock()
		s, store := newService(rt, clk)

		// Some peers are already trusted, so the property can check that an existing
		// store survives a failed attempt untouched.
		existingCount := rapid.IntRange(0, 4).Draw(rt, "existingPeers")
		for i := 0; i < existingCount; i++ {
			pairFully(rt, s, keyFor(byte(100+i)), "existing")
		}
		before, err := store.Load()
		if err != nil {
			rt.Fatalf("snapshotting the store: %v", err)
		}

		newKey := keyFor(byte(rapid.IntRange(1, 60).Draw(rt, "newKeySeed")))
		attempt, err := s.BeginPairing(newKey, "candidate")
		if err != nil {
			rt.Fatalf("beginning pairing: %v", err)
		}
		fingerprint := attempt.PeerFingerprint

		// The code is displayed and is the right shape (Req 9.3).
		if !crypto.IsVerificationCode(attempt.Code) {
			rt.Fatalf("displayed code %q is not six digits", attempt.Code)
		}

		// One of the two ways Req 9.5 fails an attempt.
		var outcome PairingOutcome
		switch rapid.SampledFrom([]string{
			"mismatch", "timeout", "one-sided-then-timeout",
		}).Draw(rt, "failureMode") {

		case "mismatch":
			// Possibly after one side already confirmed, which must not help.
			if rapid.Bool().Draw(rt, "confirmFirst") {
				s.ConfirmLocal(fingerprint)
			}
			outcome = s.ReportMismatch(fingerprint)

		case "timeout":
			clk.advance(crypto.VerificationCodeValidity +
				rapid.SampledFrom([]time.Duration{0, time.Second, time.Hour}).Draw(rt, "past"))
			failures := s.ExpirePairings()
			if len(failures) != 1 {
				rt.Fatalf("expiry produced %d failures, want 1", len(failures))
			}
			outcome = PairingOutcome{Failed: failures[0]}

		case "one-sided-then-timeout":
			s.ConfirmLocal(fingerprint)
			clk.advance(crypto.VerificationCodeValidity)
			// A confirmation arriving at the boundary must not pair.
			outcome = s.ConfirmPeer(fingerprint)
		}

		// Req 9.5: the attempt failed and the report names the affected Peer.
		if outcome.Kind() != PairingFailed {
			rt.Fatalf("got %s, want failed", outcome.Kind())
		}
		if outcome.Failed.PeerFingerprint != fingerprint {
			rt.Fatalf("failure names %s, want %s", outcome.Failed.PeerFingerprint, fingerprint)
		}
		if strings.TrimSpace(outcome.Failed.Reason) == "" {
			rt.Fatal("failure carries no reason")
		}
		if !strings.Contains(outcome.Failed.Error(), "candidate") &&
			!strings.Contains(outcome.Failed.Error(), fingerprint) {
			rt.Fatalf("report %q names neither the display name nor the fingerprint",
				outcome.Failed.Error())
		}

		// Req 9.5: no entry added, the received key discarded, existing entries
		// unchanged.
		if _, trusted := s.Trusted(fingerprint); trusted {
			rt.Fatal("a failed pairing added a trust store entry")
		}
		if s.Attempt(fingerprint) != nil {
			rt.Fatal("a failed pairing left the received key in an attempt")
		}
		after, err := store.Load()
		if err != nil {
			rt.Fatalf("reloading the store: %v", err)
		}
		if len(after) != len(before) {
			rt.Fatalf("store holds %d entries, held %d before the failed attempt",
				len(after), len(before))
		}
		for i := range before {
			if !before[i].Equal(after[i]) {
				rt.Fatalf("entry %d changed across a failed pairing:\n before %+v\n after  %+v",
					i, before[i], after[i])
			}
		}

		// And the Peer is still not admitted afterwards (Req 9.6).
		if got := s.Admit(fingerprint, newKey); got.Kind() != AdmitNotTrusted {
			rt.Fatalf("after a failed pairing, admission gave %s", got.Kind())
		}
	})
}

// TestProperty33SessionAdmissionAcceptsOnlyTrustedByteIdenticalKeys covers
// Property 33: Session admission accepts only trusted, byte-identical keys.
//
// Validates: Requirements 9.2, 9.6, 9.7, 9.8, 9.11
func TestProperty33SessionAdmissionAcceptsOnlyTrustedByteIdenticalKeys(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		clk := newManualClock()
		s, store := newService(rt, clk)

		// A set of trusted peers, plus a key that was never paired.
		trustedCount := rapid.IntRange(0, 5).Draw(rt, "trustedPeers")
		trustedKeys := make([][]byte, 0, trustedCount)
		for i := 0; i < trustedCount; i++ {
			key := keyFor(byte(10 + i))
			pairFully(rt, s, key, "peer")
			trustedKeys = append(trustedKeys, key)
		}
		strangerKey := keyFor(200)

		// Req 9.6: an unknown Peer is rejected with a pairing prompt.
		strangerFingerprint := Fingerprint(strangerKey)
		got := s.Admit(strangerFingerprint, strangerKey)
		if got.Kind() != AdmitNotTrusted {
			rt.Fatalf("stranger got %s, want not trusted", got.Kind())
		}
		if !got.NotTrusted.PromptPairing {
			rt.Fatal("an untrusted peer did not prompt for pairing")
		}
		if got.Admitted() {
			rt.Fatal("an untrusted peer was admitted")
		}
		if !strings.Contains(got.Reason(), strangerFingerprint) {
			rt.Fatalf("reason %q does not name the peer", got.Reason())
		}

		for i, key := range trustedKeys {
			fingerprint := Fingerprint(key)

			// Req 9.6 and 9.7 satisfied: byte-identical key is admitted.
			admitted := s.Admit(fingerprint, key)
			if !admitted.Admitted() {
				rt.Fatalf("trusted peer %d got %s: %s", i, admitted.Kind(), admitted.Reason())
			}
			if admitted.Admit.Fingerprint != fingerprint {
				rt.Fatalf("admitted entry names %s, want %s",
					admitted.Admit.Fingerprint, fingerprint)
			}

			// Req 9.7: a single changed byte is a mismatch, and the stored key stays.
			tampered := append([]byte(nil), key...)
			at := rapid.IntRange(0, len(tampered)-1).Draw(rt, "tamperAt")
			tampered[at] ^= byte(rapid.IntRange(1, 255).Draw(rt, "tamperMask"))

			mismatch := s.Admit(fingerprint, tampered)
			if mismatch.Kind() != AdmitKeyMismatch {
				rt.Fatalf("tampered key got %s, want key mismatch", mismatch.Kind())
			}
			if !mismatch.KeyMismatch.StoredKeyRetained {
				rt.Fatal("mismatch did not report the stored key as retained")
			}
			if !strings.Contains(mismatch.Reason(), fingerprint) {
				rt.Fatalf("mismatch reason %q does not name the peer", mismatch.Reason())
			}
			stored, found := s.Trusted(fingerprint)
			if !found {
				rt.Fatal("a mismatch removed the stored entry")
			}
			if !equalKeys(stored.PublicKey, key) {
				rt.Fatal("a mismatch changed the stored key")
			}

			// The honest key still works afterwards, so a mismatch is not sticky.
			if again := s.Admit(fingerprint, key); !again.Admitted() {
				rt.Fatalf("after a mismatch the honest key got %s", again.Kind())
			}
		}

		// Req 9.8: removing a Peer closes its Session and rejects it from then on.
		if len(trustedKeys) > 0 {
			key := trustedKeys[0]
			fingerprint := Fingerprint(key)

			removal := s.RemoveTrustedPeer(fingerprint)
			if removal.Err != nil {
				rt.Fatalf("removal failed: %v", removal.Err)
			}
			if !removal.Removed {
				rt.Fatal("removing a trusted peer reported nothing removed")
			}
			if removal.CloseSessionFor != fingerprint {
				rt.Fatalf("removal asks to close %q, want %q",
					removal.CloseSessionFor, fingerprint)
			}
			if got := s.Admit(fingerprint, key); got.Kind() != AdmitNotTrusted {
				rt.Fatalf("a removed peer got %s, want not trusted", got.Kind())
			}
			// Removing again is a no-op rather than an error.
			if again := s.RemoveTrustedPeer(fingerprint); again.Removed {
				rt.Fatal("removing an absent peer reported a removal")
			}
		}

		// Req 9.11: while the trust store is failed, every request is rejected with the
		// failing step named.
		store.Fail(errors.New("integrity tag mismatch"))
		if err := s.Load(); err == nil {
			rt.Fatal("loading a failed store succeeded")
		}
		for _, key := range append(trustedKeys, strangerKey) {
			got := s.Admit(Fingerprint(key), key)
			if got.Kind() != AdmitStoreFailed {
				rt.Fatalf("with a failed store, admission gave %s", got.Kind())
			}
			if !strings.Contains(got.Reason(), "trust store") {
				rt.Fatalf("reason %q does not name the failing step", got.Reason())
			}
		}

		// Req 9.2: the same holds for a failed key store, and it is reported first,
		// since without an identity there is nothing to authenticate with.
		store.Fail(nil)
		s.SetIdentity(IdentityKeyPair{}, errors.New("cannot chmod identity.key"))
		got = s.Admit(strangerFingerprint, strangerKey)
		if got.Kind() != AdmitStoreFailed {
			rt.Fatalf("with a failed key store, admission gave %s", got.Kind())
		}
		if !strings.Contains(got.Reason(), "key store") {
			rt.Fatalf("reason %q does not name the key store", got.Reason())
		}
	})
}

// TestPairingRequiresBothConfirmationsInsideTheWindow pins Req 9.4 against Req 9.5: one
// side alone is not enough, and neither is a late second confirmation.
//
// Requirements: 9.3, 9.4, 9.5
func TestPairingRequiresBothConfirmationsInsideTheWindow(t *testing.T) {
	t.Run("both inside the window pairs", func(t *testing.T) {
		clk := newManualClock()
		s, _ := newService(t, clk)
		key := keyFor(7)

		attempt, err := s.BeginPairing(key, "laptop")
		if err != nil {
			t.Fatalf("beginning pairing: %v", err)
		}
		if got := s.ConfirmLocal(attempt.PeerFingerprint); got.Kind() != PairingPending {
			t.Fatalf("local confirmation alone gave %s", got.Kind())
		}
		clk.advance(crypto.VerificationCodeValidity - time.Nanosecond)
		got := s.ConfirmPeer(attempt.PeerFingerprint)
		if got.Paired == nil {
			t.Fatalf("got %s, want paired", got.Kind())
		}
		// Req 9.4: the entry carries the key, its fingerprint, and the pairing time.
		if got.Paired.Fingerprint != Fingerprint(key) {
			t.Fatalf("entry fingerprint %s, want %s", got.Paired.Fingerprint, Fingerprint(key))
		}
		if !equalKeys(got.Paired.PublicKey, key) {
			t.Fatal("entry does not carry the received key")
		}
		if got.Paired.DisplayName != "laptop" {
			t.Fatalf("entry names %q", got.Paired.DisplayName)
		}
		if got.Paired.PairedAt.IsZero() {
			t.Fatal("entry has no pairing time")
		}
	})

	t.Run("second confirmation exactly at the window fails", func(t *testing.T) {
		clk := newManualClock()
		s, _ := newService(t, clk)

		attempt, _ := s.BeginPairing(keyFor(8), "laptop")
		s.ConfirmLocal(attempt.PeerFingerprint)
		clk.advance(crypto.VerificationCodeValidity)

		got := s.ConfirmPeer(attempt.PeerFingerprint)
		if got.Kind() != PairingFailed {
			t.Fatalf("got %s, want failed", got.Kind())
		}
		if !strings.Contains(got.Failed.Reason, "2m0s") {
			t.Fatalf("reason %q does not name the window", got.Failed.Reason)
		}
	})
}

// TestRepeatedPairingKeepsOneEntryPerFingerprint pins Req 9.4's "exactly one entry per
// public key fingerprint".
//
// Requirements: 9.4
func TestRepeatedPairingKeepsOneEntryPerFingerprint(t *testing.T) {
	clk := newManualClock()
	s, store := newService(t, clk)
	key := keyFor(11)

	first := pairFully(t, s, key, "old name")
	clk.advance(time.Hour)
	second := pairFully(t, s, key, "new name")

	if store.Len() != 1 {
		t.Fatalf("store holds %d entries after pairing the same peer twice", store.Len())
	}
	if first.Fingerprint != second.Fingerprint {
		t.Fatal("the same key produced two fingerprints")
	}
	// The later pairing replaces the entry rather than being ignored.
	if second.DisplayName != "new name" {
		t.Fatalf("entry names %q, want the newer name", second.DisplayName)
	}
	if !second.PairedAt.After(first.PairedAt) {
		t.Fatal("re-pairing did not update the pairing time")
	}
}

// TestAdmissionIsRejectedBeforeTheStoreIsLoaded pins Req 9.10: entries load before the
// first Session request, so a request that arrives earlier is rejected rather than
// treated as untrusted.
//
// Requirements: 9.10, 9.11
func TestAdmissionIsRejectedBeforeTheStoreIsLoaded(t *testing.T) {
	store := NewMemoryTrustStore()
	s := NewPairingService(store, newManualClock())
	public, private, _ := ed25519.GenerateKey(nil)
	s.SetIdentity(IdentityKeyPair{PublicKey: public, PrivateKey: private}, nil)

	if s.Ready() {
		t.Fatal("an unloaded service reports ready")
	}
	got := s.Admit(Fingerprint(keyFor(3)), keyFor(3))
	if got.Kind() != AdmitStoreFailed {
		t.Fatalf("got %s, want store failed", got.Kind())
	}
	if !strings.Contains(got.Reason(), "not been loaded") {
		t.Fatalf("reason %q does not say the store was never loaded", got.Reason())
	}

	if err := s.Load(); err != nil {
		t.Fatalf("loading: %v", err)
	}
	if !s.Ready() {
		t.Fatal("a loaded service does not report ready")
	}
	// Now it is a plain untrusted peer rather than a store failure.
	if got := s.Admit(Fingerprint(keyFor(3)), keyFor(3)); got.Kind() != AdmitNotTrusted {
		t.Fatalf("got %s, want not trusted", got.Kind())
	}
}

// TestRemovalDuringPairingCannotResurrectTheKey checks that a removal drops any in-flight
// attempt, so a confirmation arriving afterwards cannot re-add the key the user just
// deleted.
//
// Requirements: 9.8, 9.9
func TestRemovalDuringPairingCannotResurrectTheKey(t *testing.T) {
	clk := newManualClock()
	s, store := newService(t, clk)
	key := keyFor(21)
	fingerprint := Fingerprint(key)

	pairFully(t, s, key, "laptop")

	// A fresh attempt starts, one side confirms, then the user removes the peer.
	s.BeginPairing(key, "laptop")
	s.ConfirmLocal(fingerprint)
	if removal := s.RemoveTrustedPeer(fingerprint); !removal.Removed {
		t.Fatal("removal reported nothing removed")
	}

	// The late confirmation finds no attempt and adds nothing.
	got := s.ConfirmPeer(fingerprint)
	if got.Kind() != PairingFailed {
		t.Fatalf("late confirmation gave %s, want failed", got.Kind())
	}
	if store.Len() != 0 {
		t.Fatalf("store holds %d entries after removal", store.Len())
	}
	if _, trusted := s.Trusted(fingerprint); trusted {
		t.Fatal("the removed peer is trusted again")
	}
}

// TestTrustedPeerValidateCatchesAMismatchedFingerprint is the invariant that keeps an
// entry from being indexed under one identity while authenticating another.
//
// Requirements: 9.4, 9.7
func TestTrustedPeerValidateCatchesAMismatchedFingerprint(t *testing.T) {
	key := keyFor(5)
	good, err := NewTrustedPeer(key, "laptop", baseTime)
	if err != nil {
		t.Fatalf("building an entry: %v", err)
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("a well-formed entry failed validation: %v", err)
	}

	// A fingerprint belonging to a different key is rejected.
	bad := good
	bad.Fingerprint = Fingerprint(keyFor(6))
	if err := bad.Validate(); err == nil {
		t.Fatal("an entry whose fingerprint does not match its key passed validation")
	}

	// So is a key of the wrong length.
	short := good
	short.PublicKey = key[:16]
	if err := short.Validate(); err == nil {
		t.Fatal("a 16-byte public key passed validation")
	}

	// And a store refuses to hold either.
	store := NewMemoryTrustStore()
	if err := store.Put(bad); err == nil {
		t.Fatal("the store accepted an inconsistent entry")
	}
	if store.Len() != 0 {
		t.Fatal("a rejected entry was stored anyway")
	}
}

// TestMemoryTrustStoreHoldsTheRequiredCapacity pins Req 9.10's floor of 32 entries.
//
// Requirements: 9.10
func TestMemoryTrustStoreHoldsTheRequiredCapacity(t *testing.T) {
	store := NewMemoryTrustStore()
	for i := 0; i < MinTrustStoreCapacity+8; i++ {
		key := make([]byte, PublicKeyBytes)
		key[0], key[1] = byte(i), byte(i>>8)
		peer, err := NewTrustedPeer(key, "peer", baseTime)
		if err != nil {
			t.Fatalf("building entry %d: %v", i, err)
		}
		if err := store.Put(peer); err != nil {
			t.Fatalf("storing entry %d: %v", i, err)
		}
	}
	if store.Len() < MinTrustStoreCapacity {
		t.Fatalf("store holds %d entries, want at least %d", store.Len(), MinTrustStoreCapacity)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	// Load is ordered by fingerprint, so a report built from it is deterministic.
	for i := 1; i < len(loaded); i++ {
		if loaded[i].Fingerprint <= loaded[i-1].Fingerprint {
			t.Fatal("Load is not ordered by fingerprint")
		}
	}
}

func equalKeys(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
