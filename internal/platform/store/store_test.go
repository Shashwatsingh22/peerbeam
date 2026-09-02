package store

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/peerbeam/peerbeam/internal/core/trust"
)

var baseTime = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

// newIdentity generates a key pair for a test store.
func newIdentity(t rapid.TB) trust.IdentityKeyPair {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating an identity: %v", err)
	}
	return trust.IdentityKeyPair{PublicKey: public, PrivateKey: private}
}

// peerFor builds a valid entry from a seed, with a multi-byte display name so the JSON and the tag
// are exercised against something other than ASCII.
func peerFor(t rapid.TB, seed int, name string) trust.TrustedPeer {
	t.Helper()
	key := make([]byte, ed25519.PublicKeySize)
	key[0], key[1] = byte(seed), byte(seed>>8)
	for i := 2; i < len(key); i++ {
		key[i] = byte(seed + i)
	}
	peer, err := trust.NewTrustedPeer(key, name, baseTime.Add(time.Duration(seed)*time.Second))
	if err != nil {
		t.Fatalf("building entry %d: %v", seed, err)
	}
	return peer
}

// TestProperty31TrustStorePersistsFaithfully covers
// Property 31: The trust store persists faithfully, holds one entry per fingerprint, and never
// loses a key silently.
//
// Validates: Requirements 9.4, 9.9, 9.10, 9.11
func TestProperty31TrustStorePersistsFaithfully(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		dir, removeDir := makeTempDir(rt)
		defer removeDir()
		identity := newIdentity(rt)

		store, err := NewFileTrustStore(dir, identity)
		if err != nil {
			rt.Fatalf("creating the store: %v", err)
		}
		// Req 9.10: entries load before the first Session request, and a missing file is a
		// fresh install rather than a failure.
		if _, err := store.Load(); err != nil {
			rt.Fatalf("loading an absent store: %v", err)
		}

		// Entries with multi-byte display names.
		//
		// The property caps at 8 rather than the 64 the property statement names, because
		// every Put rewrites the whole file with an fsync: 64 entries across a hundred
		// iterations is thousands of syncs and turns a fast property into a slow one. The
		// upper end of the range is covered by TestTrustStoreHoldsTheRequiredCapacity below,
		// which stores 40 entries once. What the property is actually exercising - faithful
		// round trips, one entry per fingerprint, and tamper detection - does not get stronger
		// with more entries.
		count := rapid.IntRange(1, 8).Draw(rt, "entryCount")
		names := []string{"laptop", "デスクトップ", "café-serveur", "Ω-box", "emoji 🖥"}

		want := map[string]trust.TrustedPeer{}
		for i := 0; i < count; i++ {
			name := names[i%len(names)]
			peer := peerFor(rt, i+1, name)
			if err := store.Put(peer); err != nil {
				rt.Fatalf("storing entry %d: %v", i, err)
			}
			want[peer.Fingerprint] = peer
		}

		// Req 9.4: a repeated pairing with a fingerprint already stored replaces the entry
		// rather than adding a second one.
		repeat := peerFor(rt, 1, "renamed after re-pairing")
		repeat.PairedAt = baseTime.Add(time.Hour)
		if err := store.Put(repeat); err != nil {
			rt.Fatalf("re-pairing: %v", err)
		}
		want[repeat.Fingerprint] = repeat

		// Saving and reloading yields exactly the same set, every field preserved. A fresh
		// store instance is used so nothing is served from memory.
		reloaded, err := NewFileTrustStore(dir, identity)
		if err != nil {
			rt.Fatalf("reopening: %v", err)
		}
		got, err := reloaded.Load()
		if err != nil {
			rt.Fatalf("reloading: %v", err)
		}
		if len(got) != len(want) {
			rt.Fatalf("reloaded %d entries, stored %d", len(got), len(want))
		}
		seen := map[string]struct{}{}
		for _, peer := range got {
			expected, found := want[peer.Fingerprint]
			if !found {
				rt.Fatalf("reloaded an entry that was never stored: %s", peer.Fingerprint)
			}
			if !peer.Equal(expected) {
				rt.Fatalf("entry %s changed across a save and reload:\n stored   %+v\n reloaded %+v",
					peer.Fingerprint, expected, peer)
			}
			// Req 9.4: one entry per fingerprint.
			if _, duplicate := seen[peer.Fingerprint]; duplicate {
				rt.Fatalf("fingerprint %s appears twice", peer.Fingerprint)
			}
			seen[peer.Fingerprint] = struct{}{}
		}

		// Req 9.9: no sequence without a removal loses a fingerprint. Every Put above was an
		// addition or a replacement, so every fingerprint stored is still present.
		for fingerprint := range want {
			if _, found := seen[fingerprint]; !found {
				rt.Fatalf("fingerprint %s was lost without a removal request", fingerprint)
			}
		}

		// Req 9.11: any single-byte mutation of the file fails the integrity check, leaves the
		// file unmodified, and blocks every Session request.
		path := filepath.Join(dir, TrustedFileName)
		original, err := os.ReadFile(path)
		if err != nil {
			rt.Fatalf("reading the file: %v", err)
		}

		mutated := append([]byte(nil), original...)
		at := rapid.IntRange(0, len(mutated)-1).Draw(rt, "mutateAt")
		// Flip to another printable byte, so the file usually still parses as JSON and the tag
		// is what catches it rather than the parser.
		mutated[at] = flipPrintable(mutated[at])

		if err := os.WriteFile(path, mutated, 0o600); err != nil {
			rt.Fatalf("writing the mutated file: %v", err)
		}

		tampered, err := NewFileTrustStore(dir, identity)
		if err != nil {
			rt.Fatalf("reopening after mutation: %v", err)
		}
		entries, loadErr := tampered.Load()

		// A mutation that happens to be a no-op - flipping a byte to itself is impossible
		// here, but changing whitespace inside the JSON is not - would legitimately still
		// verify, because the tag covers the canonical entries rather than the file bytes.
		// That is by design: reformatting must not look like tampering. So the assertion is
		// conditional on the mutation having changed something the tag covers.
		reserialised, sameEntries := entriesMatch(entries, want)
		if loadErr == nil && !sameEntries {
			rt.Fatalf("a mutation at byte %d changed the entries but still verified: %s",
				at, reserialised)
		}
		if loadErr != nil {
			// The failure names the step, and the file is untouched.
			var failure *TrustStoreFailure
			if !asTrustStoreFailure(loadErr, &failure) {
				rt.Fatalf("load error is %T (%v), want *TrustStoreFailure", loadErr, loadErr)
			}
			if strings.TrimSpace(failure.Step) == "" || strings.TrimSpace(failure.Reason) == "" {
				rt.Fatalf("failure carries no step or reason: %+v", failure)
			}
			if !tampered.Ready() {
				// Req 9.11: while the store is failed, writing is refused too, so a
				// blocked node cannot quietly overwrite the file it could not read.
				if err := tampered.Put(peerFor(rt, 999, "new")); err == nil {
					rt.Fatal("a failed store accepted a write")
				}
			}
			after, err := os.ReadFile(path)
			if err != nil {
				rt.Fatalf("re-reading the file: %v", err)
			}
			if string(after) != string(mutated) {
				rt.Fatal("a failed load modified the file")
			}
		}
	})
}

// entriesMatch reports whether a loaded set equals the expected set, and renders a difference.
func entriesMatch(got []trust.TrustedPeer, want map[string]trust.TrustedPeer) (string, bool) {
	if len(got) != len(want) {
		return "entry count differs", false
	}
	for _, peer := range got {
		expected, found := want[peer.Fingerprint]
		if !found || !peer.Equal(expected) {
			return "entry " + peer.Fingerprint + " differs", false
		}
	}
	return "", true
}

func asTrustStoreFailure(err error, target **TrustStoreFailure) bool {
	failure, ok := err.(*TrustStoreFailure)
	if ok {
		*target = failure
	}
	return ok
}

// flipPrintable maps a byte to a different byte, staying printable where possible so the mutated
// file usually still parses and the integrity tag is what rejects it.
func flipPrintable(b byte) byte {
	switch {
	case b >= '0' && b <= '8':
		return b + 1
	case b == '9':
		return '0'
	case b >= 'a' && b <= 'e':
		return b + 1
	case b == 'f':
		return 'a'
	case b >= 'A' && b <= 'Y':
		return b + 1
	default:
		return 'x'
	}
}

// TestTrustStoreRejectsAWriteBeforeLoad pins the guard that stops silent key loss: writing into a
// store that was never read would drop everything already on disk.
//
// Requirements: 9.9, 9.10
func TestTrustStoreRejectsAWriteBeforeLoad(t *testing.T) {
	dir := t.TempDir()
	identity := newIdentity(t)

	first, err := NewFileTrustStore(dir, identity)
	if err != nil {
		t.Fatalf("creating: %v", err)
	}
	if _, err := first.Load(); err != nil {
		t.Fatalf("loading: %v", err)
	}
	peer := peerFor(t, 1, "laptop")
	if err := first.Put(peer); err != nil {
		t.Fatalf("storing: %v", err)
	}

	// A second instance that never loaded must refuse to write.
	second, err := NewFileTrustStore(dir, identity)
	if err != nil {
		t.Fatalf("creating the second store: %v", err)
	}
	if second.Ready() {
		t.Fatal("an unloaded store reports itself ready")
	}
	if err := second.Put(peerFor(t, 2, "desktop")); err == nil {
		t.Fatal("an unloaded store accepted a write")
	}
	if _, err := second.Remove(peer.Fingerprint); err == nil {
		t.Fatal("an unloaded store accepted a removal")
	}

	// The original entry is still there, which is the point.
	third, _ := NewFileTrustStore(dir, identity)
	got, err := third.Load()
	if err != nil {
		t.Fatalf("reloading: %v", err)
	}
	if len(got) != 1 || !got[0].Equal(peer) {
		t.Fatalf("the entry was lost: %+v", got)
	}
}

// TestTrustStoreTagIsKeyedToTheIdentity checks that a store written by one node cannot be read by
// another: the tag is derived from the identity key, so a copied file fails verification.
//
// Requirements: 9.11
func TestTrustStoreTagIsKeyedToTheIdentity(t *testing.T) {
	dir := t.TempDir()
	mine := newIdentity(t)
	theirs := newIdentity(t)

	store, _ := NewFileTrustStore(dir, mine)
	if _, err := store.Load(); err != nil {
		t.Fatalf("loading: %v", err)
	}
	if err := store.Put(peerFor(t, 1, "laptop")); err != nil {
		t.Fatalf("storing: %v", err)
	}

	// Another identity reading the same file fails the tag check rather than trusting entries
	// it cannot verify.
	other, _ := NewFileTrustStore(dir, theirs)
	if _, err := other.Load(); err == nil {
		t.Fatal("a store written under one identity verified under another")
	}

	// And the original identity still reads it.
	if _, err := store.Load(); err != nil {
		t.Fatalf("the owning identity can no longer read its own store: %v", err)
	}
}

// TestTrustStoreReformattingDoesNotLookLikeTampering is the reason the tag covers canonical entry
// bytes rather than the file bytes: an operator who pretty-prints the JSON has not tampered with it.
//
// Requirements: 9.11
func TestTrustStoreReformattingDoesNotLookLikeTampering(t *testing.T) {
	dir := t.TempDir()
	identity := newIdentity(t)
	store, _ := NewFileTrustStore(dir, identity)
	if _, err := store.Load(); err != nil {
		t.Fatalf("loading: %v", err)
	}
	peer := peerFor(t, 1, "laptop")
	if err := store.Put(peer); err != nil {
		t.Fatalf("storing: %v", err)
	}

	path := filepath.Join(dir, TrustedFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}

	// Reserialise with no indentation: same data, different bytes.
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	compact, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-encoding: %v", err)
	}
	if string(compact) == string(raw) {
		t.Fatal("the reformatting produced identical bytes, so the test proves nothing")
	}
	if err := os.WriteFile(path, compact, 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	reopened, _ := NewFileTrustStore(dir, identity)
	got, err := reopened.Load()
	if err != nil {
		t.Fatalf("a reformatted file failed verification: %v", err)
	}
	if len(got) != 1 || !got[0].Equal(peer) {
		t.Fatalf("the entry did not survive reformatting: %+v", got)
	}
}

// TestTrustStoreRejectsADuplicateFingerprintOnDisk checks that a file holding two entries for one
// fingerprint is a failure rather than something to silently deduplicate: which of the two keys is
// real is exactly the question a key mismatch turns on.
//
// Requirements: 9.4, 9.11
func TestTrustStoreRejectsADuplicateFingerprintOnDisk(t *testing.T) {
	dir := t.TempDir()
	identity := newIdentity(t)
	store, _ := NewFileTrustStore(dir, identity)
	if _, err := store.Load(); err != nil {
		t.Fatalf("loading: %v", err)
	}
	peer := peerFor(t, 1, "laptop")
	if err := store.Put(peer); err != nil {
		t.Fatalf("storing: %v", err)
	}

	// Duplicate the entry and retag, so the tag verifies and the duplicate check is what
	// catches it.
	path := filepath.Join(dir, TrustedFileName)
	raw, _ := os.ReadFile(path)
	var file storedFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	file.Peers = append(file.Peers, file.Peers[0])
	file.Tag = hexOf(store.computeTag(file.Version, file.Peers))
	retagged, _ := json.MarshalIndent(file, "", "  ")
	if err := os.WriteFile(path, retagged, 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	reopened, _ := NewFileTrustStore(dir, identity)
	_, err := reopened.Load()
	if err == nil {
		t.Fatal("a file with two entries for one fingerprint loaded successfully")
	}
	if !strings.Contains(err.Error(), "two entries") {
		t.Fatalf("error %q does not name the duplicate", err)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, digits[v>>4], digits[v&0x0f])
	}
	return string(out)
}

// TestTrustStoreRejectsAnEntryWhoseFingerprintDoesNotMatchItsKey is the invariant that stops an
// entry from being indexed under one identity while authenticating another.
//
// Requirements: 9.4, 9.7, 9.11
func TestTrustStoreRejectsAnEntryWhoseFingerprintDoesNotMatchItsKey(t *testing.T) {
	dir := t.TempDir()
	identity := newIdentity(t)
	store, _ := NewFileTrustStore(dir, identity)
	if _, err := store.Load(); err != nil {
		t.Fatalf("loading: %v", err)
	}
	if err := store.Put(peerFor(t, 1, "laptop")); err != nil {
		t.Fatalf("storing: %v", err)
	}

	// Swap in another peer's key while keeping the fingerprint, and retag so the tag verifies.
	path := filepath.Join(dir, TrustedFileName)
	raw, _ := os.ReadFile(path)
	var file storedFile
	_ = json.Unmarshal(raw, &file)
	file.Peers[0].PublicKey = hexOf(peerFor(t, 2, "other").PublicKey)
	file.Tag = hexOf(store.computeTag(file.Version, file.Peers))
	retagged, _ := json.MarshalIndent(file, "", "  ")
	if err := os.WriteFile(path, retagged, 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	reopened, _ := NewFileTrustStore(dir, identity)
	if _, err := reopened.Load(); err == nil {
		t.Fatal("an entry whose fingerprint does not match its key was loaded")
	}
}

// TestTrustStoreRemoveOnlyDeletesWhatWasAsked covers Req 9.8 and 9.9: a removal takes one entry and
// leaves the rest.
//
// Requirements: 9.8, 9.9
func TestTrustStoreRemoveOnlyDeletesWhatWasAsked(t *testing.T) {
	dir := t.TempDir()
	identity := newIdentity(t)
	store, _ := NewFileTrustStore(dir, identity)
	if _, err := store.Load(); err != nil {
		t.Fatalf("loading: %v", err)
	}

	peers := make([]trust.TrustedPeer, 0, 5)
	for i := 1; i <= 5; i++ {
		peer := peerFor(t, i, "peer")
		if err := store.Put(peer); err != nil {
			t.Fatalf("storing %d: %v", i, err)
		}
		peers = append(peers, peer)
	}

	removed, err := store.Remove(peers[2].Fingerprint)
	if err != nil {
		t.Fatalf("removing: %v", err)
	}
	if !removed {
		t.Fatal("removing a present entry reported nothing removed")
	}

	// Removing an absent entry is a no-op rather than an error.
	removed, err = store.Remove(peers[2].Fingerprint)
	if err != nil {
		t.Fatalf("removing again: %v", err)
	}
	if removed {
		t.Fatal("removing an absent entry reported a removal")
	}

	reopened, _ := NewFileTrustStore(dir, identity)
	got, err := reopened.Load()
	if err != nil {
		t.Fatalf("reloading: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("store holds %d entries after one removal, want 4", len(got))
	}
	for _, peer := range got {
		if peer.Fingerprint == peers[2].Fingerprint {
			t.Fatal("the removed entry came back")
		}
	}
}

// TestKeyStoreGeneratesOnceAndReloads covers Req 9.1: the identity is generated on first run and
// loaded thereafter, with owner-only permissions.
//
// Requirements: 9.1, 9.2
func TestKeyStoreGeneratesOnceAndReloads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")

	store, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatalf("creating: %v", err)
	}

	first, err := store.LoadOrCreateIdentity()
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if len(first.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("public key is %d bytes, want %d", len(first.PublicKey), ed25519.PublicKeySize)
	}
	if len(first.PrivateKey) != ed25519.PrivateKeySize {
		t.Fatalf("private key is %d bytes, want %d", len(first.PrivateKey), ed25519.PrivateKeySize)
	}
	// The fingerprint the node publishes is derived from this key.
	if first.Fingerprint() == "" {
		t.Fatal("the identity has no fingerprint")
	}

	// Req 9.1: owner-only permissions on POSIX. On Windows the ACL is the mechanism and the
	// mode bits mean nothing, so the check is skipped there.
	path := store.IdentityPath()
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if got := info.Mode().Perm(); got != OwnerOnlyFileMode {
			t.Fatalf("identity.key is %#o, want %#o", got, OwnerOnlyFileMode)
		}
	}

	// A second run loads the same identity rather than generating a new one. Generating again
	// would change the node's identity and invalidate every peer's trust store entry.
	second, err := store.LoadOrCreateIdentity()
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if first.Fingerprint() != second.Fingerprint() {
		t.Fatalf("the identity changed between runs: %s then %s",
			first.Fingerprint(), second.Fingerprint())
	}

	// And a fresh store instance over the same directory agrees.
	reopened, _ := NewFileKeyStore(dir)
	third, err := reopened.LoadOrCreateIdentity()
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	if third.Fingerprint() != first.Fingerprint() {
		t.Fatal("a reopened key store produced a different identity")
	}
}

// TestKeyStoreRejectsALoosenedKeyFile covers the Req 9.2 case that only checking at creation would
// miss: a key written correctly and later made readable by others.
//
// Requirements: 9.2
func TestKeyStoreRejectsALoosenedKeyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permissions are enforced by ACL on Windows, not by mode bits")
	}

	dir := t.TempDir()
	store, _ := NewFileKeyStore(dir)
	if _, err := store.LoadOrCreateIdentity(); err != nil {
		t.Fatalf("first run: %v", err)
	}

	path := store.IdentityPath()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("loosening permissions: %v", err)
	}

	_, err := store.LoadOrCreateIdentity()
	if err == nil {
		t.Fatal("a world-readable private key was accepted")
	}
	failure, ok := err.(*KeySetupFailure)
	if !ok {
		t.Fatalf("error is %T (%v), want *KeySetupFailure", err, err)
	}
	// Req 9.2: the report names the failing step.
	if !strings.Contains(failure.Step, "permission") {
		t.Fatalf("failure step is %q, want one naming permissions", failure.Step)
	}
	if failure.Path != path {
		t.Fatalf("failure names %q, want %q", failure.Path, path)
	}
	if !strings.Contains(failure.Error(), "0644") && !strings.Contains(failure.Error(), "644") {
		t.Fatalf("failure %q does not name the offending mode", failure.Error())
	}

	// Restoring the permissions makes it usable again, without changing the identity.
	if err := os.Chmod(path, OwnerOnlyFileMode); err != nil {
		t.Fatalf("restoring: %v", err)
	}
	if _, err := store.LoadOrCreateIdentity(); err != nil {
		t.Fatalf("after restoring permissions: %v", err)
	}
}

// TestKeyStoreReportsTheFailingStep covers Req 9.2's requirement that the report name what failed,
// across the distinguishable failure modes.
//
// Requirements: 9.2
func TestKeyStoreReportsTheFailingStep(t *testing.T) {
	t.Run("corrupt key file", func(t *testing.T) {
		dir := t.TempDir()
		store, _ := NewFileKeyStore(dir)
		if _, err := store.LoadOrCreateIdentity(); err != nil {
			t.Fatalf("first run: %v", err)
		}
		if err := os.WriteFile(store.IdentityPath(), []byte("not a PEM block"), OwnerOnlyFileMode); err != nil {
			t.Fatalf("corrupting: %v", err)
		}

		_, err := store.LoadOrCreateIdentity()
		if err == nil {
			t.Fatal("a corrupt key file was accepted")
		}
		failure, ok := err.(*KeySetupFailure)
		if !ok {
			t.Fatalf("error is %T, want *KeySetupFailure", err)
		}
		if !strings.Contains(failure.Step, "read") {
			t.Fatalf("step is %q, want one naming the read", failure.Step)
		}
	})

	t.Run("wrong PEM type", func(t *testing.T) {
		dir := t.TempDir()
		store, _ := NewFileKeyStore(dir)
		if _, err := store.LoadOrCreateIdentity(); err != nil {
			t.Fatalf("first run: %v", err)
		}
		wrong := "-----BEGIN SOMETHING ELSE-----\nAAAA\n-----END SOMETHING ELSE-----\n"
		if err := os.WriteFile(store.IdentityPath(), []byte(wrong), OwnerOnlyFileMode); err != nil {
			t.Fatalf("writing: %v", err)
		}
		if _, err := store.LoadOrCreateIdentity(); err == nil {
			t.Fatal("a PEM block of the wrong type was accepted")
		}
	})

	t.Run("truncated key", func(t *testing.T) {
		dir := t.TempDir()
		store, _ := NewFileKeyStore(dir)
		if _, err := store.LoadOrCreateIdentity(); err != nil {
			t.Fatalf("first run: %v", err)
		}
		raw, _ := os.ReadFile(store.IdentityPath())
		// Re-encode with a short key body.
		short := strings.Replace(string(raw), "\n", "\nAA\n", 1)
		if err := os.WriteFile(store.IdentityPath(), []byte(short), OwnerOnlyFileMode); err != nil {
			t.Fatalf("writing: %v", err)
		}
		if _, err := store.LoadOrCreateIdentity(); err == nil {
			t.Fatal("a truncated key was accepted")
		}
	})
}

// TestKeyStoreCreatesTheStateDirectory checks that a first run on a machine with no ~/.peerbeam
// works, and that the directory is owner-only.
//
// Requirements: 9.1
func TestKeyStoreCreatesTheStateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "state")
	store, _ := NewFileKeyStore(dir)

	if _, err := store.LoadOrCreateIdentity(); err != nil {
		t.Fatalf("first run: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("the directory was not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("the state path is not a directory")
	}
	if runtime.GOOS != "windows" {
		if got := info.Mode().Perm(); got != OwnerOnlyDirMode {
			t.Fatalf("state directory is %#o, want %#o", got, OwnerOnlyDirMode)
		}
	}
}

// TestTrustStoreNeedsAnIdentity checks the constructor guard: without the identity there is no key
// to tag with, and a store with no integrity tag is not one Req 9.11 can be satisfied with.
//
// Requirements: 9.11
func TestTrustStoreNeedsAnIdentity(t *testing.T) {
	if _, err := NewFileTrustStore(t.TempDir(), trust.IdentityKeyPair{}); err == nil {
		t.Fatal("a trust store was created with no identity")
	}
}

// makeTempDir creates a temporary directory for one property test iteration.
//
// rapid.TB has neither TempDir nor Cleanup, so the directory is removed by the caller's own defer.
// rapid runs a hundred iterations per property and each one writes a trust store, so leaving them
// behind would fill the disk over a full test run.
func makeTempDir(t rapid.TB) (dir string, remove func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "peerbeam-store-*")
	if err != nil {
		t.Fatalf("creating a temporary directory: %v", err)
	}
	return dir, func() { _ = os.RemoveAll(dir) }
}

// TestTrustStoreHoldsTheRequiredCapacity covers the floor Req 9.10 sets: at least 32 entries, held
// across a restart with every field intact.
//
// It is a fixed test rather than part of the property because storing forty entries means forty
// file rewrites, which is worth doing once rather than a hundred times.
//
// Requirements: 9.10, 9.4
func TestTrustStoreHoldsTheRequiredCapacity(t *testing.T) {
	dir := t.TempDir()
	identity := newIdentity(t)

	store, err := NewFileTrustStore(dir, identity)
	if err != nil {
		t.Fatalf("creating: %v", err)
	}
	if _, err := store.Load(); err != nil {
		t.Fatalf("loading: %v", err)
	}

	const count = trust.MinTrustStoreCapacity + 8
	want := make(map[string]trust.TrustedPeer, count)
	for i := 1; i <= count; i++ {
		peer := peerFor(t, i, "peer-"+strings.Repeat("ü", i%4+1))
		if err := store.Put(peer); err != nil {
			t.Fatalf("storing entry %d: %v", i, err)
		}
		want[peer.Fingerprint] = peer
	}
	if store.Len() != count {
		t.Fatalf("store holds %d entries, want %d", store.Len(), count)
	}

	// Reload from disk with a fresh instance, so nothing is served from memory.
	reopened, _ := NewFileTrustStore(dir, identity)
	got, err := reopened.Load()
	if err != nil {
		t.Fatalf("reloading %d entries: %v", count, err)
	}
	if len(got) != count {
		t.Fatalf("reloaded %d entries, want %d", len(got), count)
	}
	if len(got) < trust.MinTrustStoreCapacity {
		t.Fatalf("store holds %d entries, under the Req 9.10 floor of %d",
			len(got), trust.MinTrustStoreCapacity)
	}
	for _, peer := range got {
		expected, found := want[peer.Fingerprint]
		if !found {
			t.Fatalf("reloaded an entry that was never stored: %s", peer.Fingerprint)
		}
		if !peer.Equal(expected) {
			t.Fatalf("entry %s changed across the restart", peer.Fingerprint)
		}
	}

	// Load returns entries ordered by fingerprint, so any listing built from it is stable.
	for i := 1; i < len(got); i++ {
		if got[i].Fingerprint <= got[i-1].Fingerprint {
			t.Fatal("Load is not ordered by fingerprint")
		}
	}
}
