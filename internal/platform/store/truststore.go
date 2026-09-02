package store

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/trust"
)

// trustStoreVersion is the on-disk format version. It is inside the tagged region, so a store
// written by a future version cannot be silently reinterpreted by this one.
const trustStoreVersion = 1

// tagDomain separates this HMAC from every other use of the identity key. Without it, a value
// signed for another purpose could be replayed as a trust store tag.
const tagDomain = "peerbeam-truststore-v1"

// TrustStoreFailure reports a trust store that could not be read or that failed its integrity
// check (Req 9.11). The node rejects every Session request while this is outstanding, and the file
// is left exactly as it was found.
type TrustStoreFailure struct {
	Step   string
	Path   string
	Reason string
}

func (f *TrustStoreFailure) Error() string {
	return fmt.Sprintf("trust store failed at %s for %s: %s", f.Step, f.Path, f.Reason)
}

// storedPeer is one entry as it appears on disk. The field names are part of the format, so they
// carry explicit tags and must not drift with a Go rename.
//
// PairedAt is stored as RFC 3339 rather than as a time.Time, because the canonical bytes the tag
// covers have to be reproducible byte for byte, and Go's default time encoding has changed
// representation before. A fixed format string is a format decision, not an implementation detail.
type storedPeer struct {
	Fingerprint string `json:"fingerprint"`
	DisplayName string `json:"displayName"`
	PublicKey   string `json:"publicKey"` // lowercase hex
	PairedAt    string `json:"pairedAt"`  // RFC 3339 with nanoseconds, UTC
}

// storedFile is the whole trust store file.
type storedFile struct {
	Version int          `json:"version"`
	Peers   []storedPeer `json:"peers"`
	// Tag is the HMAC-SHA256 over the canonical entry bytes, in lowercase hex. It is outside
	// the tagged region by definition: the tag cannot cover itself.
	Tag string `json:"tag"`
}

// FileTrustStore persists Trusted_Peer entries in a JSON file with an integrity tag (Req 9.9,
// 9.10, 9.11).
//
// The tag is keyed from the node's own identity private key. That choice has a specific
// consequence worth naming: the tag detects tampering by anything that does not hold the identity
// key, which covers a stray editor, a bad restore, and another user on the machine, but it does
// not defend against an attacker who already has the private key. At that point they can forge
// sessions directly, so the trust store is not the weak link.
//
// Not safe for concurrent use. The PairingService that owns it serialises access.
type FileTrustStore struct {
	path   string
	tagKey []byte
	// loaded is what Load last returned, kept so a Put can rewrite the whole file without
	// re-reading it, and so a failed verification can leave the previous view in place.
	loaded  map[string]trust.TrustedPeer
	isReady bool
}

// NewFileTrustStore returns a store at dir/trusted.json, tagged with a key derived from identity.
func NewFileTrustStore(dir string, identity trust.IdentityKeyPair) (*FileTrustStore, error) {
	if dir == "" {
		resolved, err := DefaultDir()
		if err != nil {
			return nil, err
		}
		dir = resolved
	}
	if len(identity.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("trust store needs the node identity to derive its integrity key")
	}

	// The tag key is derived from the private key rather than being the private key, so a
	// compromise of the tag key alone does not yield a signing key.
	sum := sha256.Sum256(append([]byte(tagDomain+"|key|"), identity.PrivateKey...))

	return &FileTrustStore{
		path:   filepath.Join(dir, TrustedFileName),
		tagKey: sum[:],
		loaded: map[string]trust.TrustedPeer{},
	}, nil
}

// Path is the trust store file's path.
func (s *FileTrustStore) Path() string { return s.path }

// Load reads and verifies the store (Req 9.10, 9.11).
//
// A missing file is not a failure: a node that has never paired has no trust store, and treating
// that as an integrity failure would block every Session on a fresh install. Anything else that
// goes wrong - unreadable, malformed, a tag that does not verify, an entry whose fingerprint does
// not match its key - is a TrustStoreFailure, and the file is not modified in any of those cases.
func (s *FileTrustStore) Load() ([]trust.TrustedPeer, error) {
	raw, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		s.loaded = map[string]trust.TrustedPeer{}
		s.isReady = true
		return nil, nil
	case err != nil:
		return nil, &TrustStoreFailure{Step: "read", Path: s.path, Reason: err.Error()}
	}

	var file storedFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, &TrustStoreFailure{Step: "parse", Path: s.path, Reason: err.Error()}
	}
	if file.Version != trustStoreVersion {
		return nil, &TrustStoreFailure{
			Step:   "check version",
			Path:   s.path,
			Reason: fmt.Sprintf("the file is version %d, this build reads version %d", file.Version, trustStoreVersion),
		}
	}

	// Verify before trusting any entry. Parsing first is unavoidable - the tag covers the
	// canonical form of the parsed entries, not the file bytes, so that reformatting the JSON
	// does not break the tag - but nothing is acted on until the tag verifies.
	expected := s.computeTag(file.Version, file.Peers)
	presented, err := hex.DecodeString(file.Tag)
	if err != nil {
		return nil, &TrustStoreFailure{
			Step:   "verify integrity tag",
			Path:   s.path,
			Reason: "the tag is not valid hex",
		}
	}
	// hmac.Equal rather than bytes.Equal: the comparison is against a value an attacker
	// controls, and a byte-at-a-time comparison would leak the expected tag through timing.
	if !hmac.Equal(expected, presented) {
		return nil, &TrustStoreFailure{
			Step:   "verify integrity tag",
			Path:   s.path,
			Reason: "the integrity tag does not match the stored entries; the file may have been modified",
		}
	}

	peers := make([]trust.TrustedPeer, 0, len(file.Peers))
	seen := make(map[string]struct{}, len(file.Peers))
	for i, stored := range file.Peers {
		peer, err := stored.toTrustedPeer()
		if err != nil {
			return nil, &TrustStoreFailure{
				Step:   "decode entry " + strconv.Itoa(i),
				Path:   s.path,
				Reason: err.Error(),
			}
		}
		// Req 9.4: one entry per fingerprint. A file with two is not something to silently
		// deduplicate, because which of the two keys is the real one is exactly the question
		// a key mismatch turns on.
		if _, duplicate := seen[peer.Fingerprint]; duplicate {
			return nil, &TrustStoreFailure{
				Step:   "decode entries",
				Path:   s.path,
				Reason: "the file holds two entries for fingerprint " + peer.Fingerprint,
			}
		}
		seen[peer.Fingerprint] = struct{}{}
		peers = append(peers, peer)
	}

	loaded := make(map[string]trust.TrustedPeer, len(peers))
	for _, peer := range peers {
		loaded[peer.Fingerprint] = peer
	}
	s.loaded = loaded
	s.isReady = true

	sort.Slice(peers, func(i, j int) bool { return peers[i].Fingerprint < peers[j].Fingerprint })
	return peers, nil
}

// Ready reports whether Load has succeeded. Req 9.10 loads before the first Session request, and
// Req 9.11 blocks every request while the store is failed, so the caller needs to distinguish
// "empty" from "not yet read".
func (s *FileTrustStore) Ready() bool { return s.isReady }

// Put adds or replaces the entry for a fingerprint and rewrites the file (Req 9.4).
//
// It refuses before Load has succeeded. Writing into a store that was never read would drop every
// entry already on disk, which is precisely the silent key loss Req 9.9 forbids.
func (s *FileTrustStore) Put(peer trust.TrustedPeer) error {
	if err := peer.Validate(); err != nil {
		return err
	}
	if !s.isReady {
		return &TrustStoreFailure{
			Step:   "put",
			Path:   s.path,
			Reason: "the trust store has not been loaded, so writing would discard its contents",
		}
	}

	s.loaded[peer.Fingerprint] = peer.Clone()
	return s.write()
}

// Remove deletes an entry and reports whether it existed (Req 9.8). It is reached only from a user
// removal request: trust.PairingService is the sole caller, which is how Req 9.9 is enforced.
func (s *FileTrustStore) Remove(fingerprint string) (bool, error) {
	if !s.isReady {
		return false, &TrustStoreFailure{
			Step:   "remove",
			Path:   s.path,
			Reason: "the trust store has not been loaded",
		}
	}
	if _, found := s.loaded[fingerprint]; !found {
		return false, nil
	}
	delete(s.loaded, fingerprint)
	if err := s.write(); err != nil {
		return false, err
	}
	return true, nil
}

// Len is the number of entries held.
func (s *FileTrustStore) Len() int { return len(s.loaded) }

// write serialises the store and replaces the file atomically.
//
// The write goes to a temporary file in the same directory and is renamed over the target, because
// a truncate-then-write would leave an empty or half-written trust store if the process died in
// between - losing every paired key to a crash, which Req 9.9 and 9.10 both rule out. Rename
// within a directory is atomic on every platform this targets.
func (s *FileTrustStore) write() error {
	peers := make([]storedPeer, 0, len(s.loaded))
	for _, peer := range s.loaded {
		peers = append(peers, fromTrustedPeer(peer))
	}
	// Sorted so the file is byte-stable across writes: an unsorted file would differ after
	// every save and make a diff useless for spotting a real change.
	sort.Slice(peers, func(i, j int) bool { return peers[i].Fingerprint < peers[j].Fingerprint })

	file := storedFile{
		Version: trustStoreVersion,
		Peers:   peers,
		Tag:     hex.EncodeToString(s.computeTag(trustStoreVersion, peers)),
	}
	encoded, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return &TrustStoreFailure{Step: "encode", Path: s.path, Reason: err.Error()}
	}
	encoded = append(encoded, '\n')

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, OwnerOnlyDirMode); err != nil {
		return &TrustStoreFailure{Step: "create directory", Path: dir, Reason: err.Error()}
	}

	temp, err := os.CreateTemp(dir, TrustedFileName+".*.tmp")
	if err != nil {
		return &TrustStoreFailure{Step: "create temporary file", Path: dir, Reason: err.Error()}
	}
	tempPath := temp.Name()
	cleanup := func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}

	if err := temp.Chmod(OwnerOnlyFileMode); err != nil {
		cleanup()
		return &TrustStoreFailure{Step: "set permissions", Path: tempPath, Reason: err.Error()}
	}
	if _, err := temp.Write(encoded); err != nil {
		cleanup()
		return &TrustStoreFailure{Step: "write", Path: tempPath, Reason: err.Error()}
	}
	// Sync before the rename, or the rename can land while the contents are still in the page
	// cache and a power loss leaves an empty file where the trust store was.
	if err := temp.Sync(); err != nil {
		cleanup()
		return &TrustStoreFailure{Step: "flush to disk", Path: tempPath, Reason: err.Error()}
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return &TrustStoreFailure{Step: "close", Path: tempPath, Reason: err.Error()}
	}

	if err := os.Rename(tempPath, s.path); err != nil {
		_ = os.Remove(tempPath)
		return &TrustStoreFailure{Step: "replace", Path: s.path, Reason: err.Error()}
	}
	// Best effort on the final permissions: the rename preserves the temporary file's mode on
	// POSIX, but on Windows the ACL has to be applied to the destination name.
	_ = secureFile(s.path)
	return nil
}

// computeTag is the HMAC over the canonical entry bytes.
//
// The canonical form is built field by field with explicit separators rather than by hashing the
// JSON, and that matters for two reasons. Hashing the JSON would make the tag depend on key order
// and whitespace, so reformatting the file would look like tampering. And a naive concatenation
// without separators would let two different entry sets produce the same bytes - a display name
// ending in a fingerprint-shaped string could impersonate the next field - so every field is
// length-prefixed.
func (s *FileTrustStore) computeTag(version int, peers []storedPeer) []byte {
	mac := hmac.New(sha256.New, s.tagKey)
	writeField := func(value string) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		mac.Write(length[:])
		mac.Write([]byte(value))
	}

	mac.Write([]byte(tagDomain))
	writeField(strconv.Itoa(version))
	writeField(strconv.Itoa(len(peers)))
	for _, peer := range peers {
		writeField(peer.Fingerprint)
		writeField(peer.DisplayName)
		writeField(peer.PublicKey)
		writeField(peer.PairedAt)
	}
	return mac.Sum(nil)
}

func fromTrustedPeer(peer trust.TrustedPeer) storedPeer {
	return storedPeer{
		Fingerprint: peer.Fingerprint,
		DisplayName: peer.DisplayName,
		PublicKey:   hex.EncodeToString(peer.PublicKey),
		PairedAt:    peer.PairedAt.UTC().Format(time.RFC3339Nano),
	}
}

func (p storedPeer) toTrustedPeer() (trust.TrustedPeer, error) {
	key, err := hex.DecodeString(p.PublicKey)
	if err != nil {
		return trust.TrustedPeer{}, fmt.Errorf("public key is not valid hex: %w", err)
	}
	pairedAt, err := time.Parse(time.RFC3339Nano, p.PairedAt)
	if err != nil {
		return trust.TrustedPeer{}, fmt.Errorf("pairedAt is not RFC 3339: %w", err)
	}

	peer := trust.TrustedPeer{
		Fingerprint: p.Fingerprint,
		DisplayName: p.DisplayName,
		PublicKey:   key,
		PairedAt:    pairedAt,
	}
	// Validate catches the case that matters: an entry indexed under one fingerprint while
	// carrying another's key would authenticate the wrong peer.
	if err := peer.Validate(); err != nil {
		return trust.TrustedPeer{}, err
	}
	return peer, nil
}

var _ trust.TrustStore = (*FileTrustStore)(nil)
