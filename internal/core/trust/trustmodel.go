package trust

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"sort"
	"time"
)

// MinTrustStoreCapacity is the number of entries a trust store must hold (Req 9.10).
// It is a floor, not a ceiling: the in-memory store below is unbounded, and the
// constant exists so a file-backed implementation can be tested against the
// requirement.
const MinTrustStoreCapacity = 32

// TrustedPeer is one entry in the trust store: a Peer the user has paired with.
//
// PublicKey and Fingerprint are both stored even though the second is derived from the
// first. The fingerprint is the key everything else indexes on, and recomputing it on
// every lookup would mean hashing on the Session admission path; keeping both makes the
// invariant checkable instead, which Validate does.
type TrustedPeer struct {
	Fingerprint string    `json:"fingerprint"`
	DisplayName string    `json:"displayName"`
	PublicKey   []byte    `json:"publicKey"`
	PairedAt    time.Time `json:"pairedAt"`
}

// Validate checks that an entry is internally consistent: a well-formed key, a
// well-formed fingerprint, and a fingerprint that actually belongs to the key.
//
// The last check is the one that matters. An entry whose fingerprint does not match its
// key would be indexed under one identity while authenticating another, which is
// exactly the confusion Req 9.7 exists to prevent.
func (p TrustedPeer) Validate() error {
	if err := CheckPublicKey(p.PublicKey); err != nil {
		return fmt.Errorf("trusted peer %q: %w", p.DisplayName, err)
	}
	if !IsFingerprint(p.Fingerprint) {
		return fmt.Errorf("trusted peer %q: fingerprint %q is not %d lowercase hex characters",
			p.DisplayName, p.Fingerprint, FingerprintHexChars)
	}
	if want := Fingerprint(p.PublicKey); p.Fingerprint != want {
		return fmt.Errorf("trusted peer %q: fingerprint %s does not match its public key (want %s)",
			p.DisplayName, p.Fingerprint, want)
	}
	return nil
}

// Equal compares two entries field by field, including the key bytes.
func (p TrustedPeer) Equal(other TrustedPeer) bool {
	return p.Fingerprint == other.Fingerprint &&
		p.DisplayName == other.DisplayName &&
		bytes.Equal(p.PublicKey, other.PublicKey) &&
		p.PairedAt.Equal(other.PairedAt)
}

// Clone returns a deep copy, so a caller holding an entry cannot mutate the store's key
// bytes through the slice it was handed.
func (p TrustedPeer) Clone() TrustedPeer {
	out := p
	out.PublicKey = append([]byte(nil), p.PublicKey...)
	return out
}

// NewTrustedPeer builds an entry from a public key, deriving the fingerprint so the two
// cannot disagree.
func NewTrustedPeer(publicKey []byte, displayName string, pairedAt time.Time) (TrustedPeer, error) {
	if err := CheckPublicKey(publicKey); err != nil {
		return TrustedPeer{}, err
	}
	return TrustedPeer{
		Fingerprint: Fingerprint(publicKey),
		DisplayName: displayName,
		PublicKey:   append([]byte(nil), publicKey...),
		PairedAt:    pairedAt,
	}, nil
}

// IdentityKeyPair is this node's long-term Ed25519 key pair (Req 9.1).
type IdentityKeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// Fingerprint is this node's own fingerprint, which it publishes in its announcement.
func (k IdentityKeyPair) Fingerprint() string { return Fingerprint(k.PublicKey) }

// KeyStore holds this node's long-term identity. The interface is one method because
// that is all the core needs: generation on first run and loading afterwards are the
// same operation from the caller's side, and both are the platform adapter's problem.
type KeyStore interface {
	// LoadOrCreateIdentity generates the key pair on first run and stores the private
	// key readable by this user only (Req 9.1). It returns an error naming the failing
	// step, so the node can reject Sessions until it succeeds (Req 9.2).
	LoadOrCreateIdentity() (IdentityKeyPair, error)
}

// TrustStore persists Trusted_Peer entries across restarts (Req 9.10).
type TrustStore interface {
	// Load reads every entry and verifies the store's integrity. It runs before the
	// first Session request (Req 9.10, 9.11).
	Load() ([]TrustedPeer, error)
	// Put adds or replaces an entry, keeping exactly one per fingerprint (Req 9.4).
	Put(peer TrustedPeer) error
	// Remove deletes an entry. It is called only from a user removal request
	// (Req 9.8, 9.9), which is why it has no other caller in this package.
	Remove(fingerprint string) (bool, error)
}

// MemoryTrustStore is an in-memory TrustStore. It is the reference implementation the
// trust rules are tested against, and it is what internal/app wires when no
// persistence is configured. The file-backed store in internal/platform/store must
// behave identically.
//
// Not safe for concurrent use; the owning PairingService serialises access.
type MemoryTrustStore struct {
	peers map[string]TrustedPeer
	// failure, when set, makes every operation fail. It models the Req 9.11 state
	// where the store could not be read or failed its integrity check, so the
	// admission rules can be tested against it without a filesystem.
	failure error
}

// NewMemoryTrustStore returns an empty store.
func NewMemoryTrustStore() *MemoryTrustStore {
	return &MemoryTrustStore{peers: map[string]TrustedPeer{}}
}

// Fail puts the store into the failed state of Req 9.11. Passing nil clears it.
func (s *MemoryTrustStore) Fail(err error) { s.failure = err }

// Load returns every entry, ordered by fingerprint so the listing is stable.
func (s *MemoryTrustStore) Load() ([]TrustedPeer, error) {
	if s.failure != nil {
		return nil, s.failure
	}
	out := make([]TrustedPeer, 0, len(s.peers))
	for _, p := range s.peers {
		out = append(out, p.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out, nil
}

// Put adds or replaces the entry for a fingerprint (Req 9.4). A repeated pairing with a
// fingerprint already stored replaces the entry rather than adding a second one.
func (s *MemoryTrustStore) Put(peer TrustedPeer) error {
	if s.failure != nil {
		return s.failure
	}
	if err := peer.Validate(); err != nil {
		return err
	}
	s.peers[peer.Fingerprint] = peer.Clone()
	return nil
}

// Remove deletes an entry and reports whether it existed (Req 9.8).
func (s *MemoryTrustStore) Remove(fingerprint string) (bool, error) {
	if s.failure != nil {
		return false, s.failure
	}
	if _, found := s.peers[fingerprint]; !found {
		return false, nil
	}
	delete(s.peers, fingerprint)
	return true, nil
}

// Len is the number of entries held.
func (s *MemoryTrustStore) Len() int { return len(s.peers) }
