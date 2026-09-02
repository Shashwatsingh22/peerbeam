package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/peerbeam/peerbeam/internal/core/trust"
)

// File and directory names under the peerbeam home.
const (
	// DefaultDirName is the directory under the user's home that holds node state.
	DefaultDirName = ".peerbeam"
	// IdentityFileName holds the long-term Ed25519 private key (Req 9.1).
	IdentityFileName = "identity.key"
	// TrustedFileName holds the trust store (Req 9.10).
	TrustedFileName = "trusted.json"
	// identityPEMType is the PEM block type for the identity file. PEM rather than raw bytes
	// so a human who opens the file sees what it is rather than binary noise, and so a future
	// key type can be distinguished by its block type.
	identityPEMType = "PEERBEAM ED25519 PRIVATE KEY"
)

// KeySetupFailure reports that the identity could not be created or secured (Req 9.2). Step names
// which part failed, because the requirement makes the report name it and because the remediation
// differs: a generation failure means no entropy, a permission failure means the filesystem.
type KeySetupFailure struct {
	Step   string
	Path   string
	Reason string
}

func (f *KeySetupFailure) Error() string {
	return fmt.Sprintf("key setup failed at %s for %s: %s", f.Step, f.Path, f.Reason)
}

// DefaultDir is the directory node state lives in: ~/.peerbeam.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate the user home directory: %w", err)
	}
	return filepath.Join(home, DefaultDirName), nil
}

// FileKeyStore holds the node's long-term identity in a file readable by its owner alone.
//
// It satisfies trust.KeyStore, so internal/core never learns where the key lives or how
// permissions work on this platform.
type FileKeyStore struct {
	dir string
}

// NewFileKeyStore returns a key store rooted at dir. An empty dir uses DefaultDir.
func NewFileKeyStore(dir string) (*FileKeyStore, error) {
	if dir == "" {
		resolved, err := DefaultDir()
		if err != nil {
			return nil, err
		}
		dir = resolved
	}
	return &FileKeyStore{dir: dir}, nil
}

// Dir is the directory this store uses.
func (s *FileKeyStore) Dir() string { return s.dir }

// IdentityPath is the identity key file's path.
func (s *FileKeyStore) IdentityPath() string { return filepath.Join(s.dir, IdentityFileName) }

// LoadOrCreateIdentity generates the key pair on first run and loads it afterwards (Req 9.1).
//
// Every failure comes back as a KeySetupFailure naming the step, because Req 9.2 makes the node
// reject every Session request until this succeeds, and an operator needs to know which of four
// things to fix: the directory, the entropy source, the write, or the permissions.
//
// The permission check runs on the load path too, not only on create. A key that was written
// correctly and later loosened - by a careless chmod, a restore from an archive that dropped
// modes, a copy onto a filesystem with no permission model - is exactly as much a Req 9.2 failure
// as one that never got its permissions, and only checking at creation would miss all three.
func (s *FileKeyStore) LoadOrCreateIdentity() (trust.IdentityKeyPair, error) {
	if err := s.ensureDir(); err != nil {
		return trust.IdentityKeyPair{}, err
	}

	path := s.IdentityPath()
	existing, err := os.ReadFile(path)
	switch {
	case err == nil:
		if permErr := checkOwnerOnly(path); permErr != nil {
			return trust.IdentityKeyPair{}, &KeySetupFailure{
				Step:   "verify private key permissions",
				Path:   path,
				Reason: permErr.Error(),
			}
		}
		pair, decodeErr := decodeIdentity(existing)
		if decodeErr != nil {
			return trust.IdentityKeyPair{}, &KeySetupFailure{
				Step:   "read the private key",
				Path:   path,
				Reason: decodeErr.Error(),
			}
		}
		return pair, nil

	case errors.Is(err, os.ErrNotExist):
		// First run.

	default:
		return trust.IdentityKeyPair{}, &KeySetupFailure{
			Step:   "read the private key",
			Path:   path,
			Reason: err.Error(),
		}
	}

	return s.create(path)
}

// create generates and stores a new identity.
func (s *FileKeyStore) create(path string) (trust.IdentityKeyPair, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return trust.IdentityKeyPair{}, &KeySetupFailure{
			Step:   "generate the long-term key pair",
			Path:   path,
			Reason: err.Error(),
		}
	}

	// O_EXCL so a key created between the read above and this write is not clobbered. Two
	// nodes racing on first run would otherwise each write a key and one would silently lose
	// its identity, taking its trust store entries with it.
	//
	// The mode is passed at creation rather than chmod'ed afterwards, so the file is never
	// briefly world-readable. secureFile then makes it certain, since the mode is masked by
	// umask and a permissive umask would leave it wide open.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, OwnerOnlyFileMode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			// Another process won the race. Its key is the node's identity, so read that
			// rather than overwrite it.
			return s.LoadOrCreateIdentity()
		}
		return trust.IdentityKeyPair{}, &KeySetupFailure{
			Step:   "create the private key file",
			Path:   path,
			Reason: err.Error(),
		}
	}

	encoded := pem.EncodeToMemory(&pem.Block{Type: identityPEMType, Bytes: private})
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		_ = os.Remove(path) // a half-written key is worse than none
		return trust.IdentityKeyPair{}, &KeySetupFailure{
			Step:   "write the private key",
			Path:   path,
			Reason: err.Error(),
		}
	}
	// Sync before reporting success: a key the node thinks it stored but that never reached
	// disk would come back as a different identity after a power loss, and every paired peer
	// would report a key mismatch.
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return trust.IdentityKeyPair{}, &KeySetupFailure{
			Step:   "flush the private key to disk",
			Path:   path,
			Reason: err.Error(),
		}
	}
	if err := file.Close(); err != nil {
		return trust.IdentityKeyPair{}, &KeySetupFailure{
			Step:   "close the private key file",
			Path:   path,
			Reason: err.Error(),
		}
	}

	if err := secureFile(path); err != nil {
		// Req 9.2: the key exists but is not protected, so this is a failure and the node
		// rejects Sessions until it is fixed. The file is left in place rather than deleted:
		// deleting it would change the node's identity and invalidate every peer's trust
		// store entry to fix a permission problem.
		return trust.IdentityKeyPair{}, &KeySetupFailure{
			Step:   "set private key permissions",
			Path:   path,
			Reason: err.Error(),
		}
	}

	return trust.IdentityKeyPair{PublicKey: public, PrivateKey: private}, nil
}

// ensureDir creates the state directory with owner-only access.
func (s *FileKeyStore) ensureDir() error {
	if err := os.MkdirAll(s.dir, OwnerOnlyDirMode); err != nil {
		return &KeySetupFailure{
			Step:   "create the state directory",
			Path:   s.dir,
			Reason: err.Error(),
		}
	}
	if err := secureDir(s.dir); err != nil {
		return &KeySetupFailure{
			Step:   "set state directory permissions",
			Path:   s.dir,
			Reason: err.Error(),
		}
	}
	return nil
}

// decodeIdentity parses a stored identity file.
func decodeIdentity(encoded []byte) (trust.IdentityKeyPair, error) {
	block, _ := pem.Decode(encoded)
	if block == nil {
		return trust.IdentityKeyPair{}, errors.New("the file is not a PEM block")
	}
	if block.Type != identityPEMType {
		return trust.IdentityKeyPair{}, fmt.Errorf("the PEM block is %q, want %q",
			block.Type, identityPEMType)
	}
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return trust.IdentityKeyPair{}, fmt.Errorf("the private key is %d bytes, want %d",
			len(block.Bytes), ed25519.PrivateKeySize)
	}

	private := ed25519.PrivateKey(block.Bytes)
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return trust.IdentityKeyPair{}, errors.New("the stored key is not an Ed25519 private key")
	}
	return trust.IdentityKeyPair{PublicKey: public, PrivateKey: private}, nil
}

var _ trust.KeyStore = (*FileKeyStore)(nil)
