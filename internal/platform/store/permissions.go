//go:build !windows

package store

import (
	"fmt"
	"os"
)

// OwnerOnlyFileMode is the permission a private key file must carry: read and write for the
// owner, nothing for anyone else (Req 9.1).
const OwnerOnlyFileMode os.FileMode = 0o600

// OwnerOnlyDirMode is the same idea for the directory holding it. Without the execute bit an
// owner cannot traverse into their own directory, so 0o700 rather than 0o600.
const OwnerOnlyDirMode os.FileMode = 0o700

// secureFile restricts a file to the local user account and verifies the result (Req 9.1, 9.2).
//
// On POSIX this is a chmod, but the verification afterwards is the part that matters. A chmod can
// silently do nothing useful: on a filesystem mounted with a fixed mode, or a FAT volume with no
// permission model at all, the call succeeds and the bits stay wide open. Req 9.2 requires the
// node to reject every Session until the key is stored with owner-only access, which means
// believing the syscall is not enough - the mode has to be read back.
func secureFile(path string) error {
	if err := os.Chmod(path, OwnerOnlyFileMode); err != nil {
		return fmt.Errorf("set owner-only permissions on %s: %w", path, err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("verify permissions on %s: %w", path, err)
	}
	if got := info.Mode().Perm(); got != OwnerOnlyFileMode {
		return fmt.Errorf(
			"permissions on %s are %#o after chmod, want %#o; the filesystem may not support permissions",
			path, got, OwnerOnlyFileMode)
	}
	return nil
}

// secureDir restricts a directory to the local user account.
func secureDir(path string) error {
	if err := os.Chmod(path, OwnerOnlyDirMode); err != nil {
		return fmt.Errorf("set owner-only permissions on %s: %w", path, err)
	}
	return nil
}

// checkOwnerOnly reports whether a file's permissions grant access to anyone but the owner. It is
// what an existing key file is checked against on startup: a key that was created correctly and
// later loosened is as much a Req 9.2 failure as one that never got its permissions.
func checkOwnerOnly(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("check permissions on %s: %w", path, err)
	}
	if got := info.Mode().Perm(); got&0o077 != 0 {
		return fmt.Errorf("permissions on %s are %#o, which grants access beyond the owner", path, got)
	}
	return nil
}
