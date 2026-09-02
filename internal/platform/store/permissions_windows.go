//go:build windows

package store

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// OwnerOnlyFileMode and OwnerOnlyDirMode exist on Windows too, so the rest of the package does
// not need build tags. They are the mode passed to os.OpenFile, which Windows uses only to decide
// read-only versus writable; the real restriction is the ACL applied below.
const (
	OwnerOnlyFileMode os.FileMode = 0o600
	OwnerOnlyDirMode  os.FileMode = 0o700
)

// secureFile restricts a file to the current user account with a Windows ACL (Req 9.1, 9.2).
//
// Unix mode bits are not honoured on Windows: os.Chmod can only toggle the read-only attribute,
// so a chmod(0o600) leaves the file readable by every account on the machine. Req 9.1 asks for
// read and write for the local user and no access to any other account, and the only way to say
// that on Windows is a discretionary ACL.
//
// The ACL is built from scratch rather than edited. A file created in a user profile inherits
// entries from its parent - typically SYSTEM and Administrators - and Req 9.1 admits no other
// account, so inheritance is switched off and a single entry for the owner is installed.
func secureFile(path string) error {
	return applyOwnerOnlyACL(path, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE)
}

// secureDir restricts a directory the same way, adding the traverse right the owner needs to
// reach files inside it.
func secureDir(path string) error {
	return applyOwnerOnlyACL(path, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.GENERIC_EXECUTE|windows.DELETE)
}

// applyOwnerOnlyACL replaces a path's ACL with one entry granting access to its owner alone.
func applyOwnerOnlyACL(path string, access windows.ACCESS_MASK) error {
	// The current user's SID is the account the entry is granted to. Reading it from the
	// process token rather than from the file's owner field is deliberate: a file created in a
	// shared location may be owned by someone else, and granting that account sole access
	// would lock this node out of its own key.
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("read the current user account for %s: %w", path, err)
	}

	entries := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: access,
		AccessMode:        windows.GRANT_ACCESS,
		// No inheritance: this entry applies to the object itself and is not passed down.
		Inheritance: windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
		},
	}}

	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("build an owner-only ACL for %s: %w", path, err)
	}

	// PROTECTED_DACL_SECURITY_INFORMATION is what stops inherited entries from reappearing.
	// Without it, the parent directory's SYSTEM and Administrators entries would be merged
	// back in and the file would not be owner-only.
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	); err != nil {
		return fmt.Errorf("apply an owner-only ACL to %s: %w", path, err)
	}
	return nil
}

// checkOwnerOnly verifies that a path's ACL grants access to no account other than the current
// user (Req 9.2).
//
// An existing key whose ACL was loosened after creation is as much a failure as one that never
// got an ACL, so this runs on every startup rather than only on first run.
func checkOwnerOnly(path string) error {
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read the ACL on %s: %w", path, err)
	}

	acl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read the ACL entries on %s: %w", path, err)
	}
	if acl == nil {
		// A nil DACL means everyone has full access, which is the opposite of what Req 9.1
		// asks for.
		return fmt.Errorf("%s has no access control list, so every account can read it", path)
	}

	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("read the current user account for %s: %w", path, err)
	}

	entries, err := aclEntries(acl)
	if err != nil {
		return fmt.Errorf("enumerate the ACL on %s: %w", path, err)
	}
	for _, sid := range entries {
		if !sid.Equals(user.User.Sid) {
			return fmt.Errorf("%s grants access to %s as well as its owner", path, sid.String())
		}
	}
	return nil
}

// aclEntries lists the SIDs an ACL grants access to.
//
// An ACE is a variable-length structure: the fixed header is followed by the SID inline, so the
// SID is reached by offsetting into the ACE rather than by dereferencing a pointer field. That is
// why this needs unsafe; it is the documented layout of the Win32 structure, not a shortcut.
func aclEntries(acl *windows.ACL) ([]*windows.SID, error) {
	var out []*windows.SID
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return nil, err
		}
		sid := (*windows.SID)(unsafe.Pointer(
			uintptr(unsafe.Pointer(ace)) + unsafe.Offsetof(ace.SidStart)))
		out = append(out, sid)
	}
	return out, nil
}
