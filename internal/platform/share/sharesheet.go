package share

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"
)

// OpenDeadline is how long the share interface has to appear (Req 12.4).
const OpenDeadline = 5 * time.Second

// Unavailable reports a share-sheet request on a platform that has none (Req 12.5).
type Unavailable struct {
	OperatingSystem string
}

func (e *Unavailable) Error() string {
	return "AirDrop handoff is available on macOS only, not on " + e.OperatingSystem
}

// FileUnusable reports a request for a file that does not exist or cannot be read (Req 12.9).
// It names both the file and the reason, which is what the requirement asks for.
type FileUnusable struct {
	Path   string
	Reason string
}

func (e *FileUnusable) Error() string {
	return fmt.Sprintf("cannot hand off %s: %s", e.Path, e.Reason)
}

// SharePort opens the operating system's share interface with a file selected.
//
// AirDrop is deliberately not a Transport. No public API lets a third-party application choose
// a recipient or drive a transfer: the only supported entry points are the share sheet, which
// hands the file to Apple's own interface with a human picking the recipient, and there is no
// reliable completion signal either. So this is a one-way handoff and nothing above it treats
// it as a way to move bytes.
type SharePort interface {
	// OpenShareSheet opens the share interface with path selected. It must leave every
	// active Session in its current state (Req 12.4), which is why it takes no Session and
	// returns nothing but an error.
	OpenShareSheet(ctx context.Context, path string) error
	// Available reports whether this platform has a share interface at all.
	Available() bool
}

// CheckFile validates the file before any platform code runs (Req 12.9).
//
// It is separate from the platform-specific open so the rejection path is identical on every
// operating system and testable on all of them. Req 12.9 requires the share interface to be
// left unopened, and running the check first is what guarantees that: there is no path where
// the picker opens and then the file turns out to be unreadable.
func CheckFile(path string) *FileUnusable {
	if path == "" {
		return &FileUnusable{Path: path, Reason: "no file path was given"}
	}

	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return &FileUnusable{Path: path, Reason: "the file does not exist"}
	case errors.Is(err, os.ErrPermission):
		return &FileUnusable{Path: path, Reason: "permission denied"}
	case err != nil:
		return &FileUnusable{Path: path, Reason: err.Error()}
	case info.IsDir():
		return &FileUnusable{Path: path, Reason: "the path is a directory, not a file"}
	}

	// Stat says it exists; opening it is what proves it is readable. A file with no read
	// permission stats fine and then fails in the picker, where the error would be Apple's
	// rather than ours.
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return &FileUnusable{Path: path, Reason: "permission denied"}
		}
		return &FileUnusable{Path: path, Reason: err.Error()}
	}
	_ = file.Close()
	return nil
}

// NewSharePort returns the share port for this platform: the macOS implementation on darwin, and
// one that rejects everything elsewhere (Req 12.5).
func NewSharePort() SharePort { return newPlatformSharePort() }

// unsupportedSharePort rejects every request, naming the operating system (Req 12.5).
type unsupportedSharePort struct {
	operatingSystem string
}

func (p *unsupportedSharePort) Available() bool { return false }

// OpenShareSheet rejects the request without touching the file.
//
// The file is still checked first, and the order is deliberate: a user on Linux who typo'd the
// path should hear about the typo, not only that AirDrop is macOS-only, because the second
// message would send them looking for a Mac to run a command that would have failed there too.
func (p *unsupportedSharePort) OpenShareSheet(_ context.Context, path string) error {
	if unusable := CheckFile(path); unusable != nil {
		return unusable
	}
	return &Unavailable{OperatingSystem: p.operatingSystem}
}

// MemorySharePort records requests instead of opening anything, for tests and for a dry run.
type MemorySharePort struct {
	available bool
	opened    []string
	failure   error
}

// NewMemorySharePort returns a port that reports itself available and records what it was asked
// to open.
func NewMemorySharePort() *MemorySharePort { return &MemorySharePort{available: true} }

// SetAvailable toggles availability.
func (p *MemorySharePort) SetAvailable(available bool) { p.available = available }

// Fail makes OpenShareSheet return err after the file check passes.
func (p *MemorySharePort) Fail(err error) { p.failure = err }

// Opened lists the paths the port was asked to open.
func (p *MemorySharePort) Opened() []string { return append([]string(nil), p.opened...) }

func (p *MemorySharePort) Available() bool { return p.available }

func (p *MemorySharePort) OpenShareSheet(_ context.Context, path string) error {
	if unusable := CheckFile(path); unusable != nil {
		return unusable
	}
	if !p.available {
		return &Unavailable{OperatingSystem: runtime.GOOS}
	}
	if p.failure != nil {
		return p.failure
	}
	p.opened = append(p.opened, path)
	return nil
}

var _ SharePort = (*unsupportedSharePort)(nil)
var _ SharePort = (*MemorySharePort)(nil)
