package share

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestAirDropIsRejectedOffMacOS covers task 18.5 and Req 12.5: on any platform other than macOS
// the request is refused, the file is untouched, and the message says AirDrop is macOS-only.
//
// The rejecting port is constructed directly rather than through NewSharePort, so the behaviour
// is checked on every host including a Mac. Testing it only where the build tags happen to select
// it would leave the branch unexercised on the developer's own machine.
//
// Requirements: 12.5
func TestAirDropIsRejectedOffMacOS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.bin")
	contents := []byte("untouched")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("writing the test file: %v", err)
	}

	for _, goos := range []string{"linux", "windows", "freebsd"} {
		t.Run(goos, func(t *testing.T) {
			port := &unsupportedSharePort{operatingSystem: goos}

			if port.Available() {
				t.Fatal("a non-macOS port reports itself available")
			}
			err := port.OpenShareSheet(context.Background(), path)
			if err == nil {
				t.Fatal("the request was accepted off macOS")
			}
			if !strings.Contains(err.Error(), "macOS only") {
				t.Fatalf("error %q does not say AirDrop is macOS-only", err)
			}
			if !strings.Contains(err.Error(), goos) {
				t.Fatalf("error %q does not name the operating system", err)
			}

			// Req 12.5: the named file is left unchanged.
			after, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatalf("the file became unreadable: %v", readErr)
			}
			if string(after) != string(contents) {
				t.Fatalf("the file changed to %q", after)
			}
		})
	}
}

// TestAirDropRejectsAnUnusableFile covers Req 12.9: a missing or unreadable file leaves the share
// interface unopened and the error names the file and the reason.
//
// Requirements: 12.9
func TestAirDropRejectsAnUnusableFile(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "no-such-file")
	directory := dir

	unreadable := filepath.Join(dir, "unreadable.bin")
	if err := os.WriteFile(unreadable, []byte("secret"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Skipf("cannot make a file unreadable on this host: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o600) })

	cases := map[string]struct {
		path       string
		wantReason string
	}{
		"missing file":    {missing, "does not exist"},
		"a directory":     {directory, "directory"},
		"empty path":      {"", "no file path"},
		"unreadable file": {unreadable, "permission denied"},
	}

	// The check is platform-independent by design, so it is asserted through both the
	// rejecting port and the in-memory one: whichever port a host selects, an unusable file is
	// refused before any platform code runs.
	ports := map[string]SharePort{
		"unsupported platform": &unsupportedSharePort{operatingSystem: "linux"},
		"available platform":   NewMemorySharePort(),
	}

	for portName, port := range ports {
		for caseName, c := range cases {
			t.Run(portName+"/"+caseName, func(t *testing.T) {
				if c.path == unreadable && os.Geteuid() == 0 {
					t.Skip("running as root, so an unreadable file is still readable")
				}

				err := port.OpenShareSheet(context.Background(), c.path)
				if err == nil {
					t.Fatal("an unusable file was accepted")
				}

				unusable, ok := err.(*FileUnusable)
				if !ok {
					t.Fatalf("error is %T (%v), want *FileUnusable", err, err)
				}
				// Req 12.9: the error names the requested file and the reason.
				if unusable.Path != c.path {
					t.Fatalf("error names %q, want %q", unusable.Path, c.path)
				}
				if !strings.Contains(unusable.Reason, c.wantReason) {
					t.Fatalf("reason %q does not mention %q", unusable.Reason, c.wantReason)
				}
				if !strings.Contains(unusable.Error(), c.path) && c.path != "" {
					t.Fatalf("rendered error %q omits the path", unusable.Error())
				}
			})
		}
	}

	// The share interface stays unopened: the in-memory port records nothing.
	memory := NewMemorySharePort()
	_ = memory.OpenShareSheet(context.Background(), missing)
	if opened := memory.Opened(); len(opened) != 0 {
		t.Fatalf("the share interface was opened for an unusable file: %v", opened)
	}
}

// TestCheckFileAcceptsAReadableFile is the other side of Req 12.9: a file that exists and can be
// read passes.
//
// Requirements: 12.4, 12.9
func TestCheckFileAcceptsAReadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "good.bin")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if got := CheckFile(path); got != nil {
		t.Fatalf("a readable file was rejected: %s", got.Error())
	}

	// And a port that is available opens it, recording the path.
	port := NewMemorySharePort()
	if err := port.OpenShareSheet(context.Background(), path); err != nil {
		t.Fatalf("opening for a readable file: %v", err)
	}
	opened := port.Opened()
	if len(opened) != 1 || opened[0] != path {
		t.Fatalf("port opened %v, want just %q", opened, path)
	}
}

// TestNewSharePortMatchesThisPlatform checks the build-tagged selection: a Mac gets the macOS
// implementation, everything else gets the rejecting one.
//
// Requirements: 12.4, 12.5
func TestNewSharePortMatchesThisPlatform(t *testing.T) {
	port := NewSharePort()

	if runtime.GOOS == "darwin" {
		if !port.Available() {
			t.Fatal("macOS reports no share interface")
		}
		return
	}

	if port.Available() {
		t.Fatalf("%s reports a share interface", runtime.GOOS)
	}
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	err := port.OpenShareSheet(context.Background(), path)
	if err == nil {
		t.Fatal("a non-macOS platform accepted a share request")
	}
	if !strings.Contains(err.Error(), "macOS only") {
		t.Fatalf("error %q does not say AirDrop is macOS-only", err)
	}
}

// TestOpenDeadlineMatchesTheRequirement pins the five-second bound of Req 12.4.
//
// Requirements: 12.4
func TestOpenDeadlineMatchesTheRequirement(t *testing.T) {
	if OpenDeadline != 5*time.Second {
		t.Fatalf("open deadline is %s, want 5s", OpenDeadline)
	}
}

// TestMemorySharePortUnavailableStillChecksTheFileFirst pins the ordering choice: a user who
// typo'd the path hears about the typo rather than only that AirDrop is macOS-only, because the
// second message would send them looking for a Mac to run a command that would fail there too.
//
// Requirements: 12.5, 12.9
func TestMemorySharePortUnavailableStillChecksTheFileFirst(t *testing.T) {
	port := NewMemorySharePort()
	port.SetAvailable(false)

	err := port.OpenShareSheet(context.Background(), filepath.Join(t.TempDir(), "typo"))
	if _, ok := err.(*FileUnusable); !ok {
		t.Fatalf("error is %T (%v), want the file problem reported first", err, err)
	}

	// With a real file, the unavailability is what surfaces.
	path := filepath.Join(t.TempDir(), "real.bin")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	err = port.OpenShareSheet(context.Background(), path)
	if _, ok := err.(*Unavailable); !ok {
		t.Fatalf("error is %T (%v), want *Unavailable", err, err)
	}
}
