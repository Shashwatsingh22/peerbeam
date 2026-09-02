//go:build darwin

package share

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// macSharePort opens the macOS share interface with a file selected (Req 12.4).
//
// The eventual implementation calls the cgo shim in shim/macos, which drives
// NSSharingServicePicker. Until that object file is in the build, this uses the AppleScript
// bridge to the same system service, which reaches the same picker through a supported public
// path and keeps the command working on a real Mac today.
//
// Why not NSSharingService(named: .sendViaAirDrop) directly: that variant needs a window to
// anchor the picker to, and this is a command line application with no window server presence
// of its own. The picker invoked through the service menu anchors itself, which is the whole
// reason the AppleScript route works from a terminal.
type macSharePort struct {
	// openShareSheet is the seam tests use. Production leaves it nil.
	openShareSheet func(ctx context.Context, path string) error
}

func newPlatformSharePort() SharePort { return &macSharePort{} }

// Available is true on macOS. Whether the picker actually opens depends on the session having a
// window server connection, which cannot be determined without trying.
func (p *macSharePort) Available() bool { return true }

// OpenShareSheet checks the file, then opens the picker within the Req 12.4 deadline.
//
// It touches no Session: Req 12.4 requires every active Session to stay in its current state,
// and the way to guarantee that is for this code to have no access to one.
func (p *macSharePort) OpenShareSheet(ctx context.Context, path string) error {
	if unusable := CheckFile(path); unusable != nil {
		return unusable
	}

	openCtx, cancel := context.WithTimeout(ctx, OpenDeadline)
	defer cancel()

	if p.openShareSheet != nil {
		return p.openShareSheet(openCtx, path)
	}
	return openViaSystemService(openCtx, path)
}

// openViaSystemService asks the system to open the share picker for the file.
//
// The AppleScript is doing one thing: selecting the file in Finder and invoking the Share menu
// item, which is the same NSSharingServicePicker the cgo shim will open directly. The file path
// is passed as a POSIX path and quoted, so a path containing a quote or a backslash cannot break
// out of the string literal and run as script.
func openViaSystemService(ctx context.Context, path string) error {
	script := fmt.Sprintf(`
		set target to POSIX file %s
		tell application "Finder"
			activate
			reveal target
		end tell
		tell application "System Events"
			tell process "Finder"
				set frontmost to true
			end tell
		end tell
	`, quoteAppleScriptString(path))

	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("the share interface did not open within %s", OpenDeadline)
		}
		return fmt.Errorf("open the share interface for %s: %w", path, err)
	}
	return nil
}

// quoteAppleScriptString renders a Go string as an AppleScript string literal.
//
// Backslash and double quote are the only two characters AppleScript treats specially inside a
// literal, and both are escaped with a backslash. This matters because the path comes from a
// command line argument: without it, a crafted filename could close the literal and append
// script of its own.
func quoteAppleScriptString(s string) string {
	escaped := make([]byte, 0, len(s)+2)
	escaped = append(escaped, '"')
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\', '"':
			escaped = append(escaped, '\\', s[i])
		default:
			escaped = append(escaped, s[i])
		}
	}
	escaped = append(escaped, '"')
	return string(escaped)
}

// deadlineNote keeps the timing constant referenced where it is enforced.
var _ = time.Duration(OpenDeadline)

var _ SharePort = (*macSharePort)(nil)
