package clip

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"unicode/utf8"
)

// ClipboardPort is the clipboard surface. Two methods, because Req 6.1 and Req 6.2 are the only
// things the node does with a clipboard: read the text on it, and replace the text on it.
type ClipboardPort interface {
	// ReadText returns the plain text currently on the clipboard, or ("", false) when it
	// holds no text. The false case covers both an empty clipboard and one holding an image
	// or a file, which Req 6.7 treats identically: there is nothing sendable.
	ReadText(ctx context.Context) (string, bool, error)
	// WriteText replaces the entire clipboard text content (Req 6.2, 6.4).
	WriteText(ctx context.Context, text string) error
}

// ErrClipboardUnsupported is returned when this host has no clipboard tool. It is a sentinel so
// internal/app can report clipboard commands as unsupported without treating the condition as a
// node failure: a machine with no clipboard tool still discovers peers, pairs, sends text, and
// transfers files.
var ErrClipboardUnsupported = errors.New("no clipboard tool is available on this host")

// tool is one clipboard implementation: a command to read with and a command to write with.
type tool struct {
	name      string
	readName  string
	readArgs  []string
	writeName string
	writeArgs []string
}

// available reports whether both halves of the tool are on PATH. Both are required: a host that
// could read but not write would apply nothing and report success, which is worse than
// reporting unsupported.
func (t tool) available() bool {
	if _, err := exec.LookPath(t.readName); err != nil {
		return false
	}
	_, err := exec.LookPath(t.writeName)
	return err == nil
}

// toolsFor returns the candidate tools for an operating system, in preference order.
//
// Linux lists Wayland first and X11 second. wl-paste works under Wayland and fails under a
// plain X session, xclip the reverse, and a machine can have both installed while only one
// session type is running - so the choice cannot be made by LookPath alone. Read falls through
// on failure, which is why the order matters.
func toolsFor(goos string) []tool {
	switch goos {
	case "darwin":
		return []tool{{
			name:      "pbpaste/pbcopy",
			readName:  "pbpaste",
			writeName: "pbcopy",
		}}

	case "windows":
		// Get-Clipboard is a PowerShell cmdlet rather than an executable, so it is invoked
		// through powershell.exe. clip.exe is a real executable and takes its input on
		// stdin.
		return []tool{{
			name:      "Get-Clipboard/clip.exe",
			readName:  "powershell.exe",
			readArgs:  []string{"-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard"},
			writeName: "clip.exe",
		}}

	case "linux":
		return []tool{
			{
				name:      "wl-paste/wl-copy",
				readName:  "wl-paste",
				readArgs:  []string{"--no-newline", "--type", "text/plain"},
				writeName: "wl-copy",
				writeArgs: []string{"--type", "text/plain"},
			},
			{
				name:      "xclip",
				readName:  "xclip",
				readArgs:  []string{"-selection", "clipboard", "-out"},
				writeName: "xclip",
				writeArgs: []string{"-selection", "clipboard", "-in"},
			},
		}

	default:
		return nil
	}
}

// CommandClipboardPort is a ClipboardPort that shells out to the tool the operating system
// already ships.
//
// There is no portable clipboard in the Go standard library, and pulling in a cgo clipboard
// library would put native code on the critical path of a feature that works fine through a
// subprocess. The cost is a process launch per operation, which against Req 6.2's one-second
// budget is not close to a problem.
type CommandClipboardPort struct {
	tools []tool
	// run is the seam tests use, so the whole selection and fallback logic is exercised
	// without a real clipboard. Production leaves it nil.
	run func(ctx context.Context, name string, args []string, stdin []byte) (stdout []byte, err error)
}

// NewCommandClipboardPort returns a port for the host operating system.
func NewCommandClipboardPort() *CommandClipboardPort {
	return &CommandClipboardPort{tools: toolsFor(runtime.GOOS)}
}

// newCommandClipboardPortFor builds a port for a named operating system, for tests.
func newCommandClipboardPortFor(goos string) *CommandClipboardPort {
	return &CommandClipboardPort{tools: toolsFor(goos)}
}

// Available reports whether any clipboard tool is present.
func (p *CommandClipboardPort) Available() bool { return p.selected() != nil }

// ToolName names the tool that will be used, or "" when none is available. It is reported at
// startup so an operator can see which of several candidates was chosen.
func (p *CommandClipboardPort) ToolName() string {
	if selected := p.selected(); selected != nil {
		return selected.name
	}
	return ""
}

// selected is the first available tool in preference order.
func (p *CommandClipboardPort) selected() *tool {
	for i := range p.tools {
		if p.run != nil {
			// Under test, availability is the injected runner's business.
			return &p.tools[i]
		}
		if p.tools[i].available() {
			return &p.tools[i]
		}
	}
	return nil
}

// ReadText returns the clipboard's text content.
//
// It tries each available tool in order and returns the first success, because LookPath cannot
// tell a Wayland session from an X one: wl-paste may be installed and still fail because the
// compositor is not running. An empty result is reported as ("", false) rather than as an
// error, since Req 6.7 treats an empty clipboard as a normal condition with its own message.
func (p *CommandClipboardPort) ReadText(ctx context.Context) (string, bool, error) {
	if len(p.tools) == 0 {
		return "", false, ErrClipboardUnsupported
	}

	var lastErr error
	tried := 0
	for i := range p.tools {
		candidate := p.tools[i]
		if p.run == nil && !candidate.available() {
			continue
		}
		tried++

		stdout, err := p.exec(ctx, candidate.readName, candidate.readArgs, nil)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", candidate.name, err)
			continue
		}

		text := normaliseRead(stdout)
		if text == "" {
			return "", false, nil
		}
		// Non-text content read as bytes is not necessarily valid UTF-8. Req 6.1 scopes a
		// send to UTF-8 text, so this reports "no text" rather than handing invalid bytes
		// up to be rejected later with a less useful message.
		if !utf8.ValidString(text) {
			return "", false, nil
		}
		return text, true, nil
	}

	if tried == 0 {
		return "", false, ErrClipboardUnsupported
	}
	return "", false, lastErr
}

// WriteText replaces the entire clipboard content (Req 6.2).
//
// "Entire" is what the tools do natively: pbcopy, clip.exe, wl-copy, and xclip all replace
// rather than append, so there is nothing to clear first.
func (p *CommandClipboardPort) WriteText(ctx context.Context, text string) error {
	if len(p.tools) == 0 {
		return ErrClipboardUnsupported
	}

	var lastErr error
	tried := 0
	for i := range p.tools {
		candidate := p.tools[i]
		if p.run == nil && !candidate.available() {
			continue
		}
		tried++

		if _, err := p.exec(ctx, candidate.writeName, candidate.writeArgs, []byte(text)); err != nil {
			lastErr = fmt.Errorf("%s: %w", candidate.name, err)
			continue
		}
		return nil
	}

	if tried == 0 {
		return ErrClipboardUnsupported
	}
	return lastErr
}

// exec runs one command, feeding it stdin and returning its stdout.
func (p *CommandClipboardPort) exec(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	if p.run != nil {
		return p.run(ctx, name, args, stdin)
	}

	cmd := exec.CommandContext(ctx, name, args...)
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return nil, fmt.Errorf("%s: %w: %s", name, err, message)
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return stdout.Bytes(), nil
}

// normaliseRead trims the line ending the tools add.
//
// Get-Clipboard appends CRLF and pbpaste appends nothing, so a round trip through Windows
// would otherwise grow a newline on every hop. Only one trailing line ending is removed: text
// the user deliberately ended with a blank line keeps the rest of it.
func normaliseRead(stdout []byte) string {
	text := string(stdout)
	text = strings.TrimSuffix(text, "\r\n")
	text = strings.TrimSuffix(text, "\n")
	return text
}

// MemoryClipboardPort is an in-process clipboard, used by the end-to-end tests and by any host
// where no tool is present but the node should still run.
//
// It is not a stub that silently discards: it behaves like a clipboard, so a test can assert
// that content was applied (Req 6.2) and that a rejected message left it unchanged (Req 6.10).
type MemoryClipboardPort struct {
	text    string
	hasText bool
	// failure, when set, makes both operations fail, for exercising the unsupported path.
	failure error
	writes  int
	reads   int
}

// NewMemoryClipboardPort returns an empty clipboard.
func NewMemoryClipboardPort() *MemoryClipboardPort { return &MemoryClipboardPort{} }

// Fail makes both operations return err. Passing nil clears it.
func (p *MemoryClipboardPort) Fail(err error) { p.failure = err }

// Set puts text on the clipboard without counting a write, for arranging a test.
func (p *MemoryClipboardPort) Set(text string) {
	p.text, p.hasText = text, text != ""
}

// Clear empties the clipboard.
func (p *MemoryClipboardPort) Clear() { p.text, p.hasText = "", false }

// Writes and Reads are the operation counts, so a test can assert that a rejected inbound
// message wrote nothing.
func (p *MemoryClipboardPort) Writes() int { return p.writes }
func (p *MemoryClipboardPort) Reads() int  { return p.reads }

func (p *MemoryClipboardPort) ReadText(context.Context) (string, bool, error) {
	p.reads++
	if p.failure != nil {
		return "", false, p.failure
	}
	return p.text, p.hasText, nil
}

func (p *MemoryClipboardPort) WriteText(_ context.Context, text string) error {
	if p.failure != nil {
		return p.failure
	}
	p.writes++
	p.text, p.hasText = text, true
	return nil
}

var _ ClipboardPort = (*CommandClipboardPort)(nil)
var _ ClipboardPort = (*MemoryClipboardPort)(nil)
