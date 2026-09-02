package clip

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// TestClipboardRoundTripsAgainstTheRealTool covers task 18.4: each adapter round-trips text
// against the command line tool its operating system ships.
//
// It skips when no tool is present, which is the honest outcome: on a headless CI host there is
// no clipboard to round-trip against, and asserting one exists would fail for a reason that has
// nothing to do with this code. The skip message says which tool was missing so a local failure
// is actionable.
//
// Requirements: 6.1, 6.2
func TestClipboardRoundTripsAgainstTheRealTool(t *testing.T) {
	port := NewCommandClipboardPort()
	if !port.Available() {
		t.Skipf("no clipboard tool on this %s host; candidates were %v",
			runtime.GOOS, toolNames(toolsFor(runtime.GOOS)))
	}
	t.Logf("using %s", port.ToolName())

	ctx := context.Background()

	// Preserve whatever the user had on their clipboard. A test that clobbered it would be a
	// bad neighbour on a developer machine.
	original, hadOriginal, err := port.ReadText(ctx)
	if err != nil {
		t.Skipf("cannot read this host's clipboard: %v", err)
	}
	t.Cleanup(func() {
		if hadOriginal {
			_ = port.WriteText(ctx, original)
			return
		}
		_ = port.WriteText(ctx, "")
	})

	// Multi-byte content, because the tools pipe bytes and a locale mishandling would show up
	// here rather than on ASCII.
	want := "peerbeam round trip ✅ 日本語 — done"
	if err := port.WriteText(ctx, want); err != nil {
		t.Fatalf("writing to the clipboard: %v", err)
	}

	got, hasText, err := port.ReadText(ctx)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if !hasText {
		t.Fatal("clipboard reports no text after a write")
	}
	if got != want {
		t.Fatalf("read back %q, want %q", got, want)
	}

	// A second write replaces rather than appends (Req 6.2's "entire clipboard content").
	if err := port.WriteText(ctx, "second"); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, _, err = port.ReadText(ctx)
	if err != nil {
		t.Fatalf("reading after the second write: %v", err)
	}
	if got != "second" {
		t.Fatalf("after replacing, clipboard holds %q, want %q", got, "second")
	}
}

func toolNames(tools []tool) []string {
	out := make([]string, 0, len(tools))
	for _, candidate := range tools {
		out = append(out, candidate.name)
	}
	return out
}

// TestToolSelectionPerOperatingSystem pins which tool each platform reaches for, so a rename or
// a reordering is a deliberate change.
//
// Requirements: 6.1, 6.2
func TestToolSelectionPerOperatingSystem(t *testing.T) {
	cases := map[string][]string{
		"darwin":  {"pbpaste", "pbcopy"},
		"windows": {"powershell.exe", "clip.exe"},
		"linux":   {"wl-paste", "wl-copy", "xclip"},
	}
	for goos, wantCommands := range cases {
		t.Run(goos, func(t *testing.T) {
			tools := toolsFor(goos)
			if len(tools) == 0 {
				t.Fatalf("no tools defined for %s", goos)
			}
			joined := strings.Join(append(toolNames(tools), commandsOf(tools)...), " ")
			for _, want := range wantCommands {
				if !strings.Contains(joined, want) {
					t.Fatalf("%s tools %q do not mention %q", goos, joined, want)
				}
			}
		})
	}

	// Linux tries Wayland before X11. LookPath cannot tell which session is running, so the
	// order is what decides, and reversing it would break Wayland hosts that also have xclip
	// installed.
	linux := toolsFor("linux")
	if len(linux) < 2 {
		t.Fatalf("linux has %d tools, want a Wayland tool and an X11 fallback", len(linux))
	}
	if linux[0].readName != "wl-paste" {
		t.Fatalf("linux tries %q first, want wl-paste", linux[0].readName)
	}
	if linux[1].readName != "xclip" {
		t.Fatalf("linux falls back to %q, want xclip", linux[1].readName)
	}

	// An unknown platform has no tools, so clipboard commands report unsupported rather than
	// failing the node.
	if got := toolsFor("plan9"); len(got) != 0 {
		t.Fatalf("plan9 has %d tools, want none", len(got))
	}
}

func commandsOf(tools []tool) []string {
	out := make([]string, 0, len(tools)*2)
	for _, candidate := range tools {
		out = append(out, candidate.readName, candidate.writeName)
	}
	return out
}

// TestClipboardReportsUnsupportedRatherThanFailing covers the case Req 6.7 and the design both
// call for: a host with no clipboard tool still runs, and clipboard commands say so.
//
// Requirements: 6.1, 6.7
func TestClipboardReportsUnsupportedRatherThanFailing(t *testing.T) {
	port := newCommandClipboardPortFor("plan9")

	if port.Available() {
		t.Fatal("a platform with no tools reports itself available")
	}
	if port.ToolName() != "" {
		t.Fatalf("a platform with no tools names %q", port.ToolName())
	}

	_, _, err := port.ReadText(context.Background())
	if !errors.Is(err, ErrClipboardUnsupported) {
		t.Fatalf("ReadText returned %v, want ErrClipboardUnsupported", err)
	}
	if err := port.WriteText(context.Background(), "x"); !errors.Is(err, ErrClipboardUnsupported) {
		t.Fatalf("WriteText returned %v, want ErrClipboardUnsupported", err)
	}
}

// TestClipboardFallsThroughToTheNextTool checks the Linux case that LookPath cannot decide: a
// Wayland tool that is installed but fails because the compositor is not running must not stop
// the X11 fallback from being tried.
//
// Requirements: 6.1, 6.2
func TestClipboardFallsThroughToTheNextTool(t *testing.T) {
	var attempted []string
	port := newCommandClipboardPortFor("linux")
	port.run = func(_ context.Context, name string, _ []string, stdin []byte) ([]byte, error) {
		attempted = append(attempted, name)
		if strings.HasPrefix(name, "wl-") {
			return nil, errors.New("cannot connect to a Wayland display")
		}
		if len(stdin) > 0 {
			return nil, nil // a write
		}
		return []byte("from xclip\n"), nil
	}

	got, hasText, err := port.ReadText(context.Background())
	if err != nil {
		t.Fatalf("ReadText: %v", err)
	}
	if !hasText || got != "from xclip" {
		t.Fatalf("read (%q, %v), want (\"from xclip\", true)", got, hasText)
	}
	if len(attempted) != 2 || attempted[0] != "wl-paste" || attempted[1] != "xclip" {
		t.Fatalf("attempted %v, want wl-paste then xclip", attempted)
	}

	attempted = nil
	if err := port.WriteText(context.Background(), "text"); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if len(attempted) != 2 || attempted[1] != "xclip" {
		t.Fatalf("write attempted %v, want the fallback to be used", attempted)
	}
}

// TestClipboardReportsTheLastErrorWhenEveryToolFails checks that a host where every tool is
// present but broken gets the tool's own error rather than a bare "unsupported", which would
// send the user installing something they already have.
//
// Requirements: 6.1
func TestClipboardReportsTheLastErrorWhenEveryToolFails(t *testing.T) {
	port := newCommandClipboardPortFor("linux")
	port.run = func(_ context.Context, name string, _ []string, _ []byte) ([]byte, error) {
		return nil, errors.New(name + " exploded")
	}

	_, _, err := port.ReadText(context.Background())
	if err == nil {
		t.Fatal("every tool failed but ReadText succeeded")
	}
	if errors.Is(err, ErrClipboardUnsupported) {
		t.Fatalf("reported unsupported when tools were present but broken: %v", err)
	}
	if !strings.Contains(err.Error(), "xclip exploded") {
		t.Fatalf("error %q does not carry the last tool's reason", err)
	}
}

// TestEmptyClipboardIsNotAnError pins Req 6.7's shape: an empty clipboard is a normal condition
// reported as (", false), not an error the caller has to interpret.
//
// Requirements: 6.7
func TestEmptyClipboardIsNotAnError(t *testing.T) {
	port := newCommandClipboardPortFor("darwin")
	port.run = func(context.Context, string, []string, []byte) ([]byte, error) {
		return nil, nil
	}

	got, hasText, err := port.ReadText(context.Background())
	if err != nil {
		t.Fatalf("an empty clipboard returned an error: %v", err)
	}
	if hasText || got != "" {
		t.Fatalf("read (%q, %v), want (\"\", false)", got, hasText)
	}

	// Non-UTF-8 bytes are reported the same way: not text, so nothing sendable.
	port.run = func(context.Context, string, []string, []byte) ([]byte, error) {
		return []byte{0xff, 0xfe, 0x00}, nil
	}
	got, hasText, err = port.ReadText(context.Background())
	if err != nil {
		t.Fatalf("non-text content returned an error: %v", err)
	}
	if hasText {
		t.Fatalf("non-UTF-8 content was reported as text: %q", got)
	}
}

// TestNormaliseReadTrimsOneTrailingNewline is why normaliseRead exists: Get-Clipboard appends
// CRLF and pbpaste appends nothing, so without trimming, a round trip through Windows would grow
// a newline on every hop.
//
// Requirements: 6.1, 6.2
func TestNormaliseReadTrimsOneTrailingNewline(t *testing.T) {
	cases := map[string]string{
		"text":          "text",
		"text\n":        "text",
		"text\r\n":      "text",
		"text\n\n":      "text\n",
		"line\nline2\n": "line\nline2",
		"":              "",
		"\n":            "",
	}
	for input, want := range cases {
		if got := normaliseRead([]byte(input)); got != want {
			t.Fatalf("normaliseRead(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestMemoryClipboardPortBehavesLikeAClipboard checks the in-process port used by the end-to-end
// tests: it applies content, replaces it, and counts writes so a test can assert that a rejected
// message wrote nothing.
//
// Requirements: 6.2, 6.10
func TestMemoryClipboardPortBehavesLikeAClipboard(t *testing.T) {
	ctx := context.Background()
	port := NewMemoryClipboardPort()

	if _, hasText, _ := port.ReadText(ctx); hasText {
		t.Fatal("a fresh clipboard reports text")
	}
	if err := port.WriteText(ctx, "first"); err != nil {
		t.Fatalf("writing: %v", err)
	}
	got, hasText, _ := port.ReadText(ctx)
	if !hasText || got != "first" {
		t.Fatalf("read (%q, %v), want (\"first\", true)", got, hasText)
	}

	// Replacing, not appending.
	_ = port.WriteText(ctx, "second")
	got, _, _ = port.ReadText(ctx)
	if got != "second" {
		t.Fatalf("clipboard holds %q, want %q", got, "second")
	}
	if port.Writes() != 2 {
		t.Fatalf("counted %d writes, want 2", port.Writes())
	}

	// A failing port leaves the content alone, which is what Req 6.10 needs to be checkable.
	port.Fail(errors.New("clipboard busy"))
	if err := port.WriteText(ctx, "third"); err == nil {
		t.Fatal("a failing port accepted a write")
	}
	port.Fail(nil)
	got, _, _ = port.ReadText(ctx)
	if got != "second" {
		t.Fatalf("a failed write changed the clipboard to %q", got)
	}
	if port.Writes() != 2 {
		t.Fatalf("a failed write counted: %d writes", port.Writes())
	}
}

// TestCommandClipboardPortUsesLookPathForAvailability guards the availability rule: both halves
// of a tool must be present, because a host that could read but not write would apply nothing
// and report success.
//
// Requirements: 6.1, 6.2
func TestCommandClipboardPortUsesLookPathForAvailability(t *testing.T) {
	// A tool naming a command that certainly does not exist is unavailable.
	missing := tool{
		name:      "nonexistent",
		readName:  "peerbeam-no-such-clipboard-reader",
		writeName: "peerbeam-no-such-clipboard-writer",
	}
	if missing.available() {
		t.Fatal("a tool with two missing commands reports itself available")
	}

	// A tool whose read half exists but whose write half does not is still unavailable.
	half := tool{name: "half", readName: pickExistingCommand(t), writeName: "peerbeam-no-such-writer"}
	if half.available() {
		t.Fatal("a tool with only its read half reports itself available")
	}
}

func pickExistingCommand(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"sh", "cmd.exe", "go"} {
		if _, err := exec.LookPath(candidate); err == nil {
			return candidate
		}
	}
	t.Skip("no known command on PATH to build the half-available case with")
	return ""
}
