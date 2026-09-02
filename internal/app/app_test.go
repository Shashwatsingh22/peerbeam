package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/peerbeam/peerbeam/internal/core/clock"
	"github.com/peerbeam/peerbeam/internal/core/codec"
	"github.com/peerbeam/peerbeam/internal/core/crypto"
	"github.com/peerbeam/peerbeam/internal/core/report"
	"github.com/peerbeam/peerbeam/internal/core/session"
	"github.com/peerbeam/peerbeam/internal/core/transport"
	"github.com/peerbeam/peerbeam/internal/core/trust"
	"github.com/peerbeam/peerbeam/internal/platform/bt"
	"github.com/peerbeam/peerbeam/internal/platform/clip"
	"github.com/peerbeam/peerbeam/internal/platform/lan"
	"github.com/peerbeam/peerbeam/internal/platform/share"
)

var baseTime = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func newManualClock() *manualClock { return &manualClock{now: baseTime} }

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

var _ clock.Clock = (*manualClock)(nil)

// newTestNode builds a node on in-process adapters, which is the same wiring production uses with
// different ports.
func newTestNode(t *testing.T) *PeerNode {
	t.Helper()

	sw := lan.NewLoopbackSwitch()
	fabric := bt.NewFabric()

	node, err := NewPeerNode(Config{DisplayName: "test-node"}, Ports{
		Transports: []transport.Transport{
			lan.NewLoopbackLanTransport(sw),
			bt.NewBtTransport(bt.NewInMemoryBluetoothBridge(fabric, "device-local")),
		},
		Clipboard:  clip.NewMemoryClipboardPort(),
		Share:      share.NewMemorySharePort(),
		TrustStore: trust.NewMemoryTrustStore(),
		Events:     report.NewMemoryEventSink(),
		Clock:      newManualClock(),
	})
	if err != nil {
		t.Fatalf("building a node: %v", err)
	}
	return node
}

// TestEveryCapabilityHasACommand covers task 21.4 and Req 12.6: every capability in Requirements 1
// through 11 is reachable as a command line command, with no graphical surface.
//
// The capability table is walked rather than the command list, so adding a capability without a
// command fails here rather than being noticed by a user.
//
// Requirements: 12.6
func TestEveryCapabilityHasACommand(t *testing.T) {
	root := NewRootCommand(func(Config) (*PeerNode, error) { return newTestNode(t), nil })

	for capability, paths := range CapabilityCommands() {
		if len(paths) == 0 {
			t.Fatalf("%s has no command", capability)
		}
		for _, path := range paths {
			t.Run(string(capability)+"/"+path, func(t *testing.T) {
				cmd, _, err := root.Find(strings.Fields(path))
				if err != nil {
					t.Fatalf("%q is not reachable from the root command: %v", path, err)
				}
				// Find falls back to the closest parent, so the resolved name has to be
				// the last word of the path or the command does not actually exist.
				want := strings.Fields(path)
				if cmd.Name() != want[len(want)-1] {
					t.Fatalf("%q resolved to %q, so that subcommand does not exist",
						path, cmd.Name())
				}
				// Req 12.6: a command with no description is not a usable command line
				// surface.
				if strings.TrimSpace(cmd.Short) == "" {
					t.Fatalf("%q has no short description", path)
				}
				if cmd.RunE == nil && !cmd.HasSubCommands() {
					t.Fatalf("%q neither runs nor groups subcommands", path)
				}
			})
		}
	}
}

// TestRootCommandDoesNotTouchTheFilesystemForHelp checks that the node is built lazily. Creating
// ~/.peerbeam or generating a key to print a help message would be a surprising side effect, and it
// would make `--help` fail on a read-only home directory.
//
// Requirements: 12.6
func TestRootCommandDoesNotTouchTheFilesystemForHelp(t *testing.T) {
	built := 0
	root := NewRootCommand(func(Config) (*PeerNode, error) {
		built++
		return newTestNode(t), nil
	})

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--help"})

	if err := root.Execute(); err != nil {
		t.Fatalf("--help failed: %v", err)
	}
	if built != 0 {
		t.Fatalf("--help built %d nodes, want 0", built)
	}
	if !strings.Contains(out.String(), "Available Commands") {
		t.Fatalf("--help did not print the command list:\n%s", out.String())
	}
}

// TestGlobalFlagsReachTheNodeConfig checks that the root flags are actually plumbed, since a flag
// that parses but is discarded is worse than no flag.
//
// Requirements: 12.6
func TestGlobalFlagsReachTheNodeConfig(t *testing.T) {
	var got Config
	root := NewRootCommand(func(config Config) (*PeerNode, error) {
		got = config
		return newTestNode(t), nil
	})

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--name", "my-laptop", "--state-dir", "/tmp/peerbeam-test", "--port", "45999", "peers"})

	if err := root.Execute(); err != nil {
		t.Fatalf("peers failed: %v", err)
	}
	if got.DisplayName != "my-laptop" {
		t.Fatalf("display name reached the node as %q", got.DisplayName)
	}
	if got.StateDir != "/tmp/peerbeam-test" {
		t.Fatalf("state dir reached the node as %q", got.StateDir)
	}
	if got.ListenPort != 45999 {
		t.Fatalf("listen port reached the node as %d", got.ListenPort)
	}
}

// TestWriterPrefersControlOverBulk covers task 21.4 and Req 4.6: with the bulk channel saturated, a
// control Message is written next.
//
// This is the one place where Go's select semantics had to be worked around rather than used. A
// plain three-way select chooses uniformly among ready cases, so a saturated bulk channel would win
// half the time and a text message would wait behind a transfer's chunks. The writer therefore polls
// Control with a non-blocking select first, and this test is what proves the ordering rather than
// assuming it.
//
// Requirements: 4.6
func TestWriterPrefersControlOverBulk(t *testing.T) {
	node := newTestNode(t)

	// A session with real crypto, so the writer exercises the production seal path.
	s, b, recorder := newWiredSession(t, node)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Saturate the bulk channel, the way a running transfer does.
	bulkCount := cap(s.Outbound)
	for i := 0; i < bulkCount; i++ {
		s.Outbound <- session.Message{
			Type:     uint8(codec.MsgChunk),
			Sequence: uint64(1000 + i),
			Payload:  []byte("chunk"),
		}
	}
	if len(s.Outbound) != bulkCount {
		t.Fatalf("bulk channel holds %d of %d", len(s.Outbound), bulkCount)
	}

	// One control message, queued after every chunk.
	s.Control <- session.Message{
		Type:     uint8(codec.MsgText),
		Sequence: 1,
		Payload:  []byte("urgent"),
		Control:  true,
	}

	done := make(chan struct{})
	go func() {
		node.writerLoop(ctx, s, b)
		close(done)
	}()

	// The control message must be among the first written, not after all the chunks.
	deadline := time.After(3 * time.Second)
	for {
		if position, found := recorder.positionOf(1); found {
			// It was queued last but must not be written last. Allowing one preceding
			// write covers the case where the loop had already committed to a chunk before
			// the control message arrived.
			if position > 1 {
				t.Fatalf("the control message was written at position %d, behind %d chunks",
					position, position)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatalf("the control message was never written; %d writes happened",
				recorder.count())
		case <-time.After(time.Millisecond):
		}
	}

	cancel()
	<-done

	// Every payload that reached the wire was sealed: no plaintext went out (Req 10.2).
	for _, written := range recorder.frames() {
		if bytes.Contains(written, []byte("urgent")) {
			t.Fatal("a payload reached the wire in plaintext")
		}
	}
}

// newWiredSession builds a Session with a binding whose connection records what was written.
func newWiredSession(t *testing.T, node *PeerNode) (*session.Session, *binding, *writeRecorder) {
	t.Helper()

	key := []byte("long-term-key-for-the-test-peer!!")
	admission := node.Sessions().Admit(session.AdmissionRequest{
		Fingerprint:  strings.Repeat("ab", 32),
		DisplayName:  "peer",
		PresentedKey: key,
		StoredKey:    key,
		Keys:         session.KeyMaterial("session-key-material"),
	})
	if admission.Admitted == nil {
		t.Fatalf("admitting a session: %s", admission.Reason())
	}
	s := node.Sessions().Get(*admission.Admitted)
	s.Rebind(transport.NameLAN)

	sessionKeys := crypto.SessionKeys{
		SendKey:    bytes.Repeat([]byte{1}, crypto.SessionKeyBytes),
		ReceiveKey: bytes.Repeat([]byte{2}, crypto.SessionKeyBytes),
	}
	sessionCrypto, err := crypto.NewSessionCrypto(sessionKeys, crypto.RoleInitiator)
	if err != nil {
		t.Fatalf("building session crypto: %v", err)
	}

	recorder := &writeRecorder{}
	b := &binding{
		conn:      recorder,
		transport: node.Transports()[0],
		crypto:    sessionCrypto,
		keepalive: transport.NewKeepaliveTracker(),
		metrics:   transport.NewTransportMetrics(node.clk),
		reader:    codec.NewFrameReader(node.clk),
	}

	node.bindMu.Lock()
	node.bindings[s.Id] = b
	node.bindMu.Unlock()

	return s, b, recorder
}

// writeRecorder is a TransportConnection that records the frames written to it, in order.
type writeRecorder struct {
	mu       sync.Mutex
	written  [][]byte
	sequence []uint64
}

func (w *writeRecorder) TransportName() string { return transport.NameLAN }

func (w *writeRecorder) Write(payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	frame := append([]byte(nil), payload...)
	w.written = append(w.written, frame)
	// The sequence number sits at bytes 2..10 of the header, in the clear: a receiver has to
	// read it to derive the nonce before it can decrypt anything.
	if len(frame) >= codec.HeaderBytes {
		var sequence uint64
		for i := 2; i < 10; i++ {
			sequence = sequence<<8 | uint64(frame[i])
		}
		w.sequence = append(w.sequence, sequence)
	}
	return nil
}

func (w *writeRecorder) Read([]byte) (int, error) { return 0, errors.New("not readable") }
func (w *writeRecorder) Close() error             { return nil }

func (w *writeRecorder) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.written)
}

func (w *writeRecorder) frames() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([][]byte(nil), w.written...)
}

// positionOf returns how many frames were written before the one carrying this sequence number.
func (w *writeRecorder) positionOf(sequence uint64) (int, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, got := range w.sequence {
		if got == sequence {
			return i, true
		}
	}
	return 0, false
}

// TestStartupReportsUnavailableTransports covers Req 12.3 and 12.8 at the wiring level: a host with
// no Bluetooth starts with LAN only and says so, and a host with neither starts and says that.
//
// Requirements: 12.3, 12.8
func TestStartupReportsUnavailableTransports(t *testing.T) {
	sw := lan.NewLoopbackSwitch()

	t.Run("bluetooth unavailable leaves LAN", func(t *testing.T) {
		node, err := NewPeerNode(Config{DisplayName: "node"}, Ports{
			Transports: []transport.Transport{
				lan.NewLoopbackLanTransport(sw),
				bt.NewBtTransport(nil), // no bridge
			},
			Clock: newManualClock(),
		})
		if err != nil {
			t.Fatalf("building: %v", err)
		}

		usable := node.UsableTransports()
		if len(usable) != 1 || usable[0].Name() != transport.NameLAN {
			t.Fatalf("usable transports are %v, want LAN only", namesOf(usable))
		}

		found := false
		for _, failure := range node.StartupReport() {
			if strings.Contains(failure.Reason, transport.NameBT) {
				found = true
				if !failure.Complete() {
					t.Fatalf("the report is incomplete, missing %v", failure.Missing())
				}
			}
		}
		if !found {
			t.Fatalf("startup did not report BT_Transport unavailable: %v", node.StartupReport())
		}
	})

	t.Run("neither transport available", func(t *testing.T) {
		node, err := NewPeerNode(Config{DisplayName: "node"}, Ports{
			Transports: []transport.Transport{bt.NewBtTransport(nil)},
			Clock:      newManualClock(),
		})
		if err != nil {
			t.Fatalf("building: %v", err)
		}
		if len(node.UsableTransports()) != 0 {
			t.Fatalf("usable transports are %v, want none", namesOf(node.UsableTransports()))
		}

		// Req 12.8: the node reports that no transport is available and still started.
		found := false
		for _, failure := range node.StartupReport() {
			if strings.Contains(failure.Reason, "no transport is available") {
				found = true
			}
		}
		if !found {
			t.Fatalf("startup did not report the no-transport case: %v", node.StartupReport())
		}
	})
}

func namesOf(transports []transport.Transport) []string {
	out := make([]string, 0, len(transports))
	for _, t := range transports {
		out = append(out, t.Name())
	}
	return out
}

// TestStatusRendererIsAllOrNothing checks that the rendered table follows Req 13.2: a Session missing
// any of the four values shows a pending row with no partial figures.
//
// Requirements: 13.1, 13.2
func TestStatusRendererIsAllOrNothing(t *testing.T) {
	node := newTestNode(t)
	s, b, _ := newWiredSession(t, node)

	var out bytes.Buffer
	renderer := NewStatusRenderer(node, &out)

	// No metrics sampled yet, so the row is pending and carries no numbers.
	if err := renderer.RenderOnce(); err != nil {
		t.Fatalf("rendering: %v", err)
	}
	rendered := out.String()
	if !strings.Contains(rendered, "pending") {
		t.Fatalf("a session with no metrics is not pending:\n%s", rendered)
	}
	if strings.Contains(rendered, "B/s") || strings.Contains(rendered, " ms") {
		t.Fatalf("a pending row carries measurements:\n%s", rendered)
	}

	// With all four present the row shows every value.
	b.metrics.RecordGoodput(41_943_040)
	b.metrics.RecordRTT(7 * time.Millisecond)

	out.Reset()
	if err := renderer.RenderOnce(); err != nil {
		t.Fatalf("rendering: %v", err)
	}
	rendered = out.String()
	for _, want := range []string{s.DisplayName, transport.NameLAN, "MiB/s", "7 ms"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("the ready row omits %q:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "pending") {
		t.Fatalf("a session with all four values is still pending:\n%s", rendered)
	}
}

// TestFormatRateUsesBinaryUnits pins the unit choice: every bound in the requirements is binary, and
// showing decimal megabytes against a 40 MiB/s target would make a transport that is exactly meeting
// it look like it is missing it.
//
// Requirements: 2.1, 13.1
func TestFormatRateUsesBinaryUnits(t *testing.T) {
	cases := map[int64]string{
		0:                            "0 B/s",
		512:                          "512 B/s",
		1024:                         "1.0 KiB/s",
		transport.BTExpectedGoodput:  "40.0 KiB/s",
		transport.LANExpectedGoodput: "40.0 MiB/s",
	}
	for input, want := range cases {
		if got := formatRate(input); got != want {
			t.Fatalf("formatRate(%d) = %q, want %q", input, got, want)
		}
	}
}

// TestNodeStopJoinsEveryGoroutine checks the single join point. A node that leaked a goroutine per
// session would fail Req 11.7's processor budget after enough connects and disconnects, and the leak
// would be invisible until then.
//
// Requirements: 11.7, 4.3
func TestNodeStopJoinsEveryGoroutine(t *testing.T) {
	node := newTestNode(t)

	if err := node.Start(context.Background()); err != nil {
		t.Fatalf("starting: %v", err)
	}
	// Starting twice is refused rather than doubling the loops.
	if err := node.Start(context.Background()); err == nil {
		t.Fatal("a second Start succeeded")
	}

	stopped := make(chan struct{})
	go func() {
		node.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return within 5s, so a goroutine is not joined")
	}

	// Stop is idempotent, so a signal handler and a deferred Stop cannot deadlock each other.
	node.Stop()
}

// TestClipboardStateIsPerPeerAndSurvivesReconnect checks the keying choice: preferences are keyed by
// fingerprint, so a reconnect does not silently turn auto-apply off again.
//
// Requirements: 6.2, 6.3, 6.5
func TestClipboardStateIsPerPeerAndSurvivesReconnect(t *testing.T) {
	node := newTestNode(t)
	fingerprint := strings.Repeat("cd", 32)

	state := node.ClipboardFor(fingerprint)
	state.SetAutoApply(true)
	state.SetContinuousSync(true)

	// The same fingerprint gets the same state back.
	again := node.ClipboardFor(fingerprint)
	if !again.AutoApply() || !again.ContinuousSync() {
		t.Fatal("clipboard preferences were not retained for the peer")
	}
	if again != state {
		t.Fatal("a second lookup built a new state rather than returning the existing one")
	}

	// A different peer starts with the safe defaults: nothing writes the clipboard and nothing
	// leaves the machine until the user asks.
	other := node.ClipboardFor(strings.Repeat("ef", 32))
	if other.AutoApply() || other.ContinuousSync() {
		t.Fatal("a fresh peer defaults to applying or syncing")
	}
}

// TestNodeRejectsSessionsWhileTheTrustStoreIsFailed covers Req 9.11 at the wiring level.
//
// Requirements: 9.2, 9.11
func TestNodeRejectsSessionsWhileTheTrustStoreIsFailed(t *testing.T) {
	failing := trust.NewMemoryTrustStore()
	failing.Fail(errors.New("integrity tag mismatch"))

	node, err := NewPeerNode(Config{DisplayName: "node"}, Ports{
		Transports: []transport.Transport{lan.NewLoopbackLanTransport(lan.NewLoopbackSwitch())},
		TrustStore: failing,
		Clock:      newManualClock(),
	})
	if err != nil {
		t.Fatalf("building: %v", err)
	}

	if node.Ready() {
		t.Fatal("a node with a failed trust store reports itself ready")
	}
	// The failure is in the startup report, complete and naming the step.
	found := false
	for _, failure := range node.StartupReport() {
		if strings.Contains(failure.Operation, "trust store") {
			found = true
			if !failure.Complete() {
				t.Fatalf("the report is incomplete, missing %v", failure.Missing())
			}
		}
	}
	if !found {
		t.Fatalf("startup did not report the trust store failure: %v", node.StartupReport())
	}

	// And admission is refused with the store failure named rather than as an untrusted peer.
	decision := node.Pairing().Admit(strings.Repeat("ab", 32), []byte("key"))
	if decision.Kind() != trust.AdmitStoreFailed {
		t.Fatalf("admission gave %s, want store failed", decision.Kind())
	}
}

// TestCommandsPrintCompleteFailureReports checks that a command's failure path goes through Describe,
// so the user gets all four fields Req 13.4 asks for rather than a bare error.
//
// Requirements: 13.4
func TestCommandsPrintCompleteFailureReports(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"empty text", []string{"send", "abc", "--text", ""}, "accepted range"},
		{"bad port", []string{"peers", "add", "192.0.2.1", "70000"}, "1 and 65535"},
		{"missing airdrop file", []string{"airdrop", "/no/such/peerbeam/file"}, "does not exist"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := NewRootCommand(func(Config) (*PeerNode, error) { return newTestNode(t), nil })
			var stdout, stderr bytes.Buffer
			root.SetOut(&stdout)
			root.SetErr(&stderr)
			root.SetArgs(c.args)

			err := root.Execute()
			if err == nil {
				t.Fatalf("%v succeeded, want a failure", c.args)
			}
			// The sentinel means the report was already written, so main stays quiet.
			if !errors.Is(err, ErrAlreadyReported) {
				t.Fatalf("error is %v, want it to carry ErrAlreadyReported", err)
			}

			printed := stderr.String()
			if !strings.Contains(printed, "try:") {
				t.Fatalf("the report carries no remediation:\n%s", printed)
			}
			if !strings.Contains(printed, c.want) {
				t.Fatalf("the report omits %q:\n%s", c.want, printed)
			}
		})
	}
}

// TestCapabilityTableCoversEveryRequirementArea checks the table itself against the requirement areas
// Req 12.6 names, so a capability cannot be dropped from the table to make the coverage test pass.
//
// Requirements: 12.6
func TestCapabilityTableCoversEveryRequirementArea(t *testing.T) {
	table := CapabilityCommands()
	want := []Capability{
		CapabilityDiscovery, CapabilityTransport, CapabilitySessions,
		CapabilityText, CapabilityClipboard, CapabilityTransfer,
		CapabilityPairing, CapabilityStatus, CapabilityAirDrop,
	}
	for _, capability := range want {
		paths, found := table[capability]
		if !found || len(paths) == 0 {
			t.Fatalf("%s is missing from the capability table", capability)
		}
	}
	if len(table) != len(want) {
		t.Fatalf("the table holds %d capabilities, want %d", len(table), len(want))
	}
}

// helperCommandCount keeps cobra referenced in a way that documents why it is here: the command tree
// is cobra's, and the tests above walk it through cobra's own Find.
var _ = (*cobra.Command)(nil)
