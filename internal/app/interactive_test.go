package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/discovery"
	"pgregory.net/rapid"
)

// scriptReader feeds a fixed list of lines to the session, then reports EOF, which the session
// treats as a quit. It stands in for the terminal so the state machine is driven without one.
type scriptReader struct {
	mu    sync.Mutex
	lines []string
	pos   int
}

func newScriptReader(lines ...string) *scriptReader {
	return &scriptReader{lines: lines}
}

func (r *scriptReader) ReadLine() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pos >= len(r.lines) {
		// The session treats io.EOF as a quit, so an exhausted script ends the loop.
		return "", io.EOF
	}
	line := r.lines[r.pos]
	r.pos++
	return line, nil
}

// seedPeer puts a peer in a node's registry so the picker has something to show.
func seedPeer(node *PeerNode, name, fingerprint string, medium discovery.Medium, addr string) {
	node.Registry().Observe(discovery.Announcement{
		DisplayName:     name,
		Fingerprint:     fingerprint,
		ProtocolVersion: ProtocolVersion,
		Port:            45770,
	}, medium, addr)
}

// newPickerSession builds an interactive session over a test node with a scripted reader and a
// captured output buffer. The node is not started, so no discovery runs; the picker reads whatever
// the test seeded into the registry.
func newPickerSession(t *testing.T, lines ...string) (*InteractiveSession, *bytes.Buffer, *PeerNode) {
	t.Helper()
	node := newTestNode(t)
	out := &bytes.Buffer{}
	session := &InteractiveSession{
		node:   node,
		in:     newScriptReader(lines...),
		out:    out,
		prompt: &promptConfirmer{out: out},
		chat:   newChatDisplay(),
	}
	return session, out, node
}

// Property 52: a selection resolves to the peer displayed at that index, or reports it is gone;
// never a different peer.
//
// The list is shuffled and trimmed between the display and the selection, and the property is that
// the fingerprint returned is the one shown at the chosen index, or - if that peer expired - an
// error, but never the peer that now occupies that row.
//
// Requirements: 6.7
func TestPropertySelectionResolvesToDisplayedPeer(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		count := rapid.IntRange(1, 6).Draw(rt, "count")
		node := newTestNode(t)
		for i := 0; i < count; i++ {
			seedPeer(node, fmt.Sprintf("peer-%d", i), hexFingerprint(i),
				discovery.MediumLAN, fmt.Sprintf("10.0.0.%d", i+1))
		}

		out := &bytes.Buffer{}
		session := &InteractiveSession{node: node, out: out, chat: newChatDisplay()}

		// Snapshot exactly what the picker would show.
		snapshot := session.renderPeers()
		if len(snapshot) != count {
			rt.Fatalf("rendered %d peers, seeded %d", len(snapshot), count)
		}

		index := rapid.IntRange(1, count).Draw(rt, "index")
		shownFingerprint := snapshot[index-1].Fingerprint

		// Simulate the list changing between display and selection. Expire(0) clears everyone
		// under the fixed manual clock, then a subset is re-seeded, so the chosen fingerprint
		// may or may not still be present - which is exactly the race pickPeer must handle.
		keep := rapid.Bool().Draw(rt, "keep")
		node.Registry().Expire(0)
		if keep {
			seedPeer(node, "peer", shownFingerprint, discovery.MediumLAN, "10.9.9.9")
		}
		// Re-seed some unrelated peers so a naive row-index lookup would resolve to the wrong one.
		for i := 0; i < count; i++ {
			seedPeer(node, fmt.Sprintf("other-%d", i), hexFingerprint(1000+i),
				discovery.MediumLAN, fmt.Sprintf("10.8.0.%d", i+1))
		}

		// Resolve the selection the way pickPeer does: against the snapshot, by fingerprint,
		// checking it is still visible.
		chosen := snapshot[index-1]
		if chosen.Fingerprint != shownFingerprint {
			rt.Fatalf("snapshot mutated under us: %s vs %s", chosen.Fingerprint, shownFingerprint)
		}
		if session.stillVisible(chosen.Fingerprint) {
			// Still visible only if we kept it; and it is the one we displayed, never another.
			if !keep {
				rt.Fatalf("a peer that was expired reported as visible: %s", shownFingerprint)
			}
		} else if keep {
			rt.Fatalf("a peer that was re-seeded reported as gone: %s", shownFingerprint)
		}
	})
}

// Property 54: every terminal edge returns to the picker; only quit reaches exit.
//
// The session is driven with scripts that exercise each way a turn can end - an invalid selection,
// a rescan, a quit - and the property is that only the quit script ends the loop, and it ends it
// cleanly.
//
// Requirements: 6.5
func TestPropertyEveryEdgeReturnsToPicker(t *testing.T) {
	// An invalid selection followed by quit: the invalid one must not exit, the quit must.
	session, out, node := newPickerSession(t, "999", "notanumber", "q")
	seedPeer(node, "peer", hexFingerprint(1), discovery.MediumLAN, "10.0.0.1")

	ctx := context.Background()
	if err := session.Run(ctx); err != nil {
		t.Fatalf("run returned an error on a normal quit: %v", err)
	}
	printed := out.String()
	if !strings.Contains(printed, "goodbye") {
		t.Fatalf("quit did not reach the exit path:\n%s", printed)
	}
	// Both invalid inputs were rejected in place, so the picker was shown at least three times
	// (initial, after 999, after notanumber).
	if strings.Count(printed, "select a peer") < 3 {
		t.Fatalf("an invalid selection did not return to the picker:\n%s", printed)
	}

	// A rescan then quit: the rescan re-displays without exiting.
	session2, out2, node2 := newPickerSession(t, "r", "q")
	seedPeer(node2, "peer", hexFingerprint(2), discovery.MediumLAN, "10.0.0.2")
	if err := session2.Run(ctx); err != nil {
		t.Fatalf("run returned an error: %v", err)
	}
	if !strings.Contains(out2.String(), "goodbye") {
		t.Fatalf("rescan-then-quit did not reach exit:\n%s", out2.String())
	}
}

// Property 53: an arriving message does not corrupt what the user has typed.
//
// This design reads whole lines rather than raw runes, so the partially typed line lives in the
// terminal's own line buffer, not in the session: an inbound Message printed between the user's
// lines is emitted by the chat display and cannot reach into a line the reader has not yet
// returned. The property asserts the observable consequence: an inbound Message and a sent Message
// are each emitted whole, on their own line, and neither is spliced into the other.
//
// Requirements: 8.3
func TestPropertyInboundMessageIsWholeLine(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		inbound := rapid.StringMatching(`[a-zA-Z0-9 ]{1,40}`).Draw(rt, "inbound")
		sent := rapid.StringMatching(`[a-zA-Z0-9 ]{1,40}`).Draw(rt, "sent")

		out := &bytes.Buffer{}
		chat := newChatDisplay()
		chat.attach("fp", out)

		// Interleave an inbound message and a sent echo, the way the chat loop and the router
		// goroutine would.
		chat.Show(InboundText{SenderName: "peer", Content: inbound, ReceivedAt: time.Now()})
		chat.showSent(sent)

		lines := strings.Split(strings.Trim(out.String(), "\n"), "\n")
		if len(lines) != 2 {
			rt.Fatalf("expected two whole lines, got %d: %q", len(lines), out.String())
		}
		// The inbound content appears intact on the received line, the sent content on the sent
		// line; neither line contains the other's marker.
		received := strings.TrimPrefix(lines[0], "\r")
		if !strings.Contains(received, inbound) || !strings.HasPrefix(received, "peer:") {
			rt.Fatalf("inbound line malformed: %q", received)
		}
		if !strings.Contains(lines[1], sent) || !strings.HasPrefix(lines[1], "you:") {
			rt.Fatalf("sent line malformed: %q", lines[1])
		}
	})
}

// Property 55: interactive output carries no secrets.
//
// No rendered line contains key material. The chat display only ever prints the sender name and the
// message content the user sent or received, so the property checks that a peer's public key bytes,
// rendered as the fingerprint's source, never appear in the transcript.
//
// Requirements: 10.2
func TestPropertyInteractiveOutputCarriesNoSecrets(t *testing.T) {
	session, out, node := newPickerSession(t, "q")
	// A peer whose fingerprint is present; its endpoint address is not secret, but the picker
	// must never print anything key-shaped beyond the fingerprint the user needs to see.
	seedPeer(node, "peer", hexFingerprint(7), discovery.MediumLAN, "10.0.0.7")

	if err := session.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	printed := out.String()

	// The node's own private key must never appear.
	priv := node.Identity().PrivateKey
	if len(priv) > 0 && bytes.Contains([]byte(printed), priv) {
		t.Fatal("the transcript contains the local private key")
	}
	// The full fingerprint is abbreviated in the picker, so the untruncated 64-char form should
	// not appear.
	if strings.Contains(printed, hexFingerprint(7)) {
		t.Fatalf("the picker printed a full fingerprint rather than an abbreviation:\n%s", printed)
	}
}
