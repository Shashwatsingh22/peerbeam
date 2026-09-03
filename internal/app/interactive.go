package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/peerbeam/peerbeam/internal/core/discovery"
	"github.com/peerbeam/peerbeam/internal/core/report"
	"github.com/peerbeam/peerbeam/internal/core/text"
)

// The interactive session: start the app, see who is around, pick one, connect, and chat.
//
// It is a state machine over five states - Discovering, PeerPicker, Connecting, Pairing, ChatView -
// and it is written so the whole thing can be tested without a terminal: input arrives through a
// LineReader and output goes to an io.Writer, so a test drives it with a scripted reader and asserts
// on captured bytes, the same shape as the status renderer test.
//
// Every terminal edge returns to the Peer_Picker rather than exiting (Req 6.5, 7.3, 8.7, 8.8):
// a user who mistyped a selection or picked a peer that went out of range has not asked to quit.
// Only an explicit quit at the picker reaches exit.

// LineReader yields one line of user input at a time. It is an interface so the session can be
// driven by a scripted script in a test and by the terminal in production, with no terminal
// dependency in the state machine itself.
type LineReader interface {
	// ReadLine returns the next line without its trailing newline, or an error. io.EOF means the
	// input closed, which the session treats as a quit.
	ReadLine() (string, error)
}

// bufioLineReader adapts a bufio.Reader to LineReader for the real terminal.
type bufioLineReader struct{ r *bufio.Reader }

func newBufioLineReader(r io.Reader) *bufioLineReader {
	return &bufioLineReader{r: bufio.NewReader(r)}
}

func (b *bufioLineReader) ReadLine() (string, error) {
	line, err := b.r.ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if err != nil && line != "" {
		// A final line with no trailing newline still counts before the error is reported.
		return line, nil
	}
	return line, err
}

// InteractiveSession runs the picker-and-chat loop over one node.
type InteractiveSession struct {
	node   *PeerNode
	in     LineReader
	out    io.Writer
	prompt *promptConfirmer

	// chat is the display the ChatView reads inbound text from. It is the node's Display, set to
	// a chatDisplay at construction, so a received Message reaches the view through the same
	// router path every other Message uses.
	chat *chatDisplay
}

// NewInteractiveSession wires a session over a node whose Display is a *chatDisplay. The node must
// already be started, so discovery is running by the time the picker is shown.
func NewInteractiveSession(node *PeerNode, chat *chatDisplay, in io.Reader, out io.Writer) *InteractiveSession {
	reader := newBufioLineReader(in)
	return &InteractiveSession{
		node: node,
		in:   reader,
		out:  out,
		// The prompt reads from the same input as the session, so the pairing y/N is answered on
		// the one stdin the user is typing into.
		prompt: &promptConfirmer{out: out, in: reader},
		chat:   chat,
	}
}

// Run drives the session until the user quits or the input closes. It never returns an error for a
// normal quit; an error means the input or output itself failed.
func (s *InteractiveSession) Run(ctx context.Context) error {
	s.printStartupReport()
	for {
		fingerprint, quit, err := s.pickPeer(ctx)
		if err != nil {
			return err
		}
		if quit {
			fmt.Fprintln(s.out, "goodbye")
			return nil
		}
		if err := s.connectAndChat(ctx, fingerprint); err != nil {
			return err
		}
		// connectAndChat returns when the chat ends or a connection failed; either way, back to
		// the picker.
	}
}

// printStartupReport shows what the node could not bring up, once, at entry (Req 10.3).
func (s *InteractiveSession) printStartupReport() {
	failures := s.node.StartupReport()
	if len(failures) == 0 {
		return
	}
	fmt.Fprintln(s.out, "at startup:")
	for _, f := range failures {
		fmt.Fprintf(s.out, "  %s\n", f.String())
	}
	fmt.Fprintln(s.out)
}

// pickPeer shows the visible peers and reads a selection. It returns the chosen fingerprint, or
// quit=true, or an input error.
//
// The list is snapshotted each time it is displayed and a selection resolves to a fingerprint, not
// a row (Req 6.7): a peer that expired between display and selection produces "no longer visible"
// rather than connecting to whoever now occupies that row.
func (s *InteractiveSession) pickPeer(ctx context.Context) (fingerprint string, quit bool, err error) {
	// Give discovery a moment on first entry so the list is not empty for no reason (Req 6.3).
	if s.node.HasPresence() && s.node.Registry().Len() == 0 {
		fmt.Fprintln(s.out, "discovering peers...")
		s.node.WaitForFirstPeer(ctx, PeerDiscoveryWait)
	}

	for {
		snapshot := s.renderPeers()
		fmt.Fprint(s.out, "select a peer [number, r to rescan, q to quit]: ")

		line, readErr := s.in.ReadLine()
		if readErr == io.EOF {
			return "", true, nil
		}
		if readErr != nil {
			return "", false, readErr
		}
		choice := strings.TrimSpace(line)

		switch choice {
		case "q", "quit":
			return "", true, nil
		case "r", "rescan", "":
			if s.node.HasPresence() {
				fmt.Fprintln(s.out, "rescanning...")
				s.node.WaitForFirstPeer(ctx, PeerDiscoveryWait)
			}
			continue
		}

		index, convErr := strconv.Atoi(choice)
		if convErr != nil || index < 1 || index > len(snapshot) {
			fmt.Fprintf(s.out, "%q is not one of 1..%d, r, or q\n", choice, len(snapshot))
			continue
		}

		// Resolve against the snapshot the user was shown, by fingerprint. If that peer has
		// since expired, say so rather than connecting to a different one.
		chosen := snapshot[index-1]
		if !s.stillVisible(chosen.Fingerprint) {
			fmt.Fprintf(s.out, "%s is no longer visible; rescanning\n", displayNameOf(chosen))
			continue
		}
		return chosen.Fingerprint, false, nil
	}
}

// renderPeers prints the current visible peer list and returns the snapshot it printed, so a later
// selection resolves against exactly what was shown.
func (s *InteractiveSession) renderPeers() []discovery.VisiblePeer {
	peers := s.node.Registry().Visible()
	// A stable order so the numbering does not shuffle between redraws.
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].DisplayName != peers[j].DisplayName {
			return peers[i].DisplayName < peers[j].DisplayName
		}
		return peers[i].Fingerprint < peers[j].Fingerprint
	})

	if len(peers) == 0 {
		fmt.Fprintln(s.out, "no peers visible yet")
		return peers
	}

	fmt.Fprintln(s.out, "peers:")
	for i, peer := range peers {
		media := make([]string, 0, len(peer.Endpoints))
		for medium := range peer.Endpoints {
			media = append(media, medium.String())
		}
		sort.Strings(media)

		trust := "needs pairing"
		if _, ok := s.node.Pairing().Trusted(peer.Fingerprint); ok {
			trust = "trusted"
		}
		fmt.Fprintf(s.out, "  %d  %-16s  %s  %s  [%s]\n",
			i+1, displayNameOf(peer), shortFingerprint(peer.Fingerprint),
			strings.Join(media, ","), trust)
	}
	return peers
}

// stillVisible reports whether a fingerprint is in the current list, which is how a selection made
// against a stale snapshot is caught.
func (s *InteractiveSession) stillVisible(fingerprint string) bool {
	for _, peer := range s.node.Registry().Visible() {
		if peer.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}

// connectAndChat pairs if needed, connects with visible progress, and runs the chat loop.
//
// Pairing precedes the session for an untrusted peer (Req 7.4), and it is a separate connection
// from the session handshake, so it is done and torn down before Connect opens its own.
func (s *InteractiveSession) connectAndChat(ctx context.Context, fingerprint string) error {
	if _, trusted := s.node.Pairing().Trusted(fingerprint); !trusted {
		fmt.Fprintf(s.out, "%s is not paired yet; pairing first\n", shortFingerprint(fingerprint))
		result, failure := s.node.PairWith(ctx, fingerprint, s.prompt)
		if failure != nil {
			s.reportInline(failure)
			return nil // back to the picker (Req 7.3)
		}
		fmt.Fprintf(s.out, "paired with %s\n", displayName(result.PeerDisplayName, result.Fingerprint))
	}

	fmt.Fprintf(s.out, "connecting to %s...\n", shortFingerprint(fingerprint))
	result, failure := s.node.Connect(ctx, fingerprint)
	if failure != nil {
		s.reportInline(failure)
		return nil
	}
	fmt.Fprintf(s.out, "connection established with %s over %s\n",
		result.Session.DisplayName, result.Transport.Name())

	return s.chatLoop(ctx, fingerprint, result.Session.DisplayName)
}

// chatLoop reads lines and sends them, while inbound Messages print through the chat display. It
// returns when the user leaves, the peer closes the session, or the input closes.
func (s *InteractiveSession) chatLoop(ctx context.Context, fingerprint, peerName string) error {
	fmt.Fprintf(s.out, "chatting with %s. type a message, or /leave to return to the peer list.\n", peerName)

	// Route this peer's inbound text to the terminal for the life of the chat, then detach so a
	// later chat with someone else does not print here.
	s.chat.attach(fingerprint, s.out)
	defer s.chat.detach()

	for {
		line, readErr := s.in.ReadLine()
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
		message := strings.TrimRight(line, "\r\n")

		switch strings.TrimSpace(message) {
		case "/leave":
			if session := s.node.Sessions().Find(fingerprint); session != nil {
				s.node.closeSession(session, "left by the user")
			}
			fmt.Fprintln(s.out, "left the conversation")
			return nil
		case "":
			// Req 8.4: an empty line sends nothing.
			continue
		}

		// Req 8.5: an oversized line is refused with a reason, and the chat stays open.
		if check := text.CheckText([]byte(message)); check.Kind() == text.CheckOutOfRange {
			fmt.Fprintf(s.out, "not sent: a message must be %d..%d bytes\n",
				text.TextMinBytes, text.TextMaxBytes)
			continue
		}

		if _, failure := s.node.SendText(fingerprint, message); failure != nil {
			// Req 8.6: report against this message and stay open.
			s.reportInline(failure)
			continue
		}
		// Req 8.9: distinguish what this user sent from what arrived.
		s.chat.showSent(message)

		// Req 8.8: if the peer closed the session while we were typing, say so and leave.
		if s.node.Sessions().FindActive(fingerprint) == nil {
			fmt.Fprintln(s.out, "the peer closed the session")
			return nil
		}
	}
}

// reportInline renders a failure through the single Describe mapping (Req 10.1).
func (s *InteractiveSession) reportInline(failure report.AppError) {
	fmt.Fprintln(s.out, report.Describe(failure, report.UnknownPeer).String())
}

// promptConfirmer asks the user to compare the pairing code at the terminal (Req 9.3, 9.9).
type promptConfirmer struct {
	out io.Writer
	in  LineReader
}

func (p *promptConfirmer) ConfirmPairing(ctx context.Context, fingerprint, peerName, code string) (bool, error) {
	name := displayName(peerName, fingerprint)
	fmt.Fprintf(p.out, "\npairing with %s\n", name)
	fmt.Fprintf(p.out, "  verification code: %s\n", code)
	fmt.Fprintf(p.out, "  confirm this exact code shows on %s? [y/N]: ", name)

	if p.in == nil {
		// No input wired means we cannot ask; refuse rather than trust silently.
		return false, nil
	}
	line, err := p.in.ReadLine()
	if err != nil {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

// chatDisplay is the TextDisplay the interactive session installs on its node.
//
// It has two states: detached, where inbound text is dropped because no chat is open, and attached
// to one peer's fingerprint, where that peer's text is printed to the chat writer. Text from any
// other peer is dropped while a chat is open, since the user is looking at one conversation - a
// message from a third peer printed into the middle of it would be confusing rather than helpful.
//
// Safe for concurrent use: Show runs on each Session's router goroutine while attach and detach run
// on the interactive goroutine.
type chatDisplay struct {
	mu          sync.Mutex
	fingerprint string
	out         io.Writer
}

func newChatDisplay() *chatDisplay { return &chatDisplay{} }

func (d *chatDisplay) attach(fingerprint string, out io.Writer) {
	d.mu.Lock()
	d.fingerprint = fingerprint
	d.out = out
	d.mu.Unlock()
}

func (d *chatDisplay) detach() {
	d.mu.Lock()
	d.fingerprint = ""
	d.out = nil
	d.mu.Unlock()
}

// Show prints an inbound Message when a chat is open. The router calls this; it does not know which
// peer the Message came from beyond the sender name, so a chat open with one peer prints every
// inbound line while it is open. In practice the interactive session holds one session at a time.
func (d *chatDisplay) Show(item InboundText) {
	d.mu.Lock()
	out := d.out
	d.mu.Unlock()
	if out == nil {
		return
	}
	// Req 8.2, 8.9: attributed to the sender and marked as received.
	fmt.Fprintf(out, "\r%s: %s\n", item.SenderName, item.Content)
}

// showSent echoes the local user's own line, marked as sent, so the transcript distinguishes the
// two directions (Req 8.9).
func (d *chatDisplay) showSent(message string) {
	d.mu.Lock()
	out := d.out
	d.mu.Unlock()
	if out == nil {
		return
	}
	fmt.Fprintf(out, "you: %s\n", message)
}

// displayNameOf and displayName render a peer's name, falling back to a short fingerprint when the
// name is empty, so a peer with no announced name is still selectable.
func displayNameOf(peer discovery.VisiblePeer) string {
	return displayName(peer.DisplayName, peer.Fingerprint)
}

func displayName(name, fingerprint string) string {
	if strings.TrimSpace(name) != "" {
		return name
	}
	return shortFingerprint(fingerprint)
}

var _ TextDisplay = (*chatDisplay)(nil)
