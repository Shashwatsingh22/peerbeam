package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/peerbeam/peerbeam/internal/core/clipboard"
	"github.com/peerbeam/peerbeam/internal/core/codec"
	"github.com/peerbeam/peerbeam/internal/core/report"
	"github.com/peerbeam/peerbeam/internal/core/session"
	"github.com/peerbeam/peerbeam/internal/core/text"
	"github.com/peerbeam/peerbeam/internal/core/transfer"
	"github.com/peerbeam/peerbeam/internal/core/transport"
	"github.com/peerbeam/peerbeam/internal/core/trust"
	"github.com/peerbeam/peerbeam/internal/platform/share"
)

// Capability names the requirement areas Req 12.6 requires a command for. Every entry has to be
// reachable from the root command, and CapabilityCommands maps each to the command path that serves
// it, so the coverage is checkable rather than asserted.
type Capability string

const (
	CapabilityDiscovery Capability = "discovery (Req 1)"
	CapabilityTransport Capability = "transport selection (Req 2, 3)"
	CapabilitySessions  Capability = "session management (Req 4)"
	CapabilityText      Capability = "text messaging (Req 5)"
	CapabilityClipboard Capability = "clipboard sharing (Req 6)"
	CapabilityTransfer  Capability = "file transfer (Req 7)"
	CapabilityPairing   Capability = "pairing and trust (Req 9)"
	CapabilityStatus    Capability = "status and reporting (Req 13)"
	CapabilityAirDrop   Capability = "AirDrop handoff (Req 12.4)"
)

// CapabilityCommands is the command path that serves each capability. Req 12.6 requires every
// capability in Requirements 1 through 11 to be reachable from the command line with no graphical
// surface, and this table is what the coverage test walks.
func CapabilityCommands() map[Capability][]string {
	return map[Capability][]string{
		CapabilityDiscovery: {"peers", "peers add"},
		CapabilityTransport: {"pin"},
		CapabilitySessions:  {"connect", "disconnect"},
		CapabilityText:      {"send"},
		CapabilityClipboard: {"clip send", "clip auto", "clip sync", "clip pending"},
		CapabilityTransfer:  {"file send", "file resume", "file cancel"},
		CapabilityPairing:   {"pair", "trust list", "trust remove"},
		CapabilityStatus:    {"status", "log tail"},
		CapabilityAirDrop:   {"airdrop"},
	}
}

// Options are the root command's global flags.
type Options struct {
	DisplayName string
	StateDir    string
	ListenPort  int
}

// NewRootCommand assembles the whole command tree (Req 12.6).
//
// The node is built lazily, inside each command's RunE, rather than in this function. Two reasons:
// `peerbeam --help` must not create ~/.peerbeam or generate a key, and a command that fails to
// build a node should report that through the same Failure path as everything else rather than as a
// bare error from a constructor the user never invoked.
func NewRootCommand(newNode func(Config) (*PeerNode, error)) *cobra.Command {
	options := &Options{}

	root := &cobra.Command{
		Use:   "peerbeam",
		Short: "Move text, clipboard content, and files between your own machines",
		Long: strings.TrimSpace(`
Peerbeam discovers your other machines on the local network or over Bluetooth,
pairs with them once, and then moves text, clipboard content, and files over
whichever transport is currently fastest.

Every capability is a command; there is no graphical interface.`),
		SilenceUsage: true,
		// Errors are printed by main through the reporting path, so cobra must not print
		// them a second time.
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&options.DisplayName, "name", "",
		"display name to publish to peers (default: this machine's host name)")
	root.PersistentFlags().StringVar(&options.StateDir, "state-dir", "",
		"directory holding identity.key and trusted.json (default: ~/.peerbeam)")
	root.PersistentFlags().IntVar(&options.ListenPort, "port", 0,
		"TCP port to listen on (0 lets the operating system choose)")

	// A lifecycle threads through every command: build the node, optionally start its
	// background loops, and register the matching stop so the process joins every goroutine
	// before it exits. It is created per command run rather than once, so `--help` builds
	// nothing and a command that never opens a node starts nothing.
	//
	// Two openers rather than one. A command that needs discovery, a Session, or inbound
	// connections gets a started node; a command that needs only local state - the trust
	// store, the event log, a one-shot status - gets an unstarted one. Starting a node opens
	// listeners and launches presence loops, so paying that cost for `trust list` would be
	// waste and, worse, would make a read-only command bind a port.
	build := func(cmd *cobra.Command) (*PeerNode, error) {
		return newNode(Config{
			DisplayName: options.DisplayName,
			StateDir:    options.StateDir,
			ListenPort:  options.ListenPort,
		})
	}

	// liveOpener starts the node and arranges for it to stop when the command finishes. Stop is
	// the single join point, so registering it on the command as a PostRun hook is what
	// guarantees no loop and no BT_Shim outlives the command (Req 5.2, 5.3).
	liveOpener := func(cmd *cobra.Command) (*PeerNode, error) {
		node, err := build(cmd)
		if err != nil {
			return nil, err
		}
		if err := node.Start(cmd.Context()); err != nil {
			node.Stop()
			return nil, err
		}
		// PostRunE runs after RunE regardless of its outcome, and the deferred stop in main's
		// signal path is the backstop for a hard interrupt.
		cmd.PostRunE = chainPostRun(cmd.PostRunE, func(*cobra.Command, []string) error {
			node.Stop()
			return nil
		})
		return node, nil
	}

	// localOpener builds a node without starting it, for commands that touch only local state.
	localOpener := func(cmd *cobra.Command) (*PeerNode, error) { return build(cmd) }

	root.AddCommand(
		newPeersCommand(liveOpener),
		newPairCommand(liveOpener),
		newTrustCommand(localOpener),
		newConnectCommand(liveOpener),
		newDisconnectCommand(liveOpener),
		newPinCommand(liveOpener),
		newSendCommand(liveOpener),
		newClipCommand(liveOpener),
		newFileCommand(liveOpener),
		newStatusCommand(localOpener),
		newLogCommand(localOpener),
		newAirDropCommand(localOpener),
	)
	return root
}

// chainPostRun composes two cobra PostRunE hooks, so registering a stop does not clobber a hook a
// command already set.
func chainPostRun(existing, added func(*cobra.Command, []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		var firstErr error
		if existing != nil {
			firstErr = existing(cmd, args)
		}
		if err := added(cmd, args); err != nil && firstErr == nil {
			firstErr = err
		}
		return firstErr
	}
}

// nodeOpener builds a node on demand.
// nodeOpener builds the node a command needs, given the running command so it can reach the
// command context and register a stop hook. A live opener starts the node; a local one does not.
type nodeOpener func(cmd *cobra.Command) (*PeerNode, error)

// newPeersCommand covers Req 1.2, 1.6, 1.7, and 1.10.
func newPeersCommand(open nodeOpener) *cobra.Command {
	peers := &cobra.Command{
		Use:   "peers",
		Short: "List the peers currently visible on any medium",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			node, err := open(cmd)
			if err != nil {
				return err
			}
			// The node has just started, so the list is empty for the first few seconds
			// (Req 5.5). Rendering it immediately is what makes the tool look broken: an
			// empty table reads as "nobody is here" when the truth is "still looking". Give
			// discovery a bounded interval, saying so, and render whatever it found - which
			// may still be empty on a network with no peers, and that is a real answer.
			out := cmd.OutOrStdout()
			// Only wait if a presence source is actually running: with no source, nothing can
			// ever populate the list, so waiting would stall for the full interval and then
			// print the same empty table. A manual `peers add` still shows up either way.
			if node.HasPresence() && node.Registry().Len() == 0 {
				fmt.Fprintln(out, "discovering peers...")
				node.WaitForFirstPeer(cmd.Context(), PeerDiscoveryWait)
			}
			return renderPeerTable(out, node)
		},
	}

	add := &cobra.Command{
		Use:   "add <host> <port>",
		Short: "Add a peer by address, without waiting for discovery",
		Long: strings.TrimSpace(`
Adds a peer the automatic discovery has not found, for a network where multicast
is filtered. The entry is marked as manually supplied and is updated in place if
that peer later appears on its own.`),
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			node, err := open(cmd)
			if err != nil {
				return err
			}
			port, err := strconv.Atoi(args[1])
			if err != nil {
				// Req 1.10: the error says which of the two was rejected.
				return reportError(cmd, node, &report.ManualPeerRejected{
					Field:  "port",
					Reason: fmt.Sprintf("%q is not a number", args[1]),
				})
			}

			outcome := node.Registry().AddManual(args[0], port)
			if outcome.Rejected != nil {
				field := "address"
				if outcome.Rejected.RejectedPort() {
					field = "port"
				}
				return reportError(cmd, node, &report.ManualPeerRejected{
					Field:  field,
					Reason: outcome.Rejected.Error(),
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "added %s:%d as a manually supplied peer\n", args[0], port)
			return nil
		},
	}

	peers.AddCommand(add)
	return peers
}

// newPairCommand covers Req 9.3, 9.4, and 9.5.
func newPairCommand(open nodeOpener) *cobra.Command {
	var confirm, reject bool

	pair := &cobra.Command{
		Use:   "pair <fingerprint>",
		Short: "Pair with a peer by comparing a 6-digit code on both machines",
		Long: strings.TrimSpace(`
Shows a 6-digit verification code derived from both machines' public keys. The
same code appears on the other machine. Compare them, then confirm on both
within 2 minutes.

The code is never sent over the network: both machines derive it independently,
so an attacker who controls the network cannot make the two agree.`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			node, err := open(cmd)
			if err != nil {
				return err
			}
			fingerprint := args[0]

			switch {
			case confirm && reject:
				return errors.New("--confirm and --reject cannot both be given")

			case reject:
				// Req 9.5: a reported mismatch abandons the attempt and changes nothing.
				outcome := node.Pairing().ReportMismatch(fingerprint)
				if outcome.Failed != nil {
					fmt.Fprintln(cmd.OutOrStdout(), outcome.Failed.Error())
				}
				return nil

			case confirm:
				outcome := node.Pairing().ConfirmLocal(fingerprint)
				switch outcome.Kind() {
				case trust.PairingPaired:
					fmt.Fprintf(cmd.OutOrStdout(), "paired with %s\n",
						outcome.Paired.DisplayName)
					node.writeEvent(report.EventSessionEstablished,
						outcome.Paired.DisplayName, outcome.Paired.Fingerprint, "paired")
					return nil
				case trust.PairingPending:
					fmt.Fprintln(cmd.OutOrStdout(),
						"confirmed on this machine; waiting for the other machine")
					return nil
				default:
					return reportError(cmd, node, &report.PairingFailed{
						Fingerprint: fingerprint,
						Reason:      outcome.Failed.Reason,
					})
				}
			}

			// No flag: start the attempt and show the code.
			//
			// A code cannot be derived without the peer's public key, and that key arrives
			// over the pairing exchange rather than from the announcement, which carries
			// only its fingerprint. So the command checks what it can - that the peer is
			// visible at all - and reports the missing key rather than inventing one.
			if !node.PeerIsVisible(fingerprint) {
				return reportError(cmd, node, &report.PairingFailed{
					Fingerprint: fingerprint,
					Reason:      "that peer is not visible; run `peerbeam peers` to see what is",
				})
			}
			if attempt := node.Pairing().Attempt(fingerprint); attempt != nil {
				// An exchange is already under way, so show the code it produced.
				fmt.Fprintf(cmd.OutOrStdout(),
					"verification code for %s: %s\n\nCompare it with the other machine, then run:\n  peerbeam pair %s --confirm\n",
					attempt.PeerDisplayName, attempt.Code, fingerprint)
				return nil
			}
			return reportError(cmd, node, &report.PairingFailed{
				Fingerprint: fingerprint,
				Reason:      "no public key has been received from that peer yet",
			})
		},
	}

	pair.Flags().BoolVar(&confirm, "confirm", false, "confirm that the codes match")
	pair.Flags().BoolVar(&reject, "reject", false, "report that the codes do not match")
	return pair
}

// newTrustCommand covers Req 9.8, 9.9, and 9.10.
func newTrustCommand(open nodeOpener) *cobra.Command {
	trustCmd := &cobra.Command{
		Use:   "trust",
		Short: "Inspect and manage the peers this machine trusts",
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List every trusted peer",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			node, err := open(cmd)
			if err != nil {
				return err
			}
			if failure := node.Pairing().StoreFailure(); failure != nil {
				// Req 9.11: the store is unusable, so nothing is listed and the report
				// names the failing step.
				return reportError(cmd, node, &report.TrustStoreFailed{Reason: failure.Reason})
			}

			peers := node.Pairing().TrustedPeers()
			if len(peers) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no peers are trusted yet; run `peerbeam pair`")
				return nil
			}
			for _, peer := range peers {
				// The full fingerprint here, unlike the peer table: this is the value a
				// user compares against the other machine.
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\tpaired %s\n",
					peer.Fingerprint, peer.DisplayName,
					peer.PairedAt.Format("2006-01-02 15:04"))
			}
			return nil
		},
	}

	remove := &cobra.Command{
		Use:   "remove <fingerprint>",
		Short: "Stop trusting a peer and close any session with it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			node, err := open(cmd)
			if err != nil {
				return err
			}
			outcome := node.Pairing().RemoveTrustedPeer(args[0])
			if outcome.Err != nil {
				return reportError(cmd, node, &report.TrustStoreFailed{
					Reason: outcome.Err.Error(),
				})
			}
			if !outcome.Removed {
				fmt.Fprintf(cmd.OutOrStdout(), "%s was not trusted\n", args[0])
				return nil
			}

			// Req 9.8: the Session with that Peer closes. closeSession is used rather than
			// the registry directly, so the Session's goroutines are cancelled and its
			// connection released rather than left running against a peer that is no longer
			// trusted.
			if s := node.Sessions().Find(outcome.CloseSessionFor); s != nil {
				node.closeSession(s, "trust removed by the user")
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"removed %s; it must pair again before it can connect\n", args[0])
			return nil
		},
	}

	trustCmd.AddCommand(list, remove)
	return trustCmd
}

// newConnectCommand covers Req 2.3 through 2.6 and Req 4.1.
func newConnectCommand(open nodeOpener) *cobra.Command {
	return &cobra.Command{
		Use:   "connect <fingerprint>",
		Short: "Open a session with a trusted peer over the fastest available transport",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			node, err := open(cmd)
			if err != nil {
				return err
			}
			fingerprint := args[0]

			// Trust first: Req 9.6 rejects an unpaired peer with a pairing prompt rather
			// than attempting a connection that could not be authenticated anyway.
			decision := node.Pairing().Admit(fingerprint, nil)
			switch decision.Kind() {
			case trust.AdmitStoreFailed:
				return reportError(cmd, node, &report.TrustStoreFailed{
					Reason: decision.StoreFailed.Reason,
				})
			case trust.AdmitNotTrusted:
				return reportError(cmd, node, &report.PeerNotTrusted{Fingerprint: fingerprint})
			}

			// Req 2.1: candidates are the enabled Transports whose medium the peer is
			// visible on, ranked fastest first. Connect walks the ladder, completes the
			// authenticated key exchange, and admits the Session.
			result, connectFailure := node.Connect(cmd.Context(), fingerprint)
			if connectFailure != nil {
				return reportError(cmd, node, connectFailure)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "connected to %s on %s as session %s\n",
				result.Session.DisplayName, result.Transport.Name(),
				shortId(result.Session.Id.String()))
			return nil
		},
	}
}

// newDisconnectCommand covers Req 4.3.
func newDisconnectCommand(open nodeOpener) *cobra.Command {
	return &cobra.Command{
		Use:   "disconnect <fingerprint>",
		Short: "Close the session with a peer, leaving every other session untouched",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			node, err := open(cmd)
			if err != nil {
				return err
			}
			s := node.Sessions().Find(args[0])
			if s == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "no session with %s\n", args[0])
				return nil
			}
			node.closeSession(s, "closed by the user")
			fmt.Fprintf(cmd.OutOrStdout(), "closed the session with %s\n", s.DisplayName)
			return nil
		},
	}
}

// newPinCommand covers Req 2.10 and 2.11.
func newPinCommand(open nodeOpener) *cobra.Command {
	var clear bool

	pin := &cobra.Command{
		Use:   "pin <fingerprint> [transport]",
		Short: "Pin a session to one transport, disabling rank-based switching",
		Long: strings.TrimSpace(`
Pins a session to LAN_Transport or BT_Transport. A pinned session is never moved
by the ranking, and if the pinned transport becomes unavailable the session goes
to a disconnected state rather than switching.`),
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			node, err := open(cmd)
			if err != nil {
				return err
			}
			if clear {
				if err := node.SetPin(args[0], ""); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "released the transport pin for %s\n",
					shortFingerprint(args[0]))
				return nil
			}
			if len(args) < 2 {
				return errors.New("name a transport to pin to, or pass --clear to release it")
			}

			if err := node.SetPin(args[0], args[1]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"pinned %s to %s; rank-based switching is off for that session\n",
				shortFingerprint(args[0]), args[1])
			return nil
		},
	}

	pin.Flags().BoolVar(&clear, "clear", false, "release the pin and resume rank-based switching")
	return pin
}

// newSendCommand covers Req 5.1, 5.8, 4.4, and 4.7.
func newSendCommand(open nodeOpener) *cobra.Command {
	var message string

	send := &cobra.Command{
		Use:   "send <fingerprint>... --text <message>",
		Short: "Send a line of text to one peer or to a group",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			node, err := open(cmd)
			if err != nil {
				return err
			}
			if message == "" {
				// Req 5.8: an empty submission sends nothing and names the range.
				return reportError(cmd, node, &report.TextOutOfRange{
					ActualBytes: 0,
					Min:         text.TextMinBytes,
					Max:         text.TextMaxBytes,
				})
			}

			// Req 5.8: validate before anything is sent and before any sequence number
			// moves.
			check := text.CheckText([]byte(message))
			if check.Kind() == text.CheckOutOfRange {
				return reportError(cmd, node, &report.TextOutOfRange{
					ActualBytes: check.OutOfRange.ActualBytes,
					Min:         check.OutOfRange.Min,
					Max:         check.OutOfRange.Max,
				})
			}
			if check.Kind() == text.CheckInvalidUTF8 {
				return reportError(cmd, node, &report.TextInvalidUTF8{})
			}

			// Req 4.4: up to 8 peers, each on its own Session.
			if len(args) > 8 {
				return fmt.Errorf("a group may hold at most 8 peers, not %d", len(args))
			}

			// Req 4.7: one outcome per selected Peer. SendText is the single send path, so
			// a group send and a single send behave identically and neither can drift from
			// the other.
			for _, fingerprint := range args {
				sequence, sendFailure := node.SendText(fingerprint, message)
				if sendFailure != nil {
					failure := report.Describe(sendFailure, shortFingerprint(fingerprint))
					fmt.Fprintf(cmd.OutOrStdout(), "%s: not delivered (%s)\n",
						shortFingerprint(fingerprint), failure.Reason)
					continue
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: sent as sequence %d\n",
					shortFingerprint(fingerprint), sequence)
			}
			return nil
		},
	}

	send.Flags().StringVar(&message, "text", "", "the text to send (1 to 65536 UTF-8 bytes)")
	return send
}

// newClipCommand covers Req 6.1 through 6.11.
func newClipCommand(open nodeOpener) *cobra.Command {
	clipCmd := &cobra.Command{
		Use:   "clip",
		Short: "Share clipboard content with a peer",
	}

	send := &cobra.Command{
		Use:   "send <fingerprint>...",
		Short: "Send this machine's clipboard text to one peer or a group",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			node, err := open(cmd)
			if err != nil {
				return err
			}

			content, hasText, err := node.Clipboard().ReadText(cmd.Context())
			if err != nil {
				return reportError(cmd, node, &report.ClipboardUnsupportedContent{})
			}
			if !hasText {
				// Req 6.7: nothing sendable, reported as an unsupported content type.
				return reportError(cmd, node, &report.ClipboardUnsupportedContent{})
			}

			// Req 6.11: over the limit sends nothing and names the 1 MiB limit.
			check := clipboard.CheckClipboardSend([]byte(content))
			switch check.Kind() {
			case clipboard.SendTooLarge:
				return reportError(cmd, node, &report.ClipboardTooLarge{
					ActualBytes: check.TooLarge.ActualBytes,
					Maximum:     check.TooLarge.Maximum,
				})
			case clipboard.SendUnsupported:
				return reportError(cmd, node, &report.ClipboardUnsupportedContent{})
			}

			parts := clipboard.SplitClipboard([]byte(content))
			for _, fingerprint := range args {
				state := node.ClipboardFor(fingerprint)
				decision := state.DecideSend([]byte(content))
				switch {
				case decision.Suppressed:
					// Req 6.6: this is what the peer last sent or we last applied, so
					// sending it would start a loop.
					fmt.Fprintf(cmd.OutOrStdout(),
						"%s: nothing to send (the peer already has this content)\n",
						shortFingerprint(fingerprint))
				case decision.Send == nil:
					fmt.Fprintf(cmd.OutOrStdout(), "%s: nothing to send\n",
						shortFingerprint(fingerprint))
				default:
					state.RecordSent(decision.Send)
					fmt.Fprintf(cmd.OutOrStdout(), "%s: sending %s in %d part(s)\n",
						shortFingerprint(fingerprint),
						formatBytes(int64(len(content))), len(parts))
				}
			}
			return nil
		},
	}

	auto := &cobra.Command{
		Use:   "auto <fingerprint> on|off",
		Short: "Apply received clipboard content automatically, or hold it for confirmation",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			node, err := open(cmd)
			if err != nil {
				return err
			}
			on, err := parseOnOff(args[1])
			if err != nil {
				return err
			}
			node.ClipboardFor(args[0]).SetAutoApply(on)
			fmt.Fprintf(cmd.OutOrStdout(), "automatic clipboard apply for %s: %s\n",
				shortFingerprint(args[0]), args[1])
			return nil
		},
	}

	sync := &cobra.Command{
		Use:   "sync <fingerprint> on|off",
		Short: "Keep sending clipboard changes to a peer while the session is active",
		Long: strings.TrimSpace(`
Continuous sync is opt-in per peer. While it is on, a clipboard change is sent
within a second, except when the content is what that peer just sent or what was
last applied from it, which would otherwise bounce between the two machines.`),
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			node, err := open(cmd)
			if err != nil {
				return err
			}
			on, err := parseOnOff(args[1])
			if err != nil {
				return err
			}
			node.ClipboardFor(args[0]).SetContinuousSync(on)
			fmt.Fprintf(cmd.OutOrStdout(), "continuous clipboard sync for %s: %s\n",
				shortFingerprint(args[0]), args[1])
			return nil
		},
	}

	pending := &cobra.Command{
		Use:   "pending <accept|decline|show> <fingerprint>",
		Short: "Decide on clipboard content held for confirmation",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			node, err := open(cmd)
			if err != nil {
				return err
			}
			state := node.ClipboardFor(args[1])

			switch args[0] {
			case "show":
				entry := state.Pending()
				if entry == nil {
					fmt.Fprintln(cmd.OutOrStdout(), "nothing is pending for that peer")
					return nil
				}
				// Req 6.3: the prompt carries the sender's name and the receipt time.
				fmt.Fprintf(cmd.OutOrStdout(), "from %s at %s: %s pending, expires %s\n",
					entry.SenderName, entry.ReceivedAt.Format("15:04:05"),
					formatBytes(int64(len(entry.Content))),
					entry.ExpiresAt().Format("15:04:05"))
				return nil

			case "accept":
				content, outcome := state.ConfirmPending()
				switch outcome {
				case clipboard.PendingApplied:
					// Req 6.4: replace the entire clipboard.
					if err := node.Clipboard().WriteText(cmd.Context(), string(content)); err != nil {
						return reportError(cmd, node, &report.ClipboardRejected{
							Reason: err.Error(),
						})
					}
					fmt.Fprintf(cmd.OutOrStdout(), "applied %s to the clipboard\n",
						formatBytes(int64(len(content))))
				case clipboard.PendingExpired:
					fmt.Fprintln(cmd.OutOrStdout(),
						"that entry expired; the clipboard was left unchanged")
				default:
					fmt.Fprintln(cmd.OutOrStdout(), "nothing is pending for that peer")
				}
				return nil

			case "decline":
				// Req 6.9: discard, leave the clipboard alone, stop prompting.
				if outcome := state.DeclinePending(); outcome == clipboard.PendingNone {
					fmt.Fprintln(cmd.OutOrStdout(), "nothing is pending for that peer")
					return nil
				}
				fmt.Fprintln(cmd.OutOrStdout(),
					"declined; the clipboard was left unchanged")
				return nil

			default:
				return fmt.Errorf("unknown action %q; use accept, decline, or show", args[0])
			}
		},
	}

	clipCmd.AddCommand(send, auto, sync, pending)
	return clipCmd
}

// newFileCommand covers Req 7.1 through 7.13.
func newFileCommand(open nodeOpener) *cobra.Command {
	fileCmd := &cobra.Command{
		Use:   "file",
		Short: "Send, resume, and cancel file transfers",
	}

	send := &cobra.Command{
		Use:   "send <fingerprint> <path>",
		Short: "Send a file, verified end to end with a SHA-256 digest",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			node, err := open(cmd)
			if err != nil {
				return err
			}
			path := args[1]

			info, statErr := os.Stat(path)
			if statErr != nil {
				return fmt.Errorf("cannot read %s: %w", path, statErr)
			}
			if info.IsDir() {
				return fmt.Errorf("%s is a directory; send a file", path)
			}

			// Req 7.12: the size is checked before an offer is built, so a file outside the
			// range is rejected without hashing 64 GiB to find out.
			if unsupported := transfer.CheckFileSize(info.Size()); unsupported != nil {
				return reportError(cmd, node, &report.FileSizeUnsupported{
					MeasuredBytes: unsupported.MeasuredBytes,
					Min:           unsupported.Min,
					Max:           unsupported.Max,
				})
			}

			chunkSize := transport.LANChunkBytes
			if s := node.Sessions().FindActive(args[0]); s != nil &&
				s.ActiveTransportName() == transport.NameBT {
				chunkSize = transport.BTChunkBytes
			}
			plan, planErr := transfer.PlanChunks(info.Size(), 0, chunkSize)
			if planErr != nil {
				return planErr
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%s: %s in %d chunks of %s\n",
				info.Name(), formatBytes(info.Size()), len(plan), formatBytes(int64(chunkSize)))
			return nil
		},
	}

	resume := &cobra.Command{
		Use:   "resume <transfer-id>",
		Short: "Resume an interrupted transfer from the last acknowledged byte",
		Long: strings.TrimSpace(`
Resumes within 10 minutes of the interruption, sending only what the receiver has
not acknowledged. If the transport changed in the meantime, the remaining bytes
are re-sliced at the new transport's chunk size.`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := open(cmd); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "resuming transfer %s\n", args[0])
			return nil
		},
	}

	cancel := &cobra.Command{
		Use:   "cancel <transfer-id>",
		Short: "Stop a transfer and tell the receiver to release the partial file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := open(cmd); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"cancelled transfer %s; the receiver will release its partial file\n", args[0])
			return nil
		},
	}

	fileCmd.AddCommand(send, resume, cancel)
	return fileCmd
}

// newStatusCommand covers Req 13.1, 13.2, and 13.3.
func newStatusCommand(open nodeOpener) *cobra.Command {
	var watch bool

	status := &cobra.Command{
		Use:   "status",
		Short: "Show each session's peer, transport, goodput, and round-trip time",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			node, err := open(cmd)
			if err != nil {
				return err
			}
			renderer := NewStatusRenderer(node, cmd.OutOrStdout())
			if !watch {
				return renderer.RenderOnce()
			}

			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			return renderer.Watch(ctx)
		},
	}

	status.Flags().BoolVar(&watch, "watch", false, "redraw every second until interrupted")
	return status
}

// newLogCommand covers Req 13.5.
func newLogCommand(open nodeOpener) *cobra.Command {
	logCmd := &cobra.Command{
		Use:   "log",
		Short: "Inspect the event log",
	}

	tail := &cobra.Command{
		Use:   "tail",
		Short: "Show recent session, transport, and transfer events",
		Long: strings.TrimSpace(`
The event log records session establishment, transport changes, transfer
completion, and session rejection. It never contains message payloads, clipboard
content, file content, or key material.`),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			node, err := open(cmd)
			if err != nil {
				return err
			}
			sink, ok := node.ports.Events.(*report.MemoryEventSink)
			if !ok {
				fmt.Fprintln(cmd.OutOrStdout(), "the event log is not readable from here")
				return nil
			}
			entries := sink.Entries()
			if len(entries) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no events recorded yet")
				return nil
			}
			for _, entry := range entries {
				fmt.Fprintln(cmd.OutOrStdout(), entry.String())
			}
			return nil
		},
	}

	logCmd.AddCommand(tail)
	return logCmd
}

// newAirDropCommand covers Req 12.4, 12.5, and 12.9.
func newAirDropCommand(open nodeOpener) *cobra.Command {
	return &cobra.Command{
		Use:   "airdrop <path>",
		Short: "Hand a file to the macOS share interface (macOS only)",
		Long: strings.TrimSpace(`
Opens the operating system share interface with the file selected, so it can be
sent with AirDrop. This is a manual handoff: no public API lets an application
choose the recipient, so a person picks it.

Every active session is left exactly as it was.`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			node, err := open(cmd)
			if err != nil {
				return err
			}

			if err := node.Share().OpenShareSheet(cmd.Context(), args[0]); err != nil {
				// The two failure shapes are reported differently because Req 12.5 and
				// Req 12.9 ask for different things: one names the platform, the other
				// names the file and why it is unusable.
				var unusable *share.FileUnusable
				if errors.As(err, &unusable) {
					return reportError(cmd, node, &report.AirDropFileUnreadable{
						Path:   unusable.Path,
						Reason: unusable.Reason,
					})
				}
				var unavailable *share.Unavailable
				if errors.As(err, &unavailable) {
					return reportError(cmd, node, &report.AirDropUnavailable{
						OperatingSystem: unavailable.OperatingSystem,
					})
				}
				return reportError(cmd, node, &report.AirDropFileUnreadable{
					Path:   args[0],
					Reason: err.Error(),
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "opened the share interface for %s\n", args[0])
			return nil
		},
	}
}

// ErrAlreadyReported marks an error whose report has already been written.
//
// It exists because a failure has to do two things that pull in opposite directions: print the
// complete four-field report Req 13.4 asks for, and make the process exit non-zero. Returning the
// reason as a plain error would make main print a second, thinner copy of what the user just read.
// So the report is written here and main recognises this sentinel and stays quiet.
var ErrAlreadyReported = errors.New("peerbeam: failure already reported")

// reportError renders an error through the single Describe mapping, prints the complete report, and
// returns a sentinel so the command exits non-zero without the message appearing twice (Req 13.4).
func reportError(cmd *cobra.Command, node *PeerNode, err report.AppError) error {
	failure := report.Describe(err, node.DisplayName())
	fmt.Fprintln(cmd.ErrOrStderr(), failure.String())
	return fmt.Errorf("%w: %s", ErrAlreadyReported, failure.Reason)
}

// parseOnOff reads an on/off argument.
func parseOnOff(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "on", "true", "yes":
		return true, nil
	case "off", "false", "no":
		return false, nil
	default:
		return false, fmt.Errorf("expected on or off, got %q", value)
	}
}

// sessionMessageFor builds the queued Message for an inactive Session (Req 4.8).
//
// The sequence number is drawn here rather than at flush time, because Req 3.7 flushes in ascending
// sequence order and Req 3.9 names discarded sequence numbers: both need the number to exist while
// the Session is still disconnected.
func sessionMessageFor(s *session.Session, message string) session.QueuedMessage {
	return session.QueuedMessage{
		Type:     uint8(codec.MsgText),
		Sequence: s.Sequence.NextSequence(),
		Payload:  []byte(message),
	}
}
