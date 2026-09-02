package app

import (
	"context"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/report"
)

// StatusRenderer draws the per-Session status view and refreshes it once a second (Req 13.1, 13.2).
type StatusRenderer struct {
	node *PeerNode
	out  io.Writer
}

// NewStatusRenderer returns a renderer writing to out.
func NewStatusRenderer(node *PeerNode, out io.Writer) *StatusRenderer {
	return &StatusRenderer{node: node, out: out}
}

// RenderOnce writes one frame of the status view.
//
// Columns are aligned with a tabwriter rather than fixed-width padding, because a peer display name
// may be 64 multi-byte characters and a fixed width would either truncate it or leave the numeric
// columns ragged.
func (r *StatusRenderer) RenderOnce() error {
	lines := r.node.StatusLines()

	writer := tabwriter.NewWriter(r.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "PEER\tTRANSPORT\tGOODPUT\tRTT")

	if len(lines) == 0 {
		fmt.Fprintln(writer, "(no sessions)\t\t\t")
	}
	for _, line := range lines {
		switch line.Kind() {
		case report.StatusReady:
			fmt.Fprintf(writer, "%s\t%s\t%s\t%d ms\n",
				line.Ready.PeerDisplayName,
				line.Ready.ActiveTransportName,
				formatRate(line.Ready.GoodputBytesPerSecond),
				line.Ready.RoundTripMillis)
		default:
			// Req 13.2: a pending Session shows no partial figures, so the three
			// measurement columns are blank rather than zeroed. A zero would read as a
			// measurement of zero, which is a different claim.
			fmt.Fprintf(writer, "%s\tpending\t\t\n", shortId(*line.Pending))
		}
	}

	if err := writer.Flush(); err != nil {
		return err
	}

	// Startup problems sit under the table rather than in it: Req 12.3 and 12.8 are about the
	// node, not about a Session, and putting them in a Session column would misattribute them.
	for _, failure := range r.node.StartupReport() {
		fmt.Fprintln(r.out, failure.String())
	}
	return nil
}

// Watch redraws until ctx is done (Req 13.1).
//
// The first frame is drawn immediately rather than after one tick, so `peerbeam status` shows
// something the moment it is run. Req 13.1 sets the refresh at one second or shorter, and
// report.StatusRefreshInterval is where that value lives.
func (r *StatusRenderer) Watch(ctx context.Context) error {
	if err := r.RenderOnce(); err != nil {
		return err
	}

	ticker := time.NewTicker(report.StatusRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			fmt.Fprintln(r.out)
			if err := r.RenderOnce(); err != nil {
				return err
			}
		}
	}
}

// formatRate renders bytes per second in the largest unit that keeps the number readable.
//
// Binary units, because every size bound in the requirements is binary: 40 MiB/s for LAN and 40
// KiB/s for Bluetooth (Req 2.1). Showing decimal megabytes against a binary target would make a
// transport that is exactly meeting its target look like it is missing it.
func formatRate(bytesPerSecond int64) string {
	switch {
	case bytesPerSecond >= 1<<20:
		return fmt.Sprintf("%.1f MiB/s", float64(bytesPerSecond)/(1<<20))
	case bytesPerSecond >= 1<<10:
		return fmt.Sprintf("%.1f KiB/s", float64(bytesPerSecond)/(1<<10))
	default:
		return fmt.Sprintf("%d B/s", bytesPerSecond)
	}
}

// shortId trims a Session id for display. The full 32 hex characters are correct but unreadable in a
// table, and the first eight are enough to tell eight concurrent Sessions apart.
func shortId(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

// formatBytes renders a byte count for transfer progress.
func formatBytes(bytes int64) string {
	switch {
	case bytes >= 1<<30:
		return fmt.Sprintf("%.2f GiB", float64(bytes)/(1<<30))
	case bytes >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(bytes)/(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(bytes)/(1<<10))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// renderPeerTable draws the visible Peer list (Req 1.2).
//
// It shows every field Req 1.2 requires an entry to carry: the display name, the fingerprint, the
// declared protocol version, whether this build supports it, and each medium the peer was seen on.
func renderPeerTable(out io.Writer, node *PeerNode) error {
	peers := node.Registry().Visible()

	writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "NAME\tFINGERPRINT\tVERSION\tMEDIA\tSOURCE")

	if len(peers) == 0 {
		fmt.Fprintln(writer, "(no peers visible)\t\t\t\t")
	}
	for _, peer := range peers {
		media := make([]string, 0, len(peer.Endpoints))
		for medium := range peer.Endpoints {
			media = append(media, medium.String())
		}
		// Sorted so repeated runs list media in the same order; map iteration would shuffle
		// it and make the output look like it changed when nothing did.
		sortStrings(media)

		version := fmt.Sprintf("%d", peer.DeclaredProtocolVersion)
		if !peer.ProtocolSupported {
			// An unsupported version is shown rather than hidden: Req 1.2 requires the
			// entry to state it, and a peer that is visible but unusable is exactly what a
			// user needs to see to know to upgrade.
			version += " (unsupported)"
		}
		source := "discovered"
		if peer.ManuallySupplied {
			source = "manual"
		}

		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n",
			peer.DisplayName, shortFingerprint(peer.Fingerprint), version,
			strings.Join(media, ","), source)
	}
	return writer.Flush()
}

// shortFingerprint trims a fingerprint for a table. The full 64 characters are shown by
// `peerbeam trust list`, where they are what a user compares.
func shortFingerprint(fingerprint string) string {
	if len(fingerprint) <= 16 {
		return fingerprint
	}
	return fingerprint[:16] + "..."
}

// sortStrings is an insertion sort, used because the slices are two or three elements and importing
// sort for that would be heavier than the loop.
func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
