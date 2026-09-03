package app

import (
	"context"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/codec"
	"github.com/peerbeam/peerbeam/internal/core/crypto"
	"github.com/peerbeam/peerbeam/internal/core/report"
	"github.com/peerbeam/peerbeam/internal/core/transport"
)

// Inbound connection dispatch.
//
// A connection this node accepts carries one of two things as its first frame: a PairingOffer,
// meaning the peer is establishing first-contact trust, or a KeyExchangeInit, meaning it is opening
// a session with a peer it already trusts. The two are separate connections in this design - the
// dialing side does PairWith on one and Connect on another - so the accept side has to tell them
// apart and route each to the handler that expects it.
//
// It tells them apart by looking at the first frame's type without consuming it, so the handler it
// hands off to reads the same bytes from the start. peekFirstFrameType does exactly that: it reads
// the raw stream until one whole frame is buffered, records the type, and returns a connection that
// replays every byte it consumed. Neither runPairing nor AcceptInbound has to change - both read
// from the connection as before, and the replay is invisible to them.

// SetInboundConfirmer installs the confirmer the responder side of pairing uses when a peer dials
// this node to pair (Req 9.9). Without one, an inbound pairing offer is declined rather than
// trusted silently, which is the safe default: a node that has not been told how to ask its user
// must not accept trust on that user's behalf.
//
// It must be set before Start, for the same reason SetDisplay must: the accept loop reads it from
// its own goroutine once running.
func (n *PeerNode) SetInboundConfirmer(confirmer PairConfirmer) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.started {
		return errInboundConfirmerAfterStart
	}
	n.inboundConfirmer = confirmer
	return nil
}

// handleInbound routes one accepted connection to pairing or to the session handshake, by its first
// frame type. It runs on its own goroutine under the node's wait group, so Stop joins it.
func (n *PeerNode) handleInbound(conn transport.TransportConnection) {
	if failure := n.pairing.StoreFailure(); failure != nil {
		n.reportFailure(&report.TrustStoreFailed{Reason: failure.Reason}, n.config.DisplayName)
		_ = conn.Close()
		return
	}

	// Peek the first frame's type under the handshake deadline, so a peer that connects and then
	// says nothing cannot hold the goroutine open.
	deadline := n.clk.Now().Add(crypto.HandshakeDeadline)
	kind, replay, err := peekFirstFrameType(n.ctx, conn, n.clk, deadline)
	if err != nil {
		// A connection that never produced a whole frame is not worth a user-facing report: it
		// is noise on the listener. Closing it is enough.
		_ = conn.Close()
		return
	}

	if kind == codec.MsgPairingOffer {
		n.handleInboundPairing(replay)
		return
	}

	// Anything else is treated as a session handshake attempt, which AcceptInbound validates: a
	// non-key-exchange first frame is rejected there by the same gate that protects an outbound
	// handshake (Req 10.9).
	result, failure := n.AcceptInbound(n.ctx, replay)
	if failure != nil {
		n.reportFailure(failure, report.UnknownPeer)
		return
	}
	n.reportTransportChange(result.Session, "", result.Transport.Name(),
		report.ReasonHigherRankedAvailable)
}

// handleInboundPairing runs the responder half of the pairing exchange on a connection whose first
// frame is a PairingOffer.
func (n *PeerNode) handleInboundPairing(conn transport.TransportConnection) {
	defer conn.Close()

	n.mu.Lock()
	confirmer := n.inboundConfirmer
	n.mu.Unlock()
	if confirmer == nil {
		// Req 9.9: no way to ask the user, so decline rather than trust silently. The exchange
		// still runs so the peer learns the answer instead of timing out.
		confirmer = decliningConfirmer{}
	}

	result, failure := n.runPairing(n.ctx, conn, confirmer)
	if failure != nil {
		n.reportFailure(failure, report.UnknownPeer)
		return
	}
	// Trust is recorded; the peer will now open a separate connection for the session.
	n.writeEvent(report.EventSessionEstablished, result.PeerDisplayName, result.Fingerprint,
		"paired on an inbound connection")
}

// decliningConfirmer answers every pairing prompt with a rejection. It is the safe default for a
// node with no confirmer wired.
type decliningConfirmer struct{}

func (decliningConfirmer) ConfirmPairing(context.Context, string, string, string) (bool, error) {
	return false, nil
}

// peekableConn wraps a connection and replays a prefix of bytes that were already read from it
// before handing the rest through. It is how the first frame is inspected without being consumed:
// the peek reads raw bytes into the prefix, and the handler that follows reads the prefix first and
// then the live connection.
type peekableConn struct {
	transport.TransportConnection
	mu     sync.Mutex
	prefix []byte
}

func (c *peekableConn) Read(into []byte) (int, error) {
	c.mu.Lock()
	if len(c.prefix) > 0 {
		n := copy(into, c.prefix)
		c.prefix = c.prefix[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	return c.TransportConnection.Read(into)
}

// peekFirstFrameType reads the connection until one whole frame is buffered, returns that frame's
// type, and returns a connection that will replay every byte consumed so the next reader sees the
// stream from the start.
//
// It parses just enough to know a frame is complete: the 14-byte header gives the declared payload
// length, and the frame ends once that many payload bytes have arrived. It does not decode the
// payload - that is the handler's job - so a malformed body is still the handler's error to report,
// with the same wording as if the peek had not happened.
func peekFirstFrameType(
	ctx context.Context,
	conn transport.TransportConnection,
	clk interface{ Now() time.Time },
	deadline time.Time,
) (codec.MessageType, transport.TransportConnection, error) {
	var consumed []byte
	buffer := make([]byte, 1024)

	for {
		if ctx.Err() != nil {
			return 0, nil, ctx.Err()
		}
		if !clk.Now().Before(deadline) {
			return 0, nil, io.ErrUnexpectedEOF
		}

		// Enough for the header?
		if len(consumed) >= codec.HeaderBytes {
			declared := binary.BigEndian.Uint32(consumed[10:14])
			if uint32(len(consumed)) >= uint32(codec.HeaderBytes)+declared {
				// A whole frame is buffered. Its type is byte 1.
				replay := &peekableConn{TransportConnection: conn, prefix: consumed}
				return codec.MessageType(consumed[1]), replay, nil
			}
		}

		read, err := conn.Read(buffer)
		if read > 0 {
			consumed = append(consumed, buffer[:read]...)
		}
		if err != nil {
			return 0, nil, err
		}
	}
}
