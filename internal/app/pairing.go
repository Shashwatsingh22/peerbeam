package app

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/codec"
	"github.com/peerbeam/peerbeam/internal/core/crypto"
	"github.com/peerbeam/peerbeam/internal/core/report"
	"github.com/peerbeam/peerbeam/internal/core/transport"
	"github.com/peerbeam/peerbeam/internal/core/trust"
)

// The pairing exchange, over an open connection and before any key is established.
//
// It is the one piece the parent spec specified but never carried over the wire: trust.PairingService
// already derives the code, holds the attempt, and completes on mutual confirmation, but it takes the
// peer's public key as a parameter and nothing ever obtained one from a remote machine. This is that
// missing step (Req 9.1).
//
// Two frame types, both unencrypted like the key exchange, because they run before the keys exist.
//
// PairingOffer payload:
//
//	offset  size  field
//	  0      1    protocolVersion   rejected first if unsupported
//	  1      1    keyLength         Ed25519 is 32, but length-prefixed so the field is self-describing
//	  2      N    publicKey         long-term identity key
//	 2+N     2    nameLength        big-endian
//	 4+N     M    displayName       UTF-8, at most 64 characters
//
// PairingDecision payload:
//
//	offset  size  field
//	  0      1    decision          1 confirmed, 0 rejected; any other value is malformed
const (
	pairDecisionRejected  uint8 = 0
	pairDecisionConfirmed uint8 = 1
)

// PairConfirmer asks the local user to compare the verification code and decide. The interactive
// session supplies one that prompts; a test supplies one that answers from a script.
//
// It is handed the peer's fingerprint, the display name the peer offered, and the derived code, and
// blocks until the user decides or ctx is cancelled. Returning confirm=false is a rejection, which
// is a normal outcome and not an error; a non-nil error is a failure to obtain a decision at all,
// such as the input stream closing.
type PairConfirmer interface {
	ConfirmPairing(ctx context.Context, fingerprint, peerDisplayName, code string) (confirm bool, err error)
}

// PairConfirmerFunc adapts a function to a PairConfirmer.
type PairConfirmerFunc func(ctx context.Context, fingerprint, peerDisplayName, code string) (bool, error)

func (f PairConfirmerFunc) ConfirmPairing(ctx context.Context, fingerprint, peerDisplayName, code string) (bool, error) {
	return f(ctx, fingerprint, peerDisplayName, code)
}

// pairResult is what a completed exchange produced: the fingerprint that is now trusted, plus the
// peer's display name for the caller to use when it goes on to connect.
type pairResult struct {
	Fingerprint     string
	PeerDisplayName string
}

// runPairing drives the symmetric pairing exchange to completion over conn (Req 9).
//
// The sequence is the same on both sides, which is what lets one function serve initiator and
// responder without branching on role beyond who sends the first offer:
//
//  1. Send this node's PairingOffer; receive the peer's.
//  2. Derive the code locally from both public keys via BeginPairing. The code is never
//     transmitted (Req 9.2).
//  3. Ask the local user (Req 9.3, 9.9). Record the decision.
//  4. Send this node's PairingDecision; receive the peer's.
//  5. Complete only if both confirmed inside the window (Req 9.4); otherwise close and report
//     (Req 9.5, 9.6).
//
// The whole exchange runs under a deadline derived from the code's 120-second validity (Req 9.6):
// a confirmation that lands after the code has expired must not pair, and PairingService.resolve
// enforces that, but the deadline is what stops a peer that never replies from blocking forever.
//
// A key that contradicts one already stored for this fingerprint is reported as a key mismatch,
// distinctly from an untrusted peer (Req 9.7), by consulting the same Admit path the handshake uses.
func (n *PeerNode) runPairing(
	ctx context.Context,
	conn transport.TransportConnection,
	confirmer PairConfirmer,
) (*pairResult, report.AppError) {
	if failure := n.pairing.StoreFailure(); failure != nil {
		return nil, &report.TrustStoreFailed{Reason: failure.Reason}
	}

	deadline := n.clk.Now().Add(crypto.VerificationCodeValidity)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// 1. Offers. This node sends first regardless of role; the peer's runPairing does the same,
	// and the reads below tolerate the two crossing on the wire.
	if failure := n.writePairingOffer(conn); failure != nil {
		return nil, failure
	}
	offer, failure := n.readPairingOffer(ctx, conn, deadline)
	if failure != nil {
		return nil, failure
	}

	// 2. A contradicting key is a mismatch, not a new pairing (Req 9.7). Admit compares the
	// offered key against any stored one without touching the store.
	if decision := n.pairing.Admit(offer.fingerprint, offer.publicKey); decision.Kind() == trust.AdmitKeyMismatch {
		return nil, &report.PeerKeyMismatch{Fingerprint: offer.fingerprint}
	}

	// Derive the code locally. BeginPairing computes it from this node's key and the received
	// one; nothing puts it on the wire.
	attempt, err := n.pairing.BeginPairing(offer.publicKey, offer.displayName)
	if err != nil {
		return nil, &report.PairingFailed{Fingerprint: offer.fingerprint, Reason: err.Error()}
	}

	// 3. The local user compares the code (Req 9.3). An inbound exchange reaches here too, so the
	// user is always prompted rather than trust being accepted automatically (Req 9.9).
	confirmed, err := confirmer.ConfirmPairing(ctx, attempt.PeerFingerprint, offer.displayName, attempt.Code)
	if err != nil {
		n.pairing.ReportMismatch(attempt.PeerFingerprint)
		return nil, &report.PairingFailed{
			Fingerprint: attempt.PeerFingerprint,
			Reason:      "could not obtain a pairing decision: " + err.Error(),
		}
	}

	localDecision := pairDecisionConfirmed
	if !confirmed {
		localDecision = pairDecisionRejected
		n.pairing.ReportMismatch(attempt.PeerFingerprint)
	} else {
		n.pairing.ConfirmLocal(attempt.PeerFingerprint)
	}

	// 4. Exchange decisions. This node's goes out even on a local rejection, so the peer learns
	// the pairing is off rather than waiting out the window.
	if failure := n.writePairingDecision(conn, localDecision); failure != nil {
		return nil, failure
	}
	peerDecision, failure := n.readPairingDecision(ctx, conn, deadline)
	if failure != nil {
		return nil, failure
	}

	// A local rejection is the decisive one; report it as this side's mismatch (Req 9.5).
	if localDecision == pairDecisionRejected {
		return nil, &report.PairingFailed{
			Fingerprint: attempt.PeerFingerprint,
			Reason:      "the verification codes were reported as not matching",
		}
	}
	if peerDecision == pairDecisionRejected {
		// The peer said no. Drop this side's attempt so a stale confirmation cannot complete it.
		n.pairing.ReportMismatch(attempt.PeerFingerprint)
		return nil, &report.PairingFailed{
			Fingerprint: attempt.PeerFingerprint,
			Reason:      "the peer reported that the verification codes do not match",
		}
	}

	// 5. Both confirmed. Record the peer's confirmation, which completes the pairing if the
	// window has not closed (Req 9.4).
	outcome := n.pairing.ConfirmPeer(attempt.PeerFingerprint)
	switch outcome.Kind() {
	case trust.PairingPaired:
		return &pairResult{
			Fingerprint:     outcome.Paired.Fingerprint,
			PeerDisplayName: outcome.Paired.DisplayName,
		}, nil
	case trust.PairingFailed:
		return nil, &report.PairingFailed{
			Fingerprint: attempt.PeerFingerprint,
			Reason:      outcome.Failed.Reason,
		}
	default:
		// Pending here means only one side confirmed, which cannot happen once both decisions
		// have been exchanged and both were confirmations. Treat it as a failure rather than
		// pretend it paired.
		return nil, &report.PairingFailed{
			Fingerprint: attempt.PeerFingerprint,
			Reason:      "pairing did not complete after both confirmations",
		}
	}
}

// pairingOffer is a decoded PairingOffer.
type pairingOffer struct {
	publicKey   []byte
	displayName string
	fingerprint string
}

func (n *PeerNode) writePairingOffer(conn transport.TransportConnection) report.AppError {
	if len(n.identity.PublicKey) != trust.PublicKeyBytes {
		return &report.KeyStoreFailed{
			Step:   "read the local identity",
			Reason: "this node has no identity key, so it cannot pair",
		}
	}
	name := []byte(n.config.DisplayName)

	payload := make([]byte, 0, 4+len(n.identity.PublicKey)+len(name))
	payload = append(payload, ProtocolVersion)
	payload = append(payload, uint8(len(n.identity.PublicKey)))
	payload = append(payload, n.identity.PublicKey...)
	var nameLen [2]byte
	binary.BigEndian.PutUint16(nameLen[:], uint16(len(name)))
	payload = append(payload, nameLen[:]...)
	payload = append(payload, name...)

	return n.writePairingFrame(conn, codec.MsgPairingOffer, payload)
}

func (n *PeerNode) writePairingDecision(conn transport.TransportConnection, decision uint8) report.AppError {
	return n.writePairingFrame(conn, codec.MsgPairingDecision, []byte{decision})
}

// writePairingFrame encodes and sends one pairing frame, reusing the codec so the framing is
// identical to every other message on the wire.
func (n *PeerNode) writePairingFrame(conn transport.TransportConnection, kind codec.MessageType, payload []byte) report.AppError {
	encoded := codec.EncodeFrame(codec.Frame{
		ProtocolVersion: ProtocolVersion,
		Type:            uint8(kind),
		Sequence:        0, // pairing frames sit outside the Session's sequence space
		Payload:         payload,
	})
	if encoded.TooLarge != nil {
		return &report.PayloadTooLarge{
			Length:  encoded.TooLarge.PayloadLength,
			Maximum: encoded.TooLarge.Maximum,
		}
	}
	if err := conn.Write(encoded.Bytes); err != nil {
		return &report.PairingFailed{Reason: "sending a pairing frame failed: " + err.Error()}
	}
	return nil
}

func (n *PeerNode) readPairingOffer(
	ctx context.Context,
	conn transport.TransportConnection,
	deadline time.Time,
) (pairingOffer, report.AppError) {
	frame, failure := n.readPairingFrame(ctx, conn, codec.MsgPairingOffer, deadline)
	if failure != nil {
		return pairingOffer{}, failure
	}
	offer, err := parsePairingOffer(frame)
	if err != nil {
		return pairingOffer{}, &report.ProtocolViolation{
			MessageType: uint8(codec.MsgPairingOffer),
			Reason:      err.Error(),
		}
	}
	return offer, nil
}

func (n *PeerNode) readPairingDecision(
	ctx context.Context,
	conn transport.TransportConnection,
	deadline time.Time,
) (uint8, report.AppError) {
	frame, failure := n.readPairingFrame(ctx, conn, codec.MsgPairingDecision, deadline)
	if failure != nil {
		return 0, failure
	}
	if len(frame) != 1 || (frame[0] != pairDecisionConfirmed && frame[0] != pairDecisionRejected) {
		return 0, &report.ProtocolViolation{
			MessageType: uint8(codec.MsgPairingDecision),
			Reason:      "pairing decision payload is not a single 0 or 1 byte",
		}
	}
	return frame[0], nil
}

// readPairingFrame reads until one frame of the wanted type arrives, enforcing the deadline.
//
// Only pairing frames are accepted before trust exists: any other type is a protocol violation
// that closes the exchange, leaving all Session and trust state untouched (Req 9.8). An
// unrecognised code is skipped rather than treated as a violation, matching Req 8.8, so a newer
// peer's extra frame does not break an older one.
func (n *PeerNode) readPairingFrame(
	ctx context.Context,
	conn transport.TransportConnection,
	want codec.MessageType,
	deadline time.Time,
) ([]byte, report.AppError) {
	reader := codec.NewFrameReader(n.clk)
	buffer := make([]byte, 1024)

	for {
		if ctx.Err() != nil {
			return nil, n.pairingReadFailure(ctx, "the pairing exchange was cancelled or timed out")
		}
		if !n.clk.Now().Before(deadline) {
			return nil, &report.PairingFailed{
				Reason: fmt.Sprintf("pairing did not complete within %s",
					crypto.VerificationCodeValidity),
			}
		}

		read, err := conn.Read(buffer)
		if err != nil {
			return nil, &report.PairingFailed{Reason: "reading a pairing frame failed: " + err.Error()}
		}

		result := reader.Push(buffer[:read])
		if result.Err != nil {
			return nil, codecAppError(result.Err)
		}
		for _, frame := range result.Frames {
			kind, known := codec.MessageTypeFromCode(frame.Type)
			if !known {
				// Req 8.8: skip an unrecognised type and keep reading.
				continue
			}
			if kind == want {
				return frame.Payload, nil
			}
			if kind == codec.MsgPairingOffer || kind == codec.MsgPairingDecision {
				// A pairing frame out of order - a decision before we asked for it - is a
				// protocol problem, but of the pairing kind, so it is reported as such.
				return nil, &report.ProtocolViolation{
					MessageType: frame.Type,
					Reason:      "received a " + kind.String() + " while awaiting a " + want.String(),
				}
			}
			// Req 9.8: anything that is not a pairing frame must not be processed before trust
			// exists. The exchange closes and nothing is delivered.
			return nil, &report.ProtocolViolation{
				MessageType: frame.Type,
				Reason:      "received a " + kind.String() + " before trust was established",
			}
		}
	}
}

func (n *PeerNode) pairingReadFailure(ctx context.Context, deadlineReason string) report.AppError {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &report.PairingFailed{
			Reason: fmt.Sprintf("pairing did not complete within %s",
				crypto.VerificationCodeValidity),
		}
	}
	return &report.PairingFailed{Reason: deadlineReason}
}

// parsePairingOffer decodes a PairingOffer payload.
func parsePairingOffer(payload []byte) (pairingOffer, error) {
	if len(payload) < 4 {
		return pairingOffer{}, errors.New("pairing offer is too short")
	}
	version := payload[0]
	if version != ProtocolVersion {
		// Version is checked before anything else, so a peer on an incompatible version reads as
		// a version problem rather than a length one, matching how the header is validated.
		return pairingOffer{}, fmt.Errorf("pairing offer declares protocol version %d, want %d",
			version, ProtocolVersion)
	}

	keyLen := int(payload[1])
	if keyLen != trust.PublicKeyBytes {
		return pairingOffer{}, fmt.Errorf("pairing offer key length is %d, want %d",
			keyLen, trust.PublicKeyBytes)
	}
	const keyStart = 2
	if len(payload) < keyStart+keyLen+2 {
		return pairingOffer{}, errors.New("pairing offer is truncated before the display name length")
	}
	publicKey := append([]byte(nil), payload[keyStart:keyStart+keyLen]...)

	nameStart := keyStart + keyLen
	nameLen := int(binary.BigEndian.Uint16(payload[nameStart : nameStart+2]))
	nameBody := nameStart + 2
	if len(payload) != nameBody+nameLen {
		return pairingOffer{}, errors.New("pairing offer display name length does not match the payload")
	}
	displayName := string(payload[nameBody : nameBody+nameLen])

	if err := trust.CheckPublicKey(publicKey); err != nil {
		return pairingOffer{}, err
	}
	return pairingOffer{
		publicKey:   publicKey,
		displayName: displayName,
		fingerprint: trust.Fingerprint(publicKey),
	}, nil
}
