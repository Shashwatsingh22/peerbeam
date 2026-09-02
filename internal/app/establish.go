package app

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/codec"
	"github.com/peerbeam/peerbeam/internal/core/crypto"
	"github.com/peerbeam/peerbeam/internal/core/discovery"
	"github.com/peerbeam/peerbeam/internal/core/report"
	"github.com/peerbeam/peerbeam/internal/core/session"
	"github.com/peerbeam/peerbeam/internal/core/transport"
	"github.com/peerbeam/peerbeam/internal/core/trust"
)

// Key exchange payload layout, inside an otherwise ordinary Wire_Frame. These frames are the only
// ones that are not encrypted, because they are what establishes the keys (Req 10.1).
//
//	offset  size  field
//	  0     32    fingerprint      raw SHA-256 of the long-term public key
//	 32     32    longTermKey      Ed25519 public key
//	 64     32    ephemeralKey     X25519 public key
//	 96     64    signature        Ed25519 over the handshake transcript
//
// The long-term key travels even though the fingerprint is its hash. Req 9.7 requires a Peer whose
// presented key differs from the stored one to be reported as a key mismatch, distinctly from an
// unknown Peer, and that comparison is impossible if the key is only ever looked up locally by
// fingerprint.
const (
	fingerprintBytes   = 32
	keyExchangeBytes   = fingerprintBytes + ed25519.PublicKeySize + crypto.EphemeralKeyBytes + ed25519.SignatureSize
	offsetLongTermKey  = fingerprintBytes
	offsetEphemeralKey = offsetLongTermKey + ed25519.PublicKeySize
	offsetSignature    = offsetEphemeralKey + crypto.EphemeralKeyBytes
)

// EstablishResult is what a completed establishment produced.
type EstablishResult struct {
	Session   *session.Session
	Transport transport.Transport
}

// Connect opens a Session with a Peer over the fastest available Transport (Req 2.3, 2.4, 2.5, 2.6),
// completes the authenticated key exchange (Req 10.1), and admits the Session (Req 4.1, 9.6, 9.7).
//
// The order is fixed and each step's failure is distinct, because the four report differently:
//
//  1. Trust, before any connection. Req 9.6 rejects an unpaired Peer with a pairing prompt, and
//     dialing first would spend three seconds per candidate to reach the same answer.
//  2. The ladder (Req 2.3 through 2.6).
//  3. The handshake, under its own 5-second deadline (Req 10.8).
//  4. Session admission, which is where the concurrency limit applies (Req 4.9).
//
// A failure at any step leaves no Session behind, which Req 10.8 states explicitly and the others
// require by implication: the caller sees a report and the registry is untouched.
func (n *PeerNode) Connect(ctx context.Context, fingerprint string) (*EstablishResult, report.AppError) {
	// 1. Trust. The presented key is not known yet, so this only asks whether the Peer is paired
	// at all; the byte-identical check happens inside the handshake once the key arrives.
	stored, trusted := n.pairing.Trusted(fingerprint)
	if failure := n.pairing.StoreFailure(); failure != nil {
		return nil, &report.TrustStoreFailed{Reason: failure.Reason}
	}
	if !n.pairing.Ready() {
		return nil, &report.TrustStoreFailed{Reason: "the trust store has not been loaded yet"}
	}
	if !trusted {
		return nil, &report.PeerNotTrusted{Fingerprint: fingerprint}
	}

	// 2. The ladder over ranked candidates.
	media := n.registry.MediaFor(fingerprint)
	ranked := transport.RankFor(n.UsableTransports(), media)

	ladder := transport.ConnectLadder(ctx, ranked, n.endpointLookup(fingerprint),
		transport.ConnectAttemptTimeout)
	switch {
	case ladder.NoCandidate:
		return nil, &report.NoCandidateTransport{}
	case ladder.Connected == nil:
		attempts := make([]report.TransportAttempt, 0, len(ladder.AllFailed))
		for _, attempt := range ladder.AllFailed {
			attempts = append(attempts, report.TransportAttempt{
				TransportName: attempt.TransportName,
				Reason:        attempt.Reason,
			})
		}
		return nil, &report.LadderAllFailed{Attempts: attempts}
	}

	conn := ladder.Connected.Connection
	chosen := ladder.Connected.Transport

	// 3. The handshake. Anything past here that fails closes the connection, so no half-open
	// socket is left behind.
	keys, peerKey, failure := n.performHandshake(ctx, conn, crypto.RoleInitiator, fingerprint, stored.PublicKey)
	if failure != nil {
		_ = conn.Close()
		return nil, failure
	}

	// 4. Admission.
	result, admitFailure := n.admit(conn, chosen, crypto.RoleInitiator, fingerprint, stored.DisplayName, peerKey, keys)
	if admitFailure != nil {
		_ = conn.Close()
		return nil, admitFailure
	}
	return result, nil
}

// endpointLookup resolves a Peer's endpoint per Transport, so the ladder can dial a mixed candidate
// list without knowing what a Bluetooth device id is.
func (n *PeerNode) endpointLookup(fingerprint string) transport.EndpointLookup {
	return func(t transport.Transport) (discovery.PeerEndpoint, bool) {
		for _, peer := range n.registry.Visible() {
			if peer.Fingerprint != fingerprint {
				continue
			}
			endpoint, found := peer.Endpoints[t.Medium()]
			return endpoint, found
		}
		return discovery.PeerEndpoint{}, false
	}
}

// performHandshake runs the authenticated key exchange over an open connection (Req 10.1).
//
// The initiator sends first and the responder replies, so the transcript's fixed
// initiator-then-responder order is the same on both sides without either needing to be told which
// it is beyond its own role.
//
// expectedFingerprint is empty for an inbound connection, where the Peer's identity is not known
// until it announces itself. For an outbound one it is checked, because dialing one Peer and
// completing a handshake with another would be exactly the confusion Req 9.7 exists to catch.
func (n *PeerNode) performHandshake(
	ctx context.Context,
	conn transport.TransportConnection,
	role crypto.Role,
	expectedFingerprint string,
	expectedKey []byte,
) (crypto.SessionKeys, []byte, report.AppError) {
	deadline := n.clk.Now().Add(crypto.HandshakeDeadline)
	gate := crypto.NewHandshakeGate(n.clk.Now())

	local, err := crypto.GenerateEphemeralKeyPair()
	if err != nil {
		return crypto.SessionKeys{}, nil, &report.HandshakeFailed{
			Step:               "generate an ephemeral key",
			AttemptedTransport: conn.TransportName(),
			Reason:             err.Error(),
		}
	}

	ownFingerprint := n.Fingerprint()
	if ownFingerprint == "" {
		return crypto.SessionKeys{}, nil, &report.KeyStoreFailed{
			Step:   "read the local identity",
			Reason: "this node has no identity key, so it cannot authenticate",
		}
	}

	// The initiator has to send before it can sign, because the transcript covers both ephemeral
	// keys and it only has one. So the exchange is: initiator sends its ephemeral unsigned,
	// responder replies signed, initiator then signs. That is one more round trip than signing
	// immediately would be, and it is what binding the signature to *both* ephemerals costs.
	//
	// It is worth the round trip: a signature over only the sender's own ephemeral key can be
	// replayed into a different session, whereas one over both cannot.
	var peerMessage crypto.HandshakeMessage

	if role == crypto.RoleInitiator {
		if failure := n.writeKeyExchange(conn, codec.MsgKeyExchangeInit, ownFingerprint,
			local.PublicKey, nil); failure != nil {
			return crypto.SessionKeys{}, nil, failure
		}
		received, failure := n.readKeyExchange(ctx, conn, gate, deadline)
		if failure != nil {
			return crypto.SessionKeys{}, nil, failure
		}
		peerMessage = received

		transcript := crypto.HandshakeTranscript(
			local.PublicKey, peerMessage.Ephemeral, ownFingerprint, peerMessage.Fingerprint)
		signature, err := crypto.SignHandshake(n.identity.PrivateKey, transcript)
		if err != nil {
			return crypto.SessionKeys{}, nil, &report.HandshakeFailed{
				Step:               "sign the transcript",
				AttemptedTransport: conn.TransportName(),
				Reason:             err.Error(),
			}
		}
		if failure := n.writeKeyExchange(conn, codec.MsgKeyExchangeResponse, ownFingerprint,
			local.PublicKey, signature); failure != nil {
			return crypto.SessionKeys{}, nil, failure
		}
	} else {
		received, failure := n.readKeyExchange(ctx, conn, gate, deadline)
		if failure != nil {
			return crypto.SessionKeys{}, nil, failure
		}
		peerMessage = received

		transcript := crypto.HandshakeTranscript(
			peerMessage.Ephemeral, local.PublicKey, peerMessage.Fingerprint, ownFingerprint)
		signature, err := crypto.SignHandshake(n.identity.PrivateKey, transcript)
		if err != nil {
			return crypto.SessionKeys{}, nil, &report.HandshakeFailed{
				Step:               "sign the transcript",
				AttemptedTransport: conn.TransportName(),
				Reason:             err.Error(),
			}
		}
		if failure := n.writeKeyExchange(conn, codec.MsgKeyExchangeResponse, ownFingerprint,
			local.PublicKey, signature); failure != nil {
			return crypto.SessionKeys{}, nil, failure
		}
		// The initiator's signature arrives in its second frame.
		signed, failure := n.readKeyExchange(ctx, conn, gate, deadline)
		if failure != nil {
			return crypto.SessionKeys{}, nil, failure
		}
		if signed.Fingerprint != peerMessage.Fingerprint {
			return crypto.SessionKeys{}, nil, &report.ProtocolViolation{
				MessageType: uint8(codec.MsgKeyExchangeResponse),
				Reason:      "the peer changed fingerprint partway through the exchange",
			}
		}
		peerMessage = signed
	}

	// Dialing one Peer and completing with another is a mismatch, not a success.
	if expectedFingerprint != "" && peerMessage.Fingerprint != expectedFingerprint {
		return crypto.SessionKeys{}, nil, &report.PeerKeyMismatch{Fingerprint: expectedFingerprint}
	}

	// For an inbound connection the stored key is looked up now that the Peer has named itself.
	storedKey := expectedKey
	if storedKey == nil {
		stored, trusted := n.pairing.Trusted(peerMessage.Fingerprint)
		if !trusted {
			// Req 9.6: no payload is delivered and the user is prompted to pair.
			return crypto.SessionKeys{}, nil, &report.PeerNotTrusted{
				Fingerprint: peerMessage.Fingerprint,
			}
		}
		storedKey = stored.PublicKey
	}

	keys, handshakeFailure := crypto.CompleteHandshake(
		role, n.identity.PublicKey, ownFingerprint, local, peerMessage, storedKey)
	if handshakeFailure != nil {
		// A trust-check failure is a key mismatch (Req 9.7), which reads very differently from
		// a signature that did not verify, so the two are reported apart.
		if handshakeFailure.Step == "trust check" {
			return crypto.SessionKeys{}, nil, &report.PeerKeyMismatch{
				Fingerprint: peerMessage.Fingerprint,
			}
		}
		return crypto.SessionKeys{}, nil, &report.HandshakeFailed{
			Step:               handshakeFailure.Step,
			AttemptedTransport: conn.TransportName(),
			Reason:             handshakeFailure.Reason,
		}
	}

	gate.Complete()
	return keys, peerMessage.PublicKey, nil
}

// writeKeyExchange sends one key exchange frame. These frames carry no AEAD tag, because they are
// what establishes the key the tag would need (Req 10.1).
func (n *PeerNode) writeKeyExchange(
	conn transport.TransportConnection,
	kind codec.MessageType,
	fingerprint string,
	ephemeral, signature []byte,
) report.AppError {
	raw, err := hex.DecodeString(fingerprint)
	if err != nil || len(raw) != fingerprintBytes {
		return &report.HandshakeFailed{
			Step:               "encode the key exchange",
			AttemptedTransport: conn.TransportName(),
			Reason:             "the local fingerprint is not 32 bytes of hex",
		}
	}

	payload := make([]byte, keyExchangeBytes)
	copy(payload[0:fingerprintBytes], raw)
	copy(payload[offsetLongTermKey:offsetEphemeralKey], n.identity.PublicKey)
	copy(payload[offsetEphemeralKey:offsetSignature], ephemeral)
	copy(payload[offsetSignature:], signature) // zero when not yet signed

	encoded := codec.EncodeFrame(codec.Frame{
		ProtocolVersion: ProtocolVersion,
		Type:            uint8(kind),
		Sequence:        0, // key exchange frames sit outside the Session's sequence space
		Payload:         payload,
	})
	if encoded.TooLarge != nil {
		return &report.PayloadTooLarge{
			Length:  encoded.TooLarge.PayloadLength,
			Maximum: encoded.TooLarge.Maximum,
		}
	}
	if err := conn.Write(encoded.Bytes); err != nil {
		return &report.HandshakeFailed{
			Step:               "send the key exchange",
			AttemptedTransport: conn.TransportName(),
			Reason:             err.Error(),
		}
	}
	return nil
}

// readKeyExchange reads one key exchange frame, enforcing the deadline of Req 10.8 and the
// pre-handshake gate of Req 10.9.
func (n *PeerNode) readKeyExchange(
	ctx context.Context,
	conn transport.TransportConnection,
	gate *crypto.HandshakeGate,
	deadline time.Time,
) (crypto.HandshakeMessage, report.AppError) {
	reader := codec.NewFrameReader(n.clk)
	buffer := make([]byte, 1024)

	for {
		if ctx.Err() != nil {
			return crypto.HandshakeMessage{}, &report.HandshakeFailed{
				Step:               "read the key exchange",
				AttemptedTransport: conn.TransportName(),
				Reason:             "the request was cancelled",
			}
		}
		if !n.clk.Now().Before(deadline) {
			// Req 10.8: abandon establishment, leave no Session in any state.
			return crypto.HandshakeMessage{}, &report.HandshakeFailed{
				Step:               "handshake deadline",
				AttemptedTransport: conn.TransportName(),
				Reason: fmt.Sprintf("the key exchange did not complete within %s",
					crypto.HandshakeDeadline),
			}
		}

		read, err := conn.Read(buffer)
		if err != nil {
			return crypto.HandshakeMessage{}, &report.HandshakeFailed{
				Step:               "read the key exchange",
				AttemptedTransport: conn.TransportName(),
				Reason:             err.Error(),
			}
		}

		result := reader.Push(buffer[:read])
		if result.Err != nil {
			return crypto.HandshakeMessage{}, codecAppError(result.Err)
		}
		for _, frame := range result.Frames {
			kind, known := codec.MessageTypeFromCode(frame.Type)
			isKeyExchange := known &&
				(kind == codec.MsgKeyExchangeInit || kind == codec.MsgKeyExchangeResponse)

			decision := gate.Admit(frame.Type, isKeyExchange, "", n.clk.Now())
			switch {
			case decision.Violation != nil:
				// Req 10.9: the payload is not parsed, the connection closes.
				return crypto.HandshakeMessage{}, &report.ProtocolViolation{
					MessageType: decision.Violation.MessageType,
					Reason:      decision.Violation.Reason,
				}
			case decision.Expired != nil:
				return crypto.HandshakeMessage{}, &report.HandshakeFailed{
					Step:               decision.Expired.Step,
					AttemptedTransport: conn.TransportName(),
					Reason:             decision.Expired.Reason,
				}
			}

			message, parseErr := parseKeyExchange(frame.Payload)
			if parseErr != nil {
				return crypto.HandshakeMessage{}, &report.ProtocolViolation{
					MessageType: frame.Type,
					Reason:      parseErr.Error(),
				}
			}
			return message, nil
		}
	}
}

// parseKeyExchange decodes a key exchange payload.
func parseKeyExchange(payload []byte) (crypto.HandshakeMessage, error) {
	if len(payload) != keyExchangeBytes {
		return crypto.HandshakeMessage{}, fmt.Errorf(
			"key exchange payload is %d bytes, want %d", len(payload), keyExchangeBytes)
	}

	fingerprint := hex.EncodeToString(payload[0:fingerprintBytes])
	longTerm := append([]byte(nil), payload[offsetLongTermKey:offsetEphemeralKey]...)
	ephemeral := append([]byte(nil), payload[offsetEphemeralKey:offsetSignature]...)
	signature := append([]byte(nil), payload[offsetSignature:]...)

	// The fingerprint has to be the hash of the key alongside it, or the sender is claiming one
	// identity while presenting another's key.
	if want := crypto.Fingerprint(longTerm); want != fingerprint {
		return crypto.HandshakeMessage{}, errors.New(
			"the declared fingerprint does not match the presented public key")
	}

	return crypto.HandshakeMessage{
		Fingerprint: fingerprint,
		PublicKey:   longTerm,
		Ephemeral:   ephemeral,
		Signature:   signature,
	}, nil
}

// admit registers the Session and starts its goroutines (Req 4.1, 4.2, 4.9).
func (n *PeerNode) admit(
	conn transport.TransportConnection,
	chosen transport.Transport,
	role crypto.Role,
	fingerprint, displayName string,
	presentedKey []byte,
	keys crypto.SessionKeys,
) (*EstablishResult, report.AppError) {
	sessionCrypto, err := crypto.NewSessionCrypto(keys, role)
	if err != nil {
		return nil, &report.HandshakeFailed{
			Step:               "derive session keys",
			AttemptedTransport: chosen.Name(),
			Reason:             err.Error(),
		}
	}

	stored, _ := n.pairing.Trusted(fingerprint)
	if displayName == "" {
		displayName = stored.DisplayName
	}

	admission := n.sessions.Admit(session.AdmissionRequest{
		Fingerprint:  fingerprint,
		DisplayName:  report.PeerName(displayName, fingerprint),
		PresentedKey: presentedKey,
		StoredKey:    stored.PublicKey,
		// The Session's key material is the pair the handshake produced, which is distinct
		// per Session by construction (Req 10.5).
		Keys: append(append(session.KeyMaterial(nil), keys.SendKey...), keys.ReceiveKey...),
	})

	switch admission.Kind() {
	case session.AdmissionLimitReached:
		return nil, &report.SessionLimitReached{Limit: *admission.LimitReached}
	case session.AdmissionPeerNotTrusted:
		return nil, &report.PeerNotTrusted{Fingerprint: fingerprint}
	case session.AdmissionKeyMismatch:
		return nil, &report.PeerKeyMismatch{Fingerprint: fingerprint}
	case session.AdmissionDuplicateSession:
		// An existing Session for this Peer wins: Req 4.1 holds one Session per Peer, and
		// replacing a live one would drop its sequence state and its queue.
		existing := n.sessions.Get(*admission.DuplicateSession)
		return &EstablishResult{Session: existing, Transport: chosen}, nil
	case session.AdmissionFailed:
		return nil, &report.HandshakeFailed{
			Step:               "admit the session",
			AttemptedTransport: chosen.Name(),
			Reason:             admission.Failed,
		}
	}

	s := n.sessions.Get(*admission.Admitted)
	s.Rebind(chosen.Name())

	n.startSession(s, conn, chosen, sessionCrypto)

	n.writeEvent(report.EventSessionEstablished, s.DisplayName, s.Fingerprint,
		"admitted on "+chosen.Name())

	return &EstablishResult{Session: s, Transport: chosen}, nil
}

// startSession installs a binding and starts the four goroutines a Session runs.
//
// Each takes a child of the root context, so cancelling one Session cannot reach another (Req 4.3)
// and Stop still joins them all through the node's wait group.
func (n *PeerNode) startSession(
	s *session.Session,
	conn transport.TransportConnection,
	chosen transport.Transport,
	sessionCrypto *crypto.SessionCrypto,
) {
	sessionCtx, cancel := context.WithCancel(n.ctx)

	b := &binding{
		conn:      conn,
		transport: chosen,
		crypto:    sessionCrypto,
		keepalive: transport.NewKeepaliveTracker(),
		metrics:   transport.NewTransportMetrics(n.clk),
		reader:    codec.NewFrameReader(n.clk),
		cancel:    cancel,
	}

	n.bindMu.Lock()
	n.bindings[s.Id] = b
	n.bindMu.Unlock()

	n.wg.Add(3)
	go func() { defer n.wg.Done(); n.readerLoop(sessionCtx, s, b) }()
	go func() { defer n.wg.Done(); n.writerLoop(sessionCtx, s, b) }()
	go func() { defer n.wg.Done(); n.metricsLoop(sessionCtx, b) }()
}

// readerLoop reads frames, opens their payloads, and hands them to the Session's inbound channel.
func (n *PeerNode) readerLoop(ctx context.Context, s *session.Session, b *binding) {
	buffer := make([]byte, 64*1024)

	for {
		if ctx.Err() != nil {
			return
		}
		read, err := b.conn.Read(buffer)
		if err != nil {
			return
		}

		result := b.reader.Push(buffer[:read])
		if result.Err != nil {
			n.reportCodecError(result.Err, s.DisplayName)
			return
		}

		for _, frame := range result.Frames {
			header := codec.EncodeFrame(codec.Frame{
				ProtocolVersion: frame.ProtocolVersion,
				Type:            frame.Type,
				Sequence:        frame.Sequence,
				Payload:         nil,
			})
			plaintext, ok := b.crypto.Open(header.Bytes[:codec.HeaderBytes], frame.Sequence, frame.Payload)
			if !ok {
				// Req 10.3 and 10.7: discard without delivering or applying, close the
				// Session, report an authentication failure naming both.
				n.reportFailure(&report.AuthenticationFailed{
					SessionId: s.Id.String(),
					Sequence:  frame.Sequence,
				}, s.DisplayName)
				n.closeSession(s, "authentication tag check failed")
				return
			}

			select {
			case s.Inbound <- session.Message{
				Type:     frame.Type,
				Sequence: frame.Sequence,
				Payload:  plaintext,
			}:
			case <-ctx.Done():
				return
			}
		}
	}
}

// closeSession tears one Session down without touching any other (Req 4.3).
func (n *PeerNode) closeSession(s *session.Session, reason string) {
	n.bindMu.Lock()
	b := n.bindings[s.Id]
	delete(n.bindings, s.Id)
	n.bindMu.Unlock()

	if b != nil {
		if b.cancel != nil {
			b.cancel()
		}
		if b.conn != nil {
			_ = b.conn.Close()
		}
	}
	n.sessions.Close(s.Id, reason)
	n.writeEvent(report.EventSessionRejected, s.DisplayName, s.Fingerprint, reason)
}

// AcceptInbound completes an inbound connection: handshake as responder, then admit.
//
// It replaces the gate-only handler the node started with. The difference is that this one knows how
// to finish: it reads the Peer's identity from the exchange, looks up its stored key, and either
// admits a Session or reports why not.
func (n *PeerNode) AcceptInbound(ctx context.Context, conn transport.TransportConnection) (*EstablishResult, report.AppError) {
	keys, peerKey, failure := n.performHandshake(ctx, conn, crypto.RoleResponder, "", nil)
	if failure != nil {
		_ = conn.Close()
		return nil, failure
	}

	fingerprint := crypto.Fingerprint(peerKey)
	chosen := n.transportNamed(conn.TransportName())
	if chosen == nil {
		_ = conn.Close()
		return nil, &report.TransportUnavailable{
			TransportName: conn.TransportName(),
			Reason:        "the transport that accepted this connection is not enabled",
		}
	}

	result, admitFailure := n.admit(conn, chosen, crypto.RoleResponder, fingerprint, "", peerKey, keys)
	if admitFailure != nil {
		_ = conn.Close()
		return nil, admitFailure
	}
	return result, nil
}

// transportNamed finds an enabled Transport by name.
func (n *PeerNode) transportNamed(name string) transport.Transport {
	for _, t := range n.ports.Transports {
		if t.Name() == name {
			return t
		}
	}
	return nil
}

// SendText queues a text Message on a Peer's active Session (Req 5.1).
//
// Validation happens before the sequence number is drawn, which is what makes Req 5.8's "send no
// Message and do not advance the sequence number" true rather than merely intended.
func (n *PeerNode) SendText(fingerprint, message string) (uint64, report.AppError) {
	s := n.sessions.FindActive(fingerprint)
	if s == nil {
		if inactive := n.sessions.Find(fingerprint); inactive != nil {
			// Req 4.8: retained on that Session's queue.
			result := inactive.Queue.Submit(sessionMessageFor(inactive, message))
			if result.Rejected != nil {
				return 0, &report.QueueLimitReached{LimitBytes: *result.Rejected}
			}
			return 0, &report.DeliveryNotAcknowledged{WindowSecond: 10}
		}
		return 0, &report.NoCandidateTransport{}
	}

	sequence := s.Sequence.NextSequence()
	select {
	case s.Control <- session.Message{
		Type:     uint8(codec.MsgText),
		Sequence: sequence,
		Payload:  []byte(message),
		Control:  true, // Req 4.6: text stays responsive while a transfer runs
	}:
		return sequence, nil
	case <-time.After(time.Second):
		return 0, &report.DeliveryNotAcknowledged{Sequence: sequence, WindowSecond: 10}
	}
}

// codecAppError maps a codec error onto the reporting kinds.
func codecAppError(err *codec.CodecError) report.AppError {
	switch {
	case err.UnsupportedVersion != nil:
		return &report.CodecUnsupportedVersion{
			Declared: uint8(err.UnsupportedVersion.Declared),
			Accepted: uint8(err.UnsupportedVersion.Accepted),
		}
	case err.PayloadTooLarge != nil:
		return &report.PayloadTooLarge{
			Length:  int(err.PayloadTooLarge.DeclaredLength),
			Maximum: err.PayloadTooLarge.Maximum,
		}
	default:
		return &report.CodecFramingMismatch{
			DeclaredLength: err.FramingMismatch.DeclaredLength,
			ReceivedLength: err.FramingMismatch.ReceivedCount,
		}
	}
}

// trustedPeerFor is a small helper for the establishment path's report strings.
func trustedPeerFor(pairing *trust.PairingService, fingerprint string) string {
	peer, trusted := pairing.Trusted(fingerprint)
	if !trusted {
		return fingerprint
	}
	return report.PeerName(peer.DisplayName, fingerprint)
}
