package report

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// AppError is the closed set of failure kinds that can reach a user.
//
// It is an interface with an unexported marker method, which is how a sealed hierarchy is
// approximated in Go: only types in this package can implement it, so the set of kinds
// Describe has to handle cannot be extended from outside. That, plus the panicking default
// in Describe and the exhaustive linter over the type switch, is what keeps Req 13.4's
// four-field contract true as kinds are added.
type AppError interface {
	error
	isAppError()
}

// TransportAttempt is one rung of a failed connection ladder, restated here so this package
// does not import internal/core/transport. Req 2.5 requires the report to name each
// attempted Transport in order with its reason.
type TransportAttempt struct {
	TransportName string
	Reason        string
}

// The error kinds. Each carries only what its report needs: names, counts, lengths, digests,
// sequence numbers. None carries payload bytes, which is what makes Property 37 hold by
// construction rather than by review.

// CodecUnsupportedVersion is a frame declaring a protocol version this build does not accept
// (Req 8.6).
type CodecUnsupportedVersion struct {
	Declared uint8
	Accepted uint8
}

func (e *CodecUnsupportedVersion) isAppError() {}
func (e *CodecUnsupportedVersion) Error() string {
	return fmt.Sprintf("unsupported protocol version %d (this build accepts %d)",
		e.Declared, e.Accepted)
}

// CodecFramingMismatch is a declared payload length that does not match the bytes received
// (Req 8.5).
type CodecFramingMismatch struct {
	DeclaredLength int
	ReceivedLength int
}

func (e *CodecFramingMismatch) isAppError() {}
func (e *CodecFramingMismatch) Error() string {
	return fmt.Sprintf("frame declared %d payload bytes but %d arrived",
		e.DeclaredLength, e.ReceivedLength)
}

// PayloadTooLarge is a payload over the frame limit (Req 8.10).
type PayloadTooLarge struct {
	Length  int
	Maximum int
}

func (e *PayloadTooLarge) isAppError() {}
func (e *PayloadTooLarge) Error() string {
	return fmt.Sprintf("payload of %d bytes exceeds the %d-byte maximum", e.Length, e.Maximum)
}

// NoCandidateTransport is a Session request for a Peer visible on nothing (Req 2.6).
type NoCandidateTransport struct{}

func (e *NoCandidateTransport) isAppError() {}
func (e *NoCandidateTransport) Error() string {
	return "no transport is available for this peer"
}

// LadderAllFailed is every candidate Transport failing to connect (Req 2.5).
type LadderAllFailed struct {
	Attempts []TransportAttempt
}

func (e *LadderAllFailed) isAppError() {}
func (e *LadderAllFailed) Error() string {
	return "every candidate transport failed: " + joinAttempts(e.Attempts)
}

// SwitchFailed is a Transport switch that did not complete in time (Req 2.9).
type SwitchFailed struct {
	FromTransport string
	ToTransport   string
	Reason        string
}

func (e *SwitchFailed) isAppError() {}
func (e *SwitchFailed) Error() string {
	return fmt.Sprintf("switch from %s to %s failed: %s",
		e.FromTransport, e.ToTransport, e.Reason)
}

// SessionLimitReached is a ninth concurrent Session (Req 4.9).
type SessionLimitReached struct {
	Limit int
}

func (e *SessionLimitReached) isAppError() {}
func (e *SessionLimitReached) Error() string {
	return fmt.Sprintf("the concurrent session limit of %d is reached", e.Limit)
}

// DeliveryNotAcknowledged is a Message that went unacknowledged inside its window (Req 4.5).
type DeliveryNotAcknowledged struct {
	Sequence     uint64
	WindowSecond int
}

func (e *DeliveryNotAcknowledged) isAppError() {}
func (e *DeliveryNotAcknowledged) Error() string {
	return fmt.Sprintf("message %d was not acknowledged within %d seconds",
		e.Sequence, e.WindowSecond)
}

// TextOutOfRange is a text submission outside the accepted size (Req 5.8).
type TextOutOfRange struct {
	ActualBytes int
	Min, Max    int
}

func (e *TextOutOfRange) isAppError() {}
func (e *TextOutOfRange) Error() string {
	return fmt.Sprintf("text is %d bytes; the accepted range is %d..%d bytes",
		e.ActualBytes, e.Min, e.Max)
}

// TextInvalidUTF8 is a received text payload that is not well-formed UTF-8 (Req 5.6).
type TextInvalidUTF8 struct {
	Sequence uint64
}

func (e *TextInvalidUTF8) isAppError() {}
func (e *TextInvalidUTF8) Error() string {
	return fmt.Sprintf("message %d is not valid UTF-8", e.Sequence)
}

// ClipboardUnsupportedContent is a send from a clipboard holding no text (Req 6.7).
type ClipboardUnsupportedContent struct{}

func (e *ClipboardUnsupportedContent) isAppError() {}
func (e *ClipboardUnsupportedContent) Error() string {
	return "the clipboard holds no text content to send"
}

// ClipboardTooLarge is clipboard content over the limit (Req 6.11).
type ClipboardTooLarge struct {
	ActualBytes int
	Maximum     int
}

func (e *ClipboardTooLarge) isAppError() {}
func (e *ClipboardTooLarge) Error() string {
	return fmt.Sprintf("clipboard content is %d bytes, over the %d-byte limit",
		e.ActualBytes, e.Maximum)
}

// ClipboardRejected is a received clipboard Message refused on its payload (Req 6.10).
type ClipboardRejected struct {
	Sequence uint64
	Reason   string
}

func (e *ClipboardRejected) isAppError() {}
func (e *ClipboardRejected) Error() string {
	return fmt.Sprintf("clipboard message %d rejected: %s", e.Sequence, e.Reason)
}

// FileSizeUnsupported is a Transfer for a file outside the accepted range (Req 7.12).
type FileSizeUnsupported struct {
	MeasuredBytes int64
	Min, Max      int64
}

func (e *FileSizeUnsupported) isAppError() {}
func (e *FileSizeUnsupported) Error() string {
	return fmt.Sprintf("file is %d bytes; the accepted range is %d..%d bytes",
		e.MeasuredBytes, e.Min, e.Max)
}

// TransferOfferRejected is an offer declined or timed out (Req 7.11).
type TransferOfferRejected struct {
	TransferId string
	FileName   string
	Reason     string
}

func (e *TransferOfferRejected) isAppError() {}
func (e *TransferOfferRejected) Error() string {
	return fmt.Sprintf("transfer %s of %s did not start: %s",
		e.TransferId, e.FileName, e.Reason)
}

// TransferIntegrityMismatch is an assembled Transfer whose digest differs from the offer
// (Req 7.5, 7.6).
type TransferIntegrityMismatch struct {
	TransferId string
	FileName   string
	Offered    []byte
	Computed   []byte
	// RetainedLocation is set only when the corrupt content could not be discarded
	// (Req 7.6).
	RetainedLocation string
}

func (e *TransferIntegrityMismatch) isAppError() {}
func (e *TransferIntegrityMismatch) Error() string {
	base := fmt.Sprintf("transfer %s of %s failed its integrity check: offered SHA-256 %s, computed %s",
		e.TransferId, e.FileName, hex.EncodeToString(e.Offered), hex.EncodeToString(e.Computed))
	if e.RetainedLocation != "" {
		return base + "; the partial content was retained at " + e.RetainedLocation
	}
	return base + "; the assembled content was discarded"
}

// TransferResendsExhausted is a Chunk that outlived its resend ceiling (Req 7.13).
type TransferResendsExhausted struct {
	TransferId string
	ChunkIndex int
	Attempts   int
}

func (e *TransferResendsExhausted) isAppError() {}
func (e *TransferResendsExhausted) Error() string {
	return fmt.Sprintf("transfer %s stopped: chunk %d went unacknowledged after %d resend attempts",
		e.TransferId, e.ChunkIndex, e.Attempts)
}

// PairingFailed is an abandoned pairing attempt (Req 9.5).
type PairingFailed struct {
	Fingerprint string
	Reason      string
}

func (e *PairingFailed) isAppError() {}
func (e *PairingFailed) Error() string {
	return fmt.Sprintf("pairing with %s failed: %s", e.Fingerprint, e.Reason)
}

// PeerNotTrusted is a Session request from an unpaired Peer (Req 9.6).
type PeerNotTrusted struct {
	Fingerprint string
}

func (e *PeerNotTrusted) isAppError() {}
func (e *PeerNotTrusted) Error() string {
	return fmt.Sprintf("peer %s is not trusted", e.Fingerprint)
}

// PeerKeyMismatch is a Trusted_Peer presenting a different key (Req 9.7).
type PeerKeyMismatch struct {
	Fingerprint string
}

func (e *PeerKeyMismatch) isAppError() {}
func (e *PeerKeyMismatch) Error() string {
	return fmt.Sprintf("peer %s presented a public key that differs from the stored key",
		e.Fingerprint)
}

// KeyStoreFailed is an identity that could not be created or secured (Req 9.2).
type KeyStoreFailed struct {
	Step   string
	Reason string
}

func (e *KeyStoreFailed) isAppError() {}
func (e *KeyStoreFailed) Error() string {
	return fmt.Sprintf("key store %s failed: %s", e.Step, e.Reason)
}

// TrustStoreFailed is a trust store that could not be read or failed its integrity check
// (Req 9.11).
type TrustStoreFailed struct {
	Reason string
}

func (e *TrustStoreFailed) isAppError() {}
func (e *TrustStoreFailed) Error() string {
	return "trust store failed its integrity check: " + e.Reason
}

// HandshakeFailed is a key exchange that did not complete (Req 10.8).
type HandshakeFailed struct {
	Step               string
	AttemptedTransport string
	Reason             string
}

func (e *HandshakeFailed) isAppError() {}
func (e *HandshakeFailed) Error() string {
	return fmt.Sprintf("key exchange failed at %s on %s: %s",
		e.Step, e.AttemptedTransport, e.Reason)
}

// AuthenticationFailed is a Message whose authentication tag did not verify (Req 10.7).
type AuthenticationFailed struct {
	SessionId string
	Sequence  uint64
}

func (e *AuthenticationFailed) isAppError() {}
func (e *AuthenticationFailed) Error() string {
	return fmt.Sprintf("message %d on session %s failed its authentication tag check",
		e.Sequence, e.SessionId)
}

// ProtocolViolation is traffic arriving before the handshake completed (Req 10.9).
type ProtocolViolation struct {
	MessageType uint8
	Reason      string
}

func (e *ProtocolViolation) isAppError() {}
func (e *ProtocolViolation) Error() string {
	return fmt.Sprintf("protocol violation (message type %d): %s", e.MessageType, e.Reason)
}

// QueueLimitReached is an outbound submission over the retention budget (Req 3.10).
type QueueLimitReached struct {
	LimitBytes int64
}

func (e *QueueLimitReached) isAppError() {}
func (e *QueueLimitReached) Error() string {
	return fmt.Sprintf("the retained queue limit of %d bytes is reached", e.LimitBytes)
}

// QueueDiscarded is retained payload dropped after the retention window (Req 3.9).
type QueueDiscarded struct {
	Sequences []uint64
}

func (e *QueueDiscarded) isAppError() {}
func (e *QueueDiscarded) Error() string {
	parts := make([]string, 0, len(e.Sequences))
	for _, s := range e.Sequences {
		parts = append(parts, fmt.Sprint(s))
	}
	return "queued messages were discarded after the retention window: " + strings.Join(parts, ", ")
}

// ManualPeerRejected is an invalid manual Peer entry (Req 1.10).
type ManualPeerRejected struct {
	Field  string // "address" or "port"
	Reason string
}

func (e *ManualPeerRejected) isAppError() {}
func (e *ManualPeerRejected) Error() string {
	return fmt.Sprintf("manual peer entry rejected: %s %s", e.Field, e.Reason)
}

// AnnouncementMalformed is a discovery announcement that failed validation (Req 1.11).
type AnnouncementMalformed struct {
	Reasons []string
}

func (e *AnnouncementMalformed) isAppError() {}
func (e *AnnouncementMalformed) Error() string {
	return "announcement discarded: " + strings.Join(e.Reasons, "; ")
}

// AirDropUnavailable is a share-sheet handoff on a platform that has none (Req 12.5).
type AirDropUnavailable struct {
	OperatingSystem string
}

func (e *AirDropUnavailable) isAppError() {}
func (e *AirDropUnavailable) Error() string {
	return "AirDrop handoff is available on macOS only, not on " + e.OperatingSystem
}

// AirDropFileUnreadable is a share-sheet handoff for a file that cannot be read (Req 12.9).
type AirDropFileUnreadable struct {
	Path   string
	Reason string
}

func (e *AirDropFileUnreadable) isAppError() {}
func (e *AirDropFileUnreadable) Error() string {
	return fmt.Sprintf("cannot hand off %s: %s", e.Path, e.Reason)
}

// TransportUnavailable is a Transport the platform cannot provide (Req 12.3, 12.8).
type TransportUnavailable struct {
	TransportName string
	Reason        string
}

func (e *TransportUnavailable) isAppError() {}
func (e *TransportUnavailable) Error() string {
	return fmt.Sprintf("%s is unavailable: %s", e.TransportName, e.Reason)
}

// LogWriteFailed is an event log entry that could not be written (Req 13.7).
type LogWriteFailed struct {
	EventType EventType
	Reason    string
}

func (e *LogWriteFailed) isAppError() {}
func (e *LogWriteFailed) Error() string {
	return fmt.Sprintf("could not write a %s event to the log: %s", e.EventType, e.Reason)
}

// describeUnhandled is what Describe does with a kind it has no branch for. It is a variable
// so tests can make it panic and production can make it degrade: a missing branch is a bug,
// but it is not a bug worth taking down a node holding eight sessions for.
//
// The panic under test, plus the exhaustive linter over the AppError implementations, is what
// stands in for a compiler-checked exhaustive switch. Both are needed: the linter catches an
// added kind at build time, and the panic catches one that slipped past it.
var describeUnhandled = func(err AppError, peerDisplayName string) Failure {
	return Failure{
		Operation:       "handle error",
		PeerDisplayName: PeerName(peerDisplayName, ""),
		Reason:          fmt.Sprintf("unhandled error kind %T: %s", err, err.Error()),
		Remediation:     "report this as a bug, including the error kind above",
	}
}

// Describe is the single place every user-visible failure passes through (Req 13.4).
//
// One function, one contract: every AppError kind yields a Failure with all four fields
// non-empty. Concentrating it here is what makes that checkable - Property 40 enumerates the
// kinds and asserts completeness - whereas building failures at each call site would give
// every site its own chance to omit the remediation.
//
// Remediation strings name a user action, not an internal state. "Check that both machines
// are on the same network" is actionable; "connection failed" is not, which is why the
// requirement asks for the former.
func Describe(err AppError, peerDisplayName string) Failure {
	peer := PeerName(peerDisplayName, "")

	switch e := err.(type) {
	case *CodecUnsupportedVersion:
		return Failure{
			Operation:       "receive message",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "update the older machine so both run the same peerbeam version",
		}

	case *CodecFramingMismatch:
		return Failure{
			Operation:       "receive message",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "retry the send; if it keeps happening, check for a flaky link between the machines",
		}

	case *PayloadTooLarge:
		return Failure{
			Operation:       "send message",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "split the content into smaller pieces and send them separately",
		}

	case *NoCandidateTransport:
		return Failure{
			Operation:       "open session",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "put both machines on the same network, or bring them within Bluetooth range",
		}

	case *LadderAllFailed:
		return Failure{
			Operation:       "open session",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "check that both machines are on the same network, or move within Bluetooth range",
		}

	case *SwitchFailed:
		return Failure{
			Operation:       "switch transport",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "no action needed; the session stayed on its current transport, so retry later or pin the transport you want",
		}

	case *SessionLimitReached:
		return Failure{
			Operation:       "open session",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     fmt.Sprintf("disconnect a session with `peerbeam disconnect <fingerprint>` to free one of the %d slots", e.Limit),
		}

	case *DeliveryNotAcknowledged:
		return Failure{
			Operation:       "deliver message",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "check that the other machine is awake and still in range, then send again",
		}

	case *TextOutOfRange:
		return Failure{
			Operation:       "send text",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     fmt.Sprintf("shorten the text to at most %d bytes, or send it as a file instead", e.Max),
		}

	case *TextInvalidUTF8:
		return Failure{
			Operation:       "receive text",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "ask the sender to resend the text; the session is still active",
		}

	case *ClipboardUnsupportedContent:
		return Failure{
			Operation:       "send clipboard",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "copy some text and try again; images and files are not supported",
		}

	case *ClipboardTooLarge:
		return Failure{
			Operation:       "send clipboard",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "send the content as a file with `peerbeam file send` instead",
		}

	case *ClipboardRejected:
		return Failure{
			Operation:       "apply clipboard",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "ask the sender to resend; your clipboard was left unchanged",
		}

	case *FileSizeUnsupported:
		return Failure{
			Operation:       "send file",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "check that the file is not empty and is under 64 GiB, then try again",
		}

	case *TransferOfferRejected:
		return Failure{
			Operation:       "send file",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "ask the other machine to accept the transfer, then send it again",
		}

	case *TransferIntegrityMismatch:
		remediation := "ask the sender to retry the transfer"
		if e.RetainedLocation != "" {
			remediation = "ask the sender to retry the transfer, and delete the partial file at " +
				e.RetainedLocation
		}
		return Failure{
			Operation:       "receive file " + e.FileName,
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     remediation,
		}

	case *TransferResendsExhausted:
		return Failure{
			Operation:       "send file",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "move the machines closer or reconnect, then resume within 10 minutes with `peerbeam file resume`",
		}

	case *PairingFailed:
		return Failure{
			Operation:       "pair with peer",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "start pairing again and confirm the same 6-digit code on both machines within 2 minutes",
		}

	case *PeerNotTrusted:
		return Failure{
			Operation:       "open session",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     fmt.Sprintf("run `peerbeam pair %s` on both machines to trust this peer", e.Fingerprint),
		}

	case *PeerKeyMismatch:
		return Failure{
			Operation:       "open session",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     fmt.Sprintf("if the peer was reinstalled, remove it with `peerbeam trust remove %s` and pair again; otherwise treat this as an impersonation attempt", e.Fingerprint),
		}

	case *KeyStoreFailed:
		return Failure{
			Operation:       "set up identity key",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "check that ~/.peerbeam is writable and that identity.key is readable only by you, then restart",
		}

	case *TrustStoreFailed:
		return Failure{
			Operation:       "load trust store",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "restore ~/.peerbeam/trusted.json from a backup, or delete it and pair your machines again",
		}

	case *HandshakeFailed:
		return Failure{
			Operation:       "establish session",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "retry the connection; if it keeps failing, confirm both machines still trust each other with `peerbeam trust list`",
		}

	case *AuthenticationFailed:
		return Failure{
			Operation:       "receive message",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "reconnect to the peer; if this repeats, treat the network as hostile and check for interference",
		}

	case *ProtocolViolation:
		return Failure{
			Operation:       "establish session",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "confirm the other machine runs peerbeam and is on the same version, then reconnect",
		}

	case *QueueLimitReached:
		return Failure{
			Operation:       "queue message",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "reconnect the peer so the queue drains, or send less while it is offline",
		}

	case *QueueDiscarded:
		return Failure{
			Operation:       "deliver queued messages",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "reconnect the peer and send the affected messages again",
		}

	case *ManualPeerRejected:
		return Failure{
			Operation:       "add peer",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "re-enter the address as a host and a port between 1 and 65535",
		}

	case *AnnouncementMalformed:
		return Failure{
			Operation:       "read peer announcement",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "no action needed unless a peer is missing from `peerbeam peers`; then check that it runs the same version",
		}

	case *AirDropUnavailable:
		return Failure{
			Operation:       "hand off to AirDrop",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "send the file with `peerbeam file send` instead",
		}

	case *AirDropFileUnreadable:
		return Failure{
			Operation:       "hand off to AirDrop",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "check that the path is correct and the file is readable, then try again",
		}

	case *TransportUnavailable:
		return Failure{
			Operation:       "start transport",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "no action needed if the other transport works; otherwise check the adapter is enabled on this machine",
		}

	case *LogWriteFailed:
		return Failure{
			Operation:       "write event log entry",
			PeerDisplayName: peer,
			Reason:          e.Error(),
			Remediation:     "check that the log directory exists and is writable; sessions are unaffected",
		}

	default:
		return describeUnhandled(err, peerDisplayName)
	}
}

// AllAppErrorKinds returns one instance of every AppError kind, populated enough to render.
//
// It exists so Property 40 can enumerate the closed set and assert Describe handles each one
// completely. Keeping the list next to Describe means adding a kind without adding a branch
// fails the property test, which is the second half of the exhaustiveness guard.
func AllAppErrorKinds() []AppError {
	return []AppError{
		&CodecUnsupportedVersion{Declared: 2, Accepted: 1},
		&CodecFramingMismatch{DeclaredLength: 100, ReceivedLength: 40},
		&PayloadTooLarge{Length: 2_000_000, Maximum: 1_048_576},
		&NoCandidateTransport{},
		&LadderAllFailed{Attempts: []TransportAttempt{
			{TransportName: "LAN_Transport", Reason: "did not connect within 3s"},
			{TransportName: "BT_Transport", Reason: "no endpoint for peer on this medium"},
		}},
		&SwitchFailed{FromTransport: "BT_Transport", ToTransport: "LAN_Transport", Reason: "timed out"},
		&SessionLimitReached{Limit: 8},
		&DeliveryNotAcknowledged{Sequence: 12, WindowSecond: 10},
		&TextOutOfRange{ActualBytes: 0, Min: 1, Max: 65_536},
		&TextInvalidUTF8{Sequence: 3},
		&ClipboardUnsupportedContent{},
		&ClipboardTooLarge{ActualBytes: 2_000_000, Maximum: 1_048_576},
		&ClipboardRejected{Sequence: 9, Reason: "payload is not valid UTF-8"},
		&FileSizeUnsupported{MeasuredBytes: 0, Min: 1, Max: 68_719_476_736},
		&TransferOfferRejected{TransferId: "tx1", FileName: "f.bin", Reason: "peer declined the offer"},
		&TransferIntegrityMismatch{
			TransferId: "tx2", FileName: "f.bin",
			Offered:  []byte{0x01, 0x02},
			Computed: []byte{0x03, 0x04},
		},
		&TransferIntegrityMismatch{
			TransferId: "tx3", FileName: "f.bin",
			Offered:          []byte{0x01},
			Computed:         []byte{0x02},
			RetainedLocation: "/tmp/peerbeam/partial-tx3",
		},
		&TransferResendsExhausted{TransferId: "tx4", ChunkIndex: 7, Attempts: 5},
		&PairingFailed{Fingerprint: "abc", Reason: "codes did not match"},
		&PeerNotTrusted{Fingerprint: "abc"},
		&PeerKeyMismatch{Fingerprint: "abc"},
		&KeyStoreFailed{Step: "permissions", Reason: "operation not permitted"},
		&TrustStoreFailed{Reason: "integrity tag mismatch"},
		&HandshakeFailed{Step: "signature check", AttemptedTransport: "LAN_Transport", Reason: "did not verify"},
		&AuthenticationFailed{SessionId: "s1", Sequence: 4},
		&ProtocolViolation{MessageType: 9, Reason: "traffic before the key exchange completed"},
		&QueueLimitReached{LimitBytes: 67_108_864},
		&QueueDiscarded{Sequences: []uint64{1, 2, 3}},
		&ManualPeerRejected{Field: "port", Reason: "is outside 1..65535"},
		&AnnouncementMalformed{Reasons: []string{"port is missing"}},
		&AirDropUnavailable{OperatingSystem: "linux"},
		&AirDropFileUnreadable{Path: "/tmp/x", Reason: "permission denied"},
		&TransportUnavailable{TransportName: "BT_Transport", Reason: "no bluetooth bridge is available"},
		&LogWriteFailed{EventType: EventSessionEstablished, Reason: "disk full"},
	}
}

func joinAttempts(attempts []TransportAttempt) string {
	parts := make([]string, 0, len(attempts))
	for _, a := range attempts {
		parts = append(parts, a.TransportName+": "+a.Reason)
	}
	return strings.Join(parts, "; ")
}
