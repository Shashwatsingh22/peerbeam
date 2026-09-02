package discovery

import (
	"fmt"
	"time"
	"unicode/utf8"
)

// Medium is a transport medium a Peer can be observed on. It is a small typed
// enum rather than a string so that VisiblePeer.Endpoints can key on it and so
// that an unhandled medium is a compile-time concern, not a typo.
type Medium uint8

const (
	MediumLAN Medium = iota
	MediumBluetooth
)

// String names the medium for reports and events. An out-of-range value is
// rendered rather than panicking, since Medium can arrive from decoded data.
func (m Medium) String() string {
	switch m {
	case MediumLAN:
		return "LAN"
	case MediumBluetooth:
		return "Bluetooth"
	default:
		return fmt.Sprintf("Medium(%d)", uint8(m))
	}
}

// Bounds that Requirements 1.1 and 1.11 state explicitly. They are named
// constants so validation and any future beacon share one definition.
const (
	// MaxDisplayNameChars is counted in UTF-8 characters (runes), not bytes
	// (Req 1.1, 1.11). A 64-rune name may be up to 256 bytes on the wire.
	MaxDisplayNameChars = 64
	// FingerprintHexChars is the length of a SHA-256 fingerprint in lowercase hex.
	FingerprintHexChars = 64
	// MinPort and MaxPort bound a listening port (Req 1.11).
	MinPort = 1
	MaxPort = 65535
)

// Announcement is what a Peer_Node publishes about itself (Req 1.1). It is
// marshalled to JSON, so every field carries an explicit tag: the wire names are
// part of the protocol and must not drift with a Go rename.
//
// The zero value is deliberately invalid on every field, which is what lets
// CheckAnnouncement detect an omitted JSON field: encoding/json leaves an absent
// field at its zero value, and CheckAnnouncement rejects each zero value by name.
type Announcement struct {
	DisplayName     string `json:"displayName"`     // 1..64 UTF-8 characters
	Fingerprint     string `json:"fingerprint"`     // 64 lowercase hex chars = SHA-256 of the public key
	ProtocolVersion int    `json:"protocolVersion"` // 1 or greater; may be unsupported locally
	Port            int    `json:"port"`            // 1..65535
}

// PeerEndpoint is where a Peer was last reached on one medium. One Peer can hold
// several of these, one per medium it was observed on (Req 1.8).
type PeerEndpoint struct {
	Medium   Medium
	Address  string // IP literal, or Bluetooth device id
	Port     int
	LastSeen time.Time
}

// VisiblePeer is one row of the visible Peer list (Req 1.2). It is keyed
// elsewhere by Fingerprint, so two announcements sharing a fingerprint collapse
// into one of these with both media listed (Req 1.8).
type VisiblePeer struct {
	Fingerprint             string
	DisplayName             string
	DeclaredProtocolVersion int
	ProtocolSupported       bool
	Endpoints               map[Medium]PeerEndpoint // every medium it was seen on (Req 1.8)
	ManuallySupplied        bool
}

// AnnouncementCheck is a tagged result: exactly one of Valid / Malformed is set.
// Go has no sealed sum type, so the invariant is stated rather than enforced.
// Callers MUST check Malformed first; when Malformed is nil, Valid is non-nil and
// holds an announcement that satisfied every bound in Req 1.1.
type AnnouncementCheck struct {
	Valid     *Announcement
	Malformed []string // Req 1.11: names every reason so the malformed event is specific
}

// CheckAnnouncement validates a received announcement against Req 1.11. It is a
// pure function over the decoded record: no clock, no I/O, no registry access, so
// the discard-and-record rule is testable on its own.
//
// Every failing field is reported, not just the first, so the malformed event can
// name all of them. Reasons use the JSON field names, since that is what an
// operator sees on the wire. The order of reasons follows the field order of
// Announcement, which makes the output deterministic.
func CheckAnnouncement(a *Announcement) AnnouncementCheck {
	if a == nil {
		return AnnouncementCheck{Malformed: []string{"announcement is missing"}}
	}

	var reasons []string

	// displayName: the limit is characters, not bytes. A multi-byte name that is
	// well over 64 bytes can still be a perfectly legal 64-character name.
	switch chars := utf8.RuneCountInString(a.DisplayName); {
	case a.DisplayName == "":
		reasons = append(reasons, "displayName is missing")
	case chars > MaxDisplayNameChars:
		reasons = append(reasons, fmt.Sprintf(
			"displayName is %d UTF-8 characters, maximum %d", chars, MaxDisplayNameChars))
	}

	if a.Fingerprint == "" {
		reasons = append(reasons, "fingerprint is missing")
	} else if !isLowerHex(a.Fingerprint, FingerprintHexChars) {
		reasons = append(reasons, fmt.Sprintf(
			"fingerprint is not %d lowercase hex characters", FingerprintHexChars))
	}

	// A supported or an unsupported version is both acceptable here; support is
	// decided by the registry (Req 1.2). Only an absent or nonsensical version
	// is malformed.
	if a.ProtocolVersion < 1 {
		reasons = append(reasons, "protocolVersion is missing")
	}

	// Port 0 is both the zero value of an omitted field and out of range, so it is
	// reported as missing to keep the event honest about what was seen.
	switch {
	case a.Port == 0:
		reasons = append(reasons, "port is missing")
	case a.Port < MinPort || a.Port > MaxPort:
		reasons = append(reasons, fmt.Sprintf(
			"port %d is outside %d..%d", a.Port, MinPort, MaxPort))
	}

	if len(reasons) > 0 {
		return AnnouncementCheck{Malformed: reasons}
	}
	// Copy so the accepted value cannot be mutated through the caller's pointer.
	accepted := *a
	return AnnouncementCheck{Valid: &accepted}
}

// isLowerHex reports whether s is exactly n characters of lowercase hex. Uppercase
// is rejected on purpose: the fingerprint is compared as a string when peers are
// keyed by it, so one canonical spelling avoids two entries for one key (Req 1.8).
func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
