package discovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// MaxAnnouncementBytes caps the size of a datagram this node will parse as an
// announcement. Datagrams are attacker-controlled, so the length is checked before
// the parser is entered: the check is one comparison and it removes any question of
// how much work a single hostile packet can cause.
//
// The ceiling is derived from the widest legal record. Field names and punctuation
// come to about 70 bytes, the fingerprint is 64, the two numbers are at most ~20
// digits together, and a 64-character display name is at most 768 bytes if a peer's
// encoder escapes every character as a surrogate pair (\uXXXX\uXXXX). That is ~922
// bytes; the rest is headroom for fields a later protocol version may add, which
// this decoder must tolerate rather than reject. The value also stays inside the
// ~1400-byte payload a single unfragmented datagram carries on a normal Ethernet
// MTU, so a legal announcement never needs to be split.
const MaxAnnouncementBytes = 2048

// EncodeAnnouncement marshals an announcement to the bytes a beacon datagram
// carries (Req 1.1). The JSON field names come from the struct tags on
// Announcement, so the wire format is defined in exactly one place.
//
// The only failure is a display name or fingerprint that is not valid UTF-8.
// encoding/json does not reject those, it silently substitutes U+FFFD for each bad
// byte, which would make Encode then Decode return a different string than went in.
// Rejecting the input instead keeps the round trip exact for every value this
// function accepts. Req 1.1 defines the display name in UTF-8 characters, so a
// string that is not valid UTF-8 was never a legal announcement.
func EncodeAnnouncement(a Announcement) ([]byte, error) {
	if !utf8.ValidString(a.DisplayName) {
		return nil, fmt.Errorf("encode announcement: displayName is not valid UTF-8")
	}
	if !utf8.ValidString(a.Fingerprint) {
		return nil, fmt.Errorf("encode announcement: fingerprint is not valid UTF-8")
	}
	data, err := json.Marshal(a)
	if err != nil {
		// Unreachable for the current field set (strings and ints only). Returned
		// rather than swallowed so that adding a field cannot hide a failure here.
		return nil, fmt.Errorf("encode announcement: %w", err)
	}
	return data, nil
}

// DecodeAnnouncement parses datagram bytes into an Announcement. It answers one
// question only — is this well-formed JSON with our field types — and deliberately
// does not validate the values; that is CheckAnnouncement's job (Req 1.11). Keeping
// the two apart means a decode failure and a bounds failure can be told apart, and
// each is testable on its own.
//
// The input is untrusted. encoding/json reports malformed, truncated, or
// wrong-typed input as an ordinary error and never panics, and the length cap plus
// the parser's own nesting limit bound the work a single datagram can cause. The
// returned announcement is meaningless when err is non-nil.
//
// Unknown fields are ignored on purpose: a peer running a later protocol version
// may add fields, and that is not a malformed announcement. Trailing bytes after
// the JSON object are an error, since a datagram carrying a record plus something
// else is not a record this node can account for.
func DecodeAnnouncement(data []byte) (*Announcement, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("decode announcement: empty datagram")
	}
	if len(data) > MaxAnnouncementBytes {
		return nil, fmt.Errorf("decode announcement: %d bytes exceeds maximum %d bytes",
			len(data), MaxAnnouncementBytes)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	var a Announcement
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("decode announcement: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("decode announcement: trailing data after the announcement object")
	}
	return &a, nil
}

// DecodeAndCheckAnnouncement is the whole receive path for one datagram: parse,
// then validate. It exists so a presence source has a single call to make and
// cannot forget the Req 1.11 check, while the two steps stay separately callable.
//
// A decode failure is reported as a malformed announcement rather than as a Go
// error, because Req 1.11 treats it the same way: the datagram is discarded, the
// visible Peer list is untouched, and a malformed announcement event is recorded.
// The caller therefore has one shape to handle no matter which step failed.
func DecodeAndCheckAnnouncement(data []byte) AnnouncementCheck {
	a, err := DecodeAnnouncement(data)
	if err != nil {
		return AnnouncementCheck{Malformed: []string{err.Error()}}
	}
	return CheckAnnouncement(a)
}
