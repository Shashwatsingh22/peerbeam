package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// SessionIdBytes is the length of the random identifier behind a SessionId. 128
// bits is far more than the 8 concurrent Sessions of Req 4.1 need; the width is
// chosen so an identifier can appear in a log or a report without being guessable
// or colliding across restarts.
const SessionIdBytes = 16

// SessionId identifies one Session for its whole life. Req 3.4 and Req 2.9 both
// turn on this value surviving a Transport change, so it is deliberately unrelated
// to anything about the Transport, the address, or the Peer: nothing about a
// rebind can change it.
//
// It is a string rather than a [16]byte so it can key a map and print itself.
type SessionId string

// String satisfies fmt.Stringer for reports and status lines.
func (id SessionId) String() string { return string(id) }

// IsZero reports whether the id was never assigned. The registry never stores a
// zero id, so this only catches an uninitialised value.
func (id SessionId) IsZero() bool { return id == "" }

// NewSessionId draws a fresh 128-bit identifier from crypto/rand and renders it as
// lowercase hex.
//
// crypto/rand rather than math/rand: a Session id appears in reports and is
// compared for equality across a rebind, and a predictable id is a needless
// invitation to confuse two Sessions. The error is returned rather than swallowed
// because a failing system entropy source must stop Session creation, not produce
// a weak id.
func NewSessionId() (SessionId, error) {
	return newSessionIdFrom(rand.Reader)
}

// newSessionIdFrom is the seam tests use to force an entropy failure. Production
// always passes crypto/rand.Reader.
func newSessionIdFrom(entropy io.Reader) (SessionId, error) {
	raw := make([]byte, SessionIdBytes)
	if _, err := io.ReadFull(entropy, raw); err != nil {
		return "", fmt.Errorf("draw session id: %w", err)
	}
	return SessionId(hex.EncodeToString(raw)), nil
}
