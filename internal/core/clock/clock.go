package clock

import "time"

// Clock is the injected time source. It is deliberately one method: everywhere a
// requirement names a duration, the type that enforces it takes a Clock instead of
// calling time.Now directly, so the duration is testable without sleeping.
// Production wires realClock; tests wire a manual clock they advance by hand.
//
// This started out in codec, the first package that needed it, with a note that it
// should move once a second package needed one. The peer registry is that second
// package (Req 1.5 expiry), so the interface now lives here and codec consumes it
// from this package rather than declaring its own.
type Clock interface {
	Now() time.Time
}

// realClock is the production Clock. It is the only place in internal/core that
// reads wall-clock time.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// NewRealClock returns the Clock used in production wiring.
func NewRealClock() Clock { return realClock{} }
