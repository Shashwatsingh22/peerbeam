package codec

import "time"

// Clock is the injected time source. It is deliberately one method: everywhere a
// requirement names a duration, the type that enforces it takes a Clock instead of
// calling time.Now directly, so the duration is testable without sleeping.
// Production wires realClock; tests wire a manual clock they advance by hand.
//
// This lives in codec because codec is the first package to need it. It is a
// candidate to move to a shared internal/core location once a second package
// needs it; the interface is small enough that moving it is a mechanical change.
type Clock interface {
	Now() time.Time
}

// realClock is the production Clock. It is the only place in this package that
// reads wall-clock time.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// NewRealClock returns the Clock used in production wiring.
func NewRealClock() Clock { return realClock{} }
