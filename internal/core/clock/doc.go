// Package clock holds the injected time source shared by every pure component
// that enforces a duration named in the requirements.
//
// It exists as its own package so that codec, discovery, session, and transfer
// can all take the same one-method interface without importing one another, and
// so that no core type ever calls time.Now directly.
//
// Pure logic only. This package must not import net, os, or any socket API.
package clock
