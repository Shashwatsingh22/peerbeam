// Package crypto implements the Peerbeam session cryptography: the
// authenticated X25519 handshake, HKDF-SHA256 key derivation, directional
// ChaCha20-Poly1305 seal/open with derived nonces, and the pairing
// verification code.
//
// Pure logic only. This package must not import net, os, or any socket API.
package crypto
