package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"
)

// HKDF-SHA256, RFC 5869, in the two steps the RFC names.
//
// It is written out here rather than imported from golang.org/x/crypto/hkdf because it
// is thirty lines, the module already depends on x/crypto for curve25519 and
// chacha20poly1305, and having the extract and expand steps visible next to the
// handshake makes the salt and info choices auditable at the point they matter.

// hkdfExtract is the extract step: a keyed hash that turns a non-uniform input keying
// material into a uniform pseudorandom key.
//
// The salt is not secret and does not need to be random. Here it is both ephemeral
// public keys, which is what binds the derived keys to this particular exchange: two
// Sessions between the same identities have different ephemerals, so they extract to
// different pseudorandom keys and Req 10.5's "no reuse across Sessions" follows.
func hkdfExtract(salt, inputKeyMaterial []byte) []byte {
	if len(salt) == 0 {
		// RFC 5869: a zero-filled salt of hash length is the defined default. This
		// path is never taken by the handshake, which always supplies both ephemeral
		// keys, but leaving it undefined would be a trap for a future caller.
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(inputKeyMaterial)
	return mac.Sum(nil)
}

// hkdfExpand is the expand step: it stretches the pseudorandom key into as many output
// bytes as asked for, bound to the info string.
//
// info is the domain separator. Two derivations from the same shared secret with
// different info values are independent, which is what lets one exchange produce two
// directional keys without either being computable from the other.
func hkdfExpand(pseudorandomKey, info []byte, length int) ([]byte, error) {
	if length < 0 {
		return nil, errors.New("hkdf: negative output length")
	}
	// RFC 5869 caps output at 255 hash lengths, because the counter is one byte.
	if length > 255*sha256.Size {
		return nil, errors.New("hkdf: requested output exceeds 255 hash lengths")
	}

	out := make([]byte, 0, length)
	var block []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(sha256.New, pseudorandomKey)
		mac.Write(block) // T(0) is empty, T(n) feeds back into T(n+1)
		mac.Write(info)
		mac.Write([]byte{counter})
		block = mac.Sum(nil)
		out = append(out, block...)
	}
	return out[:length], nil
}

// HKDF derives length bytes from inputKeyMaterial, bound to salt and info. It is the
// only key derivation in the protocol, so every derived key is traceable to one call
// site with one info string.
func HKDF(inputKeyMaterial, salt, info []byte, length int) ([]byte, error) {
	return hkdfExpand(hkdfExtract(salt, inputKeyMaterial), info, length)
}

// HKDFReader exposes the expand step as a stream, for a caller that wants several
// independent keys from one extract. The handshake does not use it; it exists because
// the alternative, calling HKDF twice with different info strings, re-runs extract
// needlessly and invites a copy-paste error in the salt.
func HKDFReader(inputKeyMaterial, salt, info []byte) io.Reader {
	return &hkdfStream{
		pseudorandomKey: hkdfExtract(salt, inputKeyMaterial),
		info:            append([]byte(nil), info...),
		counter:         1,
	}
}

type hkdfStream struct {
	pseudorandomKey []byte
	info            []byte
	counter         byte
	block           []byte
	buffered        []byte
}

func (s *hkdfStream) Read(into []byte) (int, error) {
	for len(s.buffered) < len(into) {
		if s.counter == 0 {
			return 0, errors.New("hkdf: output exhausted")
		}
		mac := hmac.New(sha256.New, s.pseudorandomKey)
		mac.Write(s.block)
		mac.Write(s.info)
		mac.Write([]byte{s.counter})
		s.block = mac.Sum(nil)
		s.buffered = append(s.buffered, s.block...)
		s.counter++
	}
	n := copy(into, s.buffered)
	s.buffered = s.buffered[n:]
	return n, nil
}
