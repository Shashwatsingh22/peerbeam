// Package codec implements the Peerbeam wire codec: the fixed 14-byte
// big-endian frame header plus payload, frame encoding, and incremental
// stream parsing with strict field-order validation.
//
// Pure logic only. This package must not import net, os, or any socket API.
package codec
