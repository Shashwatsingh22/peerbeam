// Package discovery holds the peer discovery bookkeeping: the announcement
// model and its JSON codec, announcement validation, and the bounded
// fingerprint-keyed peer registry with per-medium staleness expiry.
//
// Pure logic only. Beacon sockets live in internal/platform/lan; this package
// must not import net, os, or any socket API.
package discovery
