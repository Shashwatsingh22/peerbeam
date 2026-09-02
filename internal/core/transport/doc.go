// Package transport declares the Transport and TransportConnection interfaces
// and the transport policy: candidate selection, goodput-ordered ranking, the
// connection ladder, the switch decision rule table, keepalive strike
// counting, and transport metrics.
//
// Pure logic only. Concrete LAN and Bluetooth transports live under
// internal/platform; this package must not import net, os, or any socket API.
package transport
