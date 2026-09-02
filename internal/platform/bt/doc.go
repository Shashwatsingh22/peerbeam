// Package bt is the Bluetooth I/O adapter. It implements the Transport and
// TransportConnection interfaces declared in internal/core/transport on top of
// the BluetoothBridge, whose concrete implementations reach the per-OS native
// shim under shim/ over cgo, or a helper process over stdio while developing.
//
// The bridge is deliberately dumb: advertise, scan, connect, read, write,
// close. Framing, retries, and policy all live in core. When the host exposes
// no usable Bluetooth interface the bridge reports itself unavailable and the
// node starts with LAN as its only candidate transport.
package bt
