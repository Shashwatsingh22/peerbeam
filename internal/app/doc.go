// Package app is the wiring layer. It builds a PeerNode by joining the pure
// decision logic in internal/core to the concrete adapters in
// internal/platform, owns the root context and wait group that start and stop
// every goroutine the node runs, assembles the cobra command tree, and renders
// the once-per-second status view.
//
// This is the only package that knows which implementation backs each
// interface. No dependency injection framework: wiring is one constructor.
package app
