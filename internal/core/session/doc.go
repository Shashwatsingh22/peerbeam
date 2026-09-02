// Package session holds session identity and bookkeeping: session ids, the
// bounded session registry and admission decision, outbound sequence
// assignment with inbound duplicate detection, the gap-tolerant reorder
// buffer, the disconnected outbound queue, and group send fan-out.
//
// Pure logic only. This package must not import net, os, or any socket API.
package session
