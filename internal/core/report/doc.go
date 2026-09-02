// Package report holds the user-visible reporting shapes: the failure record
// that always names an operation, a peer, a reason, and a remediation step;
// the redacted event log entry and message trace, which have nowhere to put
// payload content; the transport change reason; and the all-or-nothing status
// line.
//
// Pure logic only. Rendering and log persistence live above this package;
// this package must not import net, os, or any socket API.
package report
