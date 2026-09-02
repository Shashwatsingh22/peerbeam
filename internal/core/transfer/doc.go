// Package transfer holds the file transfer bookkeeping: byte-offset chunk
// planning for the first leg, for a resume, and for a re-slice at a new chunk
// size after a transport rebind, plus acknowledged-range tracking with the
// contiguous watermark and bounded resend attempt counting.
//
// Pure logic only. File reads and writes live above this package; this package
// must not import net, os, or any socket API.
package transfer
