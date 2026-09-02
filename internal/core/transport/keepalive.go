package transport

import "time"

// Keepalive timing and the strike threshold, fixed by Requirements 3.1 and 3.2.
const (
	// KeepaliveInterval is how often a keepalive Message goes out on the active
	// Transport while a Session is active (Req 3.1).
	KeepaliveInterval = 5 * time.Second
	// KeepaliveResponseWindow is how long a keepalive may go unanswered before it
	// counts as a miss (Req 3.2).
	KeepaliveResponseWindow = 2 * time.Second
	// KeepaliveStrikeThreshold is the number of *consecutive* misses that marks
	// the active Transport unavailable (Req 3.2).
	KeepaliveStrikeThreshold = 3
)

// KeepaliveTracker is the three-strike liveness counter from Req 3.2. It holds no
// clock: the caller owns the 5-second ticker and the 2-second response window and
// reports the outcome of each keepalive here, which keeps the counting rule
// testable without waiting on real time.
//
// The counter is consecutive, not cumulative. Two misses followed by a response
// leave the Transport healthy with a clean slate, which is the difference between
// a lossy link and a dead one.
type KeepaliveTracker struct {
	threshold         int
	consecutiveMisses int
}

// NewKeepaliveTracker returns a tracker at the Req 3.2 threshold of three.
func NewKeepaliveTracker() *KeepaliveTracker {
	return &KeepaliveTracker{threshold: KeepaliveStrikeThreshold}
}

// OnResponse records a keepalive answered inside the response window. It resets
// the strike count, so misses only accumulate while they are unbroken.
func (k *KeepaliveTracker) OnResponse() { k.consecutiveMisses = 0 }

// OnTimeout records a keepalive that went unanswered for KeepaliveResponseWindow.
// It returns true at the point the Transport should be marked unavailable, which
// is exactly the threshold-th consecutive miss.
//
// It keeps returning true for further misses past the threshold rather than only
// firing once, because the caller acts on the value rather than latching it, and
// a tracker that reported healthy again after a fourth miss would be lying. The
// count is capped at the threshold so a long outage cannot overflow it.
func (k *KeepaliveTracker) OnTimeout() bool {
	if k.consecutiveMisses < k.threshold {
		k.consecutiveMisses++
	}
	return k.consecutiveMisses >= k.threshold
}

// Misses is the current consecutive miss count, for the status line and for
// tests. It never exceeds the threshold.
func (k *KeepaliveTracker) Misses() int { return k.consecutiveMisses }

// Threshold is the miss count that marks a Transport unavailable.
func (k *KeepaliveTracker) Threshold() int { return k.threshold }

// Unavailable reports whether the Transport is currently struck out. It is the
// same condition OnTimeout returns, exposed so a caller that lost the return
// value can still ask.
func (k *KeepaliveTracker) Unavailable() bool { return k.consecutiveMisses >= k.threshold }

// Reset returns the tracker to healthy. It is called after a rebind, since the
// strike count belongs to a Transport binding rather than to the Session.
func (k *KeepaliveTracker) Reset() { k.consecutiveMisses = 0 }
