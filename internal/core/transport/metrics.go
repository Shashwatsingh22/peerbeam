package transport

import (
	"time"

	"github.com/peerbeam/peerbeam/internal/core/clock"
)

// MetricsSampleInterval is the sampling cadence for measured goodput and RTT.
// Req 2.7 says "1 second or shorter", so this is the upper bound on the gap
// between samples, not a target.
const MetricsSampleInterval = time.Second

// GoodputSample is one measured throughput reading, in bytes per second, with the
// time it was taken.
type GoodputSample struct {
	BytesPerSecond int64
	At             time.Time
}

// RTTSample is one measured round-trip time, with the time it was taken. RTT is
// measured from the keepalive exchange, which already runs on its own timer.
type RTTSample struct {
	RTT time.Duration
	At  time.Time
}

// TransportMetrics holds the most recent measured goodput and RTT for one
// Session's active Transport (Req 2.7). It retains exactly one sample of each:
// the status line (Req 13.1) reads the latest, and the degraded-throughput and
// stall detectors keep their own 10-second windows (Req 11.8, 13.6) rather than
// asking this type to become a ring buffer.
//
// The two values are tracked separately because they arrive from different
// places: goodput from the bytes the writer moved, RTT from the keepalive
// response. Either can be present without the other, so both accessors report
// presence rather than returning a zero that cannot be told from a real reading
// of zero bytes per second.
//
// Not safe for concurrent use. One Session owns one instance, sampled from that
// Session's own goroutine.
type TransportMetrics struct {
	clk clock.Clock

	goodput    GoodputSample
	hasGoodput bool
	rtt        RTTSample
	hasRTT     bool

	lastSampleAt time.Time
	hasSampled   bool
}

// NewTransportMetrics returns metrics stamped by clk. The Clock is injected so
// the sampling cadence in Req 2.7 is testable without sleeping.
func NewTransportMetrics(clk clock.Clock) *TransportMetrics {
	if clk == nil {
		clk = clock.NewRealClock()
	}
	return &TransportMetrics{clk: clk}
}

// RecordGoodput stores a measured throughput reading, replacing any earlier one.
// A negative reading is clamped to zero: goodput is a rate over a window and a
// caller computing it from a byte delta and a clock delta can produce a small
// negative on a clock adjustment, which is noise rather than information.
func (m *TransportMetrics) RecordGoodput(bytesPerSecond int64) {
	if bytesPerSecond < 0 {
		bytesPerSecond = 0
	}
	now := m.clk.Now()
	m.goodput = GoodputSample{BytesPerSecond: bytesPerSecond, At: now}
	m.hasGoodput = true
	m.markSampled(now)
}

// RecordRTT stores a measured round-trip time, replacing any earlier one. A
// negative duration is discarded rather than clamped, since unlike a rate there
// is no reading it could plausibly represent.
func (m *TransportMetrics) RecordRTT(rtt time.Duration) {
	if rtt < 0 {
		return
	}
	now := m.clk.Now()
	m.rtt = RTTSample{RTT: rtt, At: now}
	m.hasRTT = true
	m.markSampled(now)
}

func (m *TransportMetrics) markSampled(now time.Time) {
	m.lastSampleAt = now
	m.hasSampled = true
}

// Goodput returns the most recent throughput sample, and false when none has been
// taken yet.
func (m *TransportMetrics) Goodput() (GoodputSample, bool) {
	return m.goodput, m.hasGoodput
}

// RTT returns the most recent round-trip sample, and false when none has been
// taken yet.
func (m *TransportMetrics) RTT() (RTTSample, bool) {
	return m.rtt, m.hasRTT
}

// RTTMillis is the convenience the status line wants (Req 13.1): the latest RTT
// in whole milliseconds, or false when there is none. A sub-millisecond RTT, which
// LAN loopback produces routinely, reports 0 rather than being treated as absent.
func (m *TransportMetrics) RTTMillis() (int64, bool) {
	if !m.hasRTT {
		return 0, false
	}
	return m.rtt.RTT.Milliseconds(), true
}

// DueForSample reports whether MetricsSampleInterval has elapsed since the last
// sample, so the sampling goroutine keeps Req 2.7's "1 second or shorter"
// guarantee even if its ticker drifts. A metrics instance that has never sampled
// is always due.
func (m *TransportMetrics) DueForSample() bool {
	if !m.hasSampled {
		return true
	}
	return m.clk.Now().Sub(m.lastSampleAt) >= MetricsSampleInterval
}

// LastSampleAt is when either value was last recorded, and false before the first
// sample.
func (m *TransportMetrics) LastSampleAt() (time.Time, bool) {
	return m.lastSampleAt, m.hasSampled
}
