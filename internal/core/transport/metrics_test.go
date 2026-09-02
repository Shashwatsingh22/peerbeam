package transport

import (
	"testing"
	"time"
)

// manualClock is the injected time source for tests: it moves only when a test
// advances it, so the Req 2.7 sampling cadence is checked without sleeping.
type manualClock struct{ now time.Time }

func (c *manualClock) Now() time.Time          { return c.now }
func (c *manualClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// TestTransportMetricsRetainsOnlyTheMostRecentSample covers task 6.5: sampling
// keeps the latest measured goodput and RTT and nothing older.
//
// Requirements: 2.7
func TestTransportMetricsRetainsOnlyTheMostRecentSample(t *testing.T) {
	clk := &manualClock{now: baseTime}
	m := NewTransportMetrics(clk)

	// Nothing sampled yet: both accessors report absence rather than a zero that
	// could be mistaken for a real reading.
	if _, ok := m.Goodput(); ok {
		t.Fatal("fresh metrics report a goodput sample")
	}
	if _, ok := m.RTT(); ok {
		t.Fatal("fresh metrics report an RTT sample")
	}
	if _, ok := m.RTTMillis(); ok {
		t.Fatal("fresh metrics report an RTT in millis")
	}
	if _, ok := m.LastSampleAt(); ok {
		t.Fatal("fresh metrics report a last sample time")
	}
	if !m.DueForSample() {
		t.Fatal("fresh metrics are not due for a sample")
	}

	// Three seconds of samples. Only the last of each survives.
	for i, gp := range []int64{1_000, 2_000, 41_943_040} {
		m.RecordGoodput(gp)
		m.RecordRTT(time.Duration(i+1) * 10 * time.Millisecond)
		clk.advance(MetricsSampleInterval)
	}

	gotGoodput, ok := m.Goodput()
	if !ok {
		t.Fatal("no goodput sample after three recordings")
	}
	if gotGoodput.BytesPerSecond != 41_943_040 {
		t.Fatalf("goodput %d, want the most recent 41943040", gotGoodput.BytesPerSecond)
	}
	// The retained sample carries the time it was taken, not the current time.
	wantAt := baseTime.Add(2 * MetricsSampleInterval)
	if !gotGoodput.At.Equal(wantAt) {
		t.Fatalf("goodput timestamped %s, want %s", gotGoodput.At, wantAt)
	}

	gotRTT, ok := m.RTT()
	if !ok {
		t.Fatal("no RTT sample after three recordings")
	}
	if gotRTT.RTT != 30*time.Millisecond {
		t.Fatalf("RTT %s, want the most recent 30ms", gotRTT.RTT)
	}
	if millis, ok := m.RTTMillis(); !ok || millis != 30 {
		t.Fatalf("RTTMillis() = (%d, %v), want (30, true)", millis, ok)
	}
}

// TestTransportMetricsDueForSampleTracksTheInterval checks the cadence helper that
// keeps sampling inside the "1 second or shorter" bound of Req 2.7 even when a
// ticker drifts.
//
// Requirements: 2.7
func TestTransportMetricsDueForSampleTracksTheInterval(t *testing.T) {
	clk := &manualClock{now: baseTime}
	m := NewTransportMetrics(clk)

	m.RecordGoodput(1_024)
	if m.DueForSample() {
		t.Fatal("due immediately after sampling")
	}

	clk.advance(MetricsSampleInterval - time.Nanosecond)
	if m.DueForSample() {
		t.Fatal("due one nanosecond before the interval elapsed")
	}

	clk.advance(time.Nanosecond)
	if !m.DueForSample() {
		t.Fatal("not due at exactly the interval")
	}

	// Recording either value satisfies the cadence, since both share one
	// last-sample time.
	m.RecordRTT(5 * time.Millisecond)
	if m.DueForSample() {
		t.Fatal("still due after recording an RTT")
	}
	if at, ok := m.LastSampleAt(); !ok || !at.Equal(clk.now) {
		t.Fatalf("LastSampleAt() = (%s, %v), want (%s, true)", at, ok, clk.now)
	}
}

// TestTransportMetricsRejectsNonsenseReadings pins the two guards: a negative rate
// is clamped to zero, a negative duration is discarded rather than stored.
//
// Requirements: 2.7
func TestTransportMetricsRejectsNonsenseReadings(t *testing.T) {
	clk := &manualClock{now: baseTime}
	m := NewTransportMetrics(clk)

	m.RecordGoodput(-1)
	got, ok := m.Goodput()
	if !ok || got.BytesPerSecond != 0 {
		t.Fatalf("negative goodput stored as (%d, %v), want (0, true)", got.BytesPerSecond, ok)
	}

	m.RecordRTT(20 * time.Millisecond)
	m.RecordRTT(-1)
	rtt, ok := m.RTT()
	if !ok || rtt.RTT != 20*time.Millisecond {
		t.Fatalf("negative RTT overwrote the good sample: (%s, %v)", rtt.RTT, ok)
	}

	// A genuine sub-millisecond RTT reports 0 ms and remains present, which is
	// what LAN loopback produces.
	m.RecordRTT(400 * time.Microsecond)
	if millis, ok := m.RTTMillis(); !ok || millis != 0 {
		t.Fatalf("RTTMillis() = (%d, %v), want (0, true)", millis, ok)
	}
}

// TestNewTransportMetricsWithoutAClockStillWorks guards the nil-Clock fallback, so
// a wiring slip degrades to the real clock rather than panicking mid-session.
//
// Requirements: 2.7
func TestNewTransportMetricsWithoutAClockStillWorks(t *testing.T) {
	m := NewTransportMetrics(nil)
	m.RecordGoodput(2_048)
	got, ok := m.Goodput()
	if !ok || got.BytesPerSecond != 2_048 {
		t.Fatalf("Goodput() = (%d, %v), want (2048, true)", got.BytesPerSecond, ok)
	}
	if got.At.IsZero() {
		t.Fatal("sample carries no timestamp")
	}
}
