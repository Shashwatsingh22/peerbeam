package report

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// baseTime anchors every timestamp in this package's tests.
var baseTime = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

// lanTarget and btTarget are the Req 2.1 expected goodput figures, restated here rather than
// imported so internal/core/report keeps no dependency on internal/core/transport.
const (
	lanTarget int64 = 41_943_040
	btTarget  int64 = 40_960
)

// TestProperty38ContinuousBelowTargetWindowIsDetectedExactly covers
// Property 38: A continuous below-target window is detected exactly.
//
// "Exactly" is the point: the detector must fire on a run of ten and not on a run of nine, and
// a single sample at or above target in the middle must break the run. The independent model
// below is a plain longest-run count, computed from the generated series rather than from the
// detector's own state.
//
// Validates: Requirements 11.8, 11.9, 13.6
func TestProperty38ContinuousBelowTargetWindowIsDetectedExactly(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		target := rapid.SampledFrom([]int64{lanTarget, btTarget, 1_000}).Draw(rt, "target")
		transportName := rapid.SampledFrom([]string{"LAN_Transport", "BT_Transport"}).
			Draw(rt, "transport")

		detector := NewThroughputDetector(transportName, target)

		// Samples drawn from either side of the target, so runs of both kinds occur.
		samples := rapid.SliceOfN(rapid.SampledFrom([]int64{
			0, 1, target - 1, target, target + 1, target * 2,
		}), 0, 40).Draw(rt, "samples")

		consecutiveBelow := 0
		firedAt := -1

		for i, sample := range samples {
			got := detector.Sample(sample)

			// The model: a sample at or above target breaks the run.
			if sample >= target {
				consecutiveBelow = 0
			} else {
				consecutiveBelow++
			}

			// The detector's own count agrees with the model, capped at nothing: it is a
			// plain running count.
			if detector.ConsecutiveBelowTarget() != consecutiveBelow {
				rt.Fatalf("sample %d: detector counts %d consecutive below target, model says %d",
					i, detector.ConsecutiveBelowTarget(), consecutiveBelow)
			}

			// Req 11.8: the report appears exactly at the tenth consecutive sample, and
			// once per run rather than every second thereafter.
			switch {
			case consecutiveBelow == DetectionSamples:
				if got == nil {
					rt.Fatalf("sample %d: %d consecutive below-target samples produced no report",
						i, consecutiveBelow)
				}
				firedAt = i
			case got != nil:
				rt.Fatalf("sample %d: report produced at %d consecutive below-target samples",
					i, consecutiveBelow)
			}

			if got != nil {
				// The report names all three values Req 11.8 requires.
				if got.ActiveTransportName != transportName {
					rt.Fatalf("report names transport %q, want %q",
						got.ActiveTransportName, transportName)
				}
				if got.MeasuredBytesPerSecond != sample {
					rt.Fatalf("report names measured %d, want %d",
						got.MeasuredBytesPerSecond, sample)
				}
				if got.TargetBytesPerSecond != target {
					rt.Fatalf("report names target %d, want %d",
						got.TargetBytesPerSecond, target)
				}
				rendered := got.String()
				for _, want := range []string{
					transportName,
					strconv.FormatInt(sample, 10),
					strconv.FormatInt(target, 10),
				} {
					if !strings.Contains(rendered, want) {
						rt.Fatalf("rendered report omits %q:\n%s", want, rendered)
					}
				}
				// Req 11.9: this is a report, not a termination. There is nothing on the
				// detector that could stop a transfer, which is the structural half; the
				// observable half is that sampling continues to work afterwards.
				if !detector.Degraded() {
					rt.Fatal("detector reported degradation but does not consider itself degraded")
				}
			}

			if detector.Degraded() != (consecutiveBelow >= DetectionSamples) {
				rt.Fatalf("sample %d: Degraded() = %v, model says %v",
					i, detector.Degraded(), consecutiveBelow >= DetectionSamples)
			}
		}

		// A run of ten somewhere in the series means it fired; no such run means it did not.
		longestRun, hasRun := longestBelowRun(samples, target)
		if hasRun != (firedAt >= 0) {
			rt.Fatalf("longest below-target run is %d (window %d) but fired=%v",
				longestRun, DetectionSamples, firedAt >= 0)
		}
	})
}

// longestBelowRun is the independent model: the longest run of consecutive below-target
// samples, and whether it reached the window.
func longestBelowRun(samples []int64, target int64) (int, bool) {
	longest, current := 0, 0
	for _, s := range samples {
		if s < target {
			current++
			if current > longest {
				longest = current
			}
			continue
		}
		current = 0
	}
	return longest, longest >= DetectionSamples
}

// TestThroughputDetectorBoundaryIsNineVersusTen pins "exactly" with fixed input: nine
// below-target samples say nothing, the tenth reports.
//
// Requirements: 11.8
func TestThroughputDetectorBoundaryIsNineVersusTen(t *testing.T) {
	d := NewThroughputDetector("LAN_Transport", lanTarget)

	for i := 1; i < DetectionSamples; i++ {
		if got := d.Sample(lanTarget - 1); got != nil {
			t.Fatalf("reported after %d below-target samples, want %d", i, DetectionSamples)
		}
	}
	if d.Degraded() {
		t.Fatal("degraded after nine samples")
	}

	got := d.Sample(lanTarget - 1)
	if got == nil {
		t.Fatalf("no report at exactly %d below-target samples", DetectionSamples)
	}
	if !d.Degraded() {
		t.Fatal("not degraded after the window completed")
	}

	// Latched: a sustained slow link reports once, not once a second forever.
	for i := 0; i < 5; i++ {
		if again := d.Sample(lanTarget - 1); again != nil {
			t.Fatal("reported again while still degraded")
		}
	}

	// A sample at target clears it, and a fresh run reports again.
	if got := d.Sample(lanTarget); got != nil {
		t.Fatal("a sample at target produced a report")
	}
	if d.Degraded() || d.ConsecutiveBelowTarget() != 0 {
		t.Fatal("a sample at target did not clear the run")
	}
	for i := 1; i < DetectionSamples; i++ {
		d.Sample(0)
	}
	if got := d.Sample(0); got == nil {
		t.Fatal("a second degradation was not reported")
	}
}

// TestThroughputDetectorRebindStartsOver checks that ten below-target samples on a dying LAN
// link say nothing about the Bluetooth link that replaced it.
//
// Requirements: 11.8, 3.3
func TestThroughputDetectorRebindStartsOver(t *testing.T) {
	d := NewThroughputDetector("LAN_Transport", lanTarget)
	for i := 0; i < DetectionSamples-1; i++ {
		d.Sample(0)
	}
	if d.ConsecutiveBelowTarget() != DetectionSamples-1 {
		t.Fatalf("count is %d, want %d", d.ConsecutiveBelowTarget(), DetectionSamples-1)
	}

	d.Rebind("BT_Transport", btTarget)
	if d.ConsecutiveBelowTarget() != 0 {
		t.Fatalf("rebind left %d samples counted", d.ConsecutiveBelowTarget())
	}
	// A sample that was far below the LAN target is comfortably above the Bluetooth one.
	if got := d.Sample(btTarget + 1); got != nil {
		t.Fatal("a sample above the new target produced a report")
	}
	if _, ok := d.LastMeasured(); !ok {
		t.Fatal("no measurement recorded after the rebind")
	}
}

// TestProperty38StallDetectionCounterpart is the acknowledged-bytes half of Property 38: a
// stall is indicated exactly when ten consecutive seconds pass with no increase.
//
// Validates: Requirements 13.6
func TestProperty38StallDetectionCounterpart(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		d := NewStallDetector("tx-1")

		// A series of acknowledged byte counts: sometimes advancing, sometimes flat.
		deltas := rapid.SliceOfN(rapid.SampledFrom([]int64{0, 0, 0, 1, 4096}), 0, 40).
			Draw(rt, "deltas")

		acknowledged := int64(0)
		consecutiveFlat := 0
		first := true
		fired := false

		for i, delta := range deltas {
			acknowledged += delta
			got := d.Sample(acknowledged, "LAN_Transport", 1_000, 7)

			if first {
				// The first sample has nothing to compare against.
				first = false
				if got != nil {
					rt.Fatalf("sample %d: the first sample produced a report", i)
				}
				if d.ConsecutiveFlatSamples() != 0 {
					rt.Fatalf("the first sample counted %d flat samples",
						d.ConsecutiveFlatSamples())
				}
				continue
			}

			if delta > 0 {
				consecutiveFlat = 0
			} else {
				consecutiveFlat++
			}
			if d.ConsecutiveFlatSamples() != consecutiveFlat {
				rt.Fatalf("sample %d: detector counts %d flat, model says %d",
					i, d.ConsecutiveFlatSamples(), consecutiveFlat)
			}

			switch {
			case consecutiveFlat == DetectionSamples:
				if got == nil {
					rt.Fatalf("sample %d: %d flat samples produced no stall indication",
						i, consecutiveFlat)
				}
				fired = true
			case got != nil:
				rt.Fatalf("sample %d: stall indicated at %d flat samples", i, consecutiveFlat)
			}

			if got != nil {
				// Req 13.6: names the transfer, the transport, the goodput, and the RTT.
				if got.TransferId != "tx-1" {
					rt.Fatalf("indication names transfer %q", got.TransferId)
				}
				if got.ActiveTransportName != "LAN_Transport" {
					rt.Fatalf("indication names transport %q", got.ActiveTransportName)
				}
				if got.GoodputBytesPerSecond != 1_000 || got.RoundTripMillis != 7 {
					rt.Fatalf("indication carries %d B/s and %d ms",
						got.GoodputBytesPerSecond, got.RoundTripMillis)
				}
				rendered := got.String()
				for _, want := range []string{"tx-1", "LAN_Transport", "1000", "7"} {
					if !strings.Contains(rendered, want) {
						rt.Fatalf("rendered indication omits %q:\n%s", want, rendered)
					}
				}
			}
		}

		// The detector agrees with the model about whether a stall ever happened.
		if longest, hasRun := longestFlatRun(deltas); hasRun != fired {
			rt.Fatalf("longest flat run is %d (window %d) but fired=%v",
				longest, DetectionSamples, fired)
		}
	})
}

// longestFlatRun models the stall condition over the delta series, ignoring the first sample
// since it establishes the baseline.
func longestFlatRun(deltas []int64) (int, bool) {
	if len(deltas) == 0 {
		return 0, false
	}
	longest, current := 0, 0
	for _, d := range deltas[1:] {
		if d > 0 {
			current = 0
			continue
		}
		current++
		if current > longest {
			longest = current
		}
	}
	return longest, longest >= DetectionSamples
}

// TestStallDetectorWatchesAcknowledgementsNotActivity is the case the detector exists for: a
// transfer resending a chunk nobody acknowledges is busy the whole time and still stalled.
//
// Requirements: 13.6
func TestStallDetectorWatchesAcknowledgementsNotActivity(t *testing.T) {
	d := NewStallDetector("tx-9")

	d.Sample(1024, "BT_Transport", 40_000, 30) // baseline
	for i := 1; i < DetectionSamples; i++ {
		if got := d.Sample(1024, "BT_Transport", 40_000, 30); got != nil {
			t.Fatalf("stall indicated after %d flat samples, want %d", i, DetectionSamples)
		}
	}
	got := d.Sample(1024, "BT_Transport", 40_000, 30)
	if got == nil {
		t.Fatalf("no stall indication at %d flat samples", DetectionSamples)
	}
	if !d.Stalled() {
		t.Fatal("detector does not consider itself stalled")
	}

	// Latched until progress resumes.
	if again := d.Sample(1024, "BT_Transport", 40_000, 30); again != nil {
		t.Fatal("stall indicated twice without progress in between")
	}
	if resumed := d.Sample(2048, "BT_Transport", 40_000, 30); resumed != nil {
		t.Fatal("progress produced a stall indication")
	}
	if d.Stalled() || d.ConsecutiveFlatSamples() != 0 {
		t.Fatal("progress did not clear the stall")
	}
	if d.AcknowledgedBytes() != 2048 {
		t.Fatalf("detector tracks %d acknowledged bytes, want 2048", d.AcknowledgedBytes())
	}
}

// TestStallDetectorTreatsABackwardsCountAsFlat checks the conservative reading: an
// acknowledged count that went backwards is nonsense, and treating it as progress would hide
// a real stall.
//
// Requirements: 13.6
func TestStallDetectorTreatsABackwardsCountAsFlat(t *testing.T) {
	d := NewStallDetector("tx-b")
	d.Sample(5000, "LAN_Transport", 1, 1)

	for i := 1; i < DetectionSamples; i++ {
		if got := d.Sample(100, "LAN_Transport", 1, 1); got != nil {
			t.Fatalf("stall indicated early, at %d samples", i)
		}
	}
	if got := d.Sample(100, "LAN_Transport", 1, 1); got == nil {
		t.Fatal("a series of backwards counts did not stall")
	}
	// The high-water mark is kept, so a later genuine count is compared against reality.
	if d.AcknowledgedBytes() != 5000 {
		t.Fatalf("detector tracks %d bytes, want the high-water mark 5000", d.AcknowledgedBytes())
	}
}

// TestDetectionWindowMatchesTheRequirement pins the ten-second window of Req 11.8 and 13.6,
// and the one-second sampling cadence it assumes.
//
// Requirements: 11.8, 13.6, 2.7
func TestDetectionWindowMatchesTheRequirement(t *testing.T) {
	if DetectionWindow != 10*time.Second {
		t.Fatalf("detection window is %s, want 10s", DetectionWindow)
	}
	if DetectionSamples != 10 {
		t.Fatalf("detection window is %d samples, want 10", DetectionSamples)
	}
	// The two have to agree: the detectors count samples, and the requirement states
	// seconds, which only lines up at a one-second cadence.
	if time.Duration(DetectionSamples)*time.Second != DetectionWindow {
		t.Fatalf("%d samples at one per second is not %s", DetectionSamples, DetectionWindow)
	}
}

// TestDegradedThroughputRendersAsACompleteFailure checks that the Req 11.8 condition reaches
// the user through the same four-field contract as everything else, and that its remediation
// says the transfer continues (Req 11.9).
//
// Requirements: 11.8, 11.9, 13.4
func TestDegradedThroughputRendersAsACompleteFailure(t *testing.T) {
	got := DegradedThroughput{
		ActiveTransportName:    "BT_Transport",
		MeasuredBytesPerSecond: 1_024,
		TargetBytesPerSecond:   btTarget,
	}.AsFailure("laptop")

	if !got.Complete() {
		t.Fatalf("incomplete failure, missing %v", got.Missing())
	}
	if !strings.Contains(got.Remediation, "continues") {
		t.Fatalf("remediation %q does not say the transfer continues", got.Remediation)
	}
	for _, want := range []string{"BT_Transport", "1024", strconv.FormatInt(btTarget, 10)} {
		if !strings.Contains(got.Reason, want) {
			t.Fatalf("reason %q omits %q", got.Reason, want)
		}
	}
}
