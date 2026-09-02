package report

import "time"

// DetectionWindow is the continuous window both detectors watch: ten seconds of per-second
// samples (Req 11.8, 13.6).
const DetectionWindow = 10 * time.Second

// DetectionSamples is DetectionWindow expressed in one-second samples. Both detectors count
// samples rather than measuring elapsed time, because the samples arrive on a one-second
// ticker (Req 2.7) and counting them is exactly what "a continuous 10-second window" means
// at that cadence.
const DetectionSamples = 10

// ThroughputDetector reports when measured goodput stays under the active Transport's target
// for a continuous ten-second window (Req 11.8).
//
// It keeps a count rather than a ring buffer of samples. The rule is "some window of ten
// consecutive samples lies entirely below target", and a running count of consecutive
// below-target samples answers that in one integer: any sample at or above target resets it,
// so the count reaching ten is precisely the condition.
//
// Not safe for concurrent use. One Session's metrics goroutine owns one detector.
type ThroughputDetector struct {
	targetBytesPerSecond int64
	transportName        string

	consecutiveBelow int
	lastMeasured     int64
	haveMeasured     bool
	// reported latches, so a sustained slow link produces one report rather than one per
	// second for the rest of the transfer. Req 11.8 asks for the condition to be
	// reported; it does not ask for it to be repeated indefinitely.
	reported bool
}

// NewThroughputDetector returns a detector against the target goodput of transportName.
func NewThroughputDetector(transportName string, targetBytesPerSecond int64) *ThroughputDetector {
	return &ThroughputDetector{
		targetBytesPerSecond: targetBytesPerSecond,
		transportName:        transportName,
	}
}

// Sample records one per-second goodput measurement and returns the degraded-throughput
// report at the moment the window completes, or nil.
//
// A sample at or above target clears the count and re-arms the report, so a link that
// recovers and degrades again is reported again.
func (d *ThroughputDetector) Sample(measuredBytesPerSecond int64) *DegradedThroughput {
	d.lastMeasured = measuredBytesPerSecond
	d.haveMeasured = true

	if measuredBytesPerSecond >= d.targetBytesPerSecond {
		d.consecutiveBelow = 0
		d.reported = false
		return nil
	}

	d.consecutiveBelow++
	if d.consecutiveBelow < DetectionSamples || d.reported {
		return nil
	}
	d.reported = true
	return &DegradedThroughput{
		ActiveTransportName:    d.transportName,
		MeasuredBytesPerSecond: measuredBytesPerSecond,
		TargetBytesPerSecond:   d.targetBytesPerSecond,
	}
}

// ConsecutiveBelowTarget is how many consecutive samples have been under target.
func (d *ThroughputDetector) ConsecutiveBelowTarget() int { return d.consecutiveBelow }

// Degraded reports whether the window has completed and not since recovered.
func (d *ThroughputDetector) Degraded() bool { return d.consecutiveBelow >= DetectionSamples }

// LastMeasured is the most recent sample, and false before the first one.
func (d *ThroughputDetector) LastMeasured() (int64, bool) { return d.lastMeasured, d.haveMeasured }

// Rebind resets the detector to a new Transport and target, called when a Session rebinds
// (Req 3.3). The count starts over, because ten below-target samples on a dying LAN link say
// nothing about the Bluetooth link that replaced it.
func (d *ThroughputDetector) Rebind(transportName string, targetBytesPerSecond int64) {
	d.transportName = transportName
	d.targetBytesPerSecond = targetBytesPerSecond
	d.consecutiveBelow = 0
	d.reported = false
}

// StallDetector reports when a Transfer's acknowledged byte count has not increased for ten
// consecutive seconds (Req 13.6).
//
// The rule is "no increase", not "no activity". A Transfer that keeps resending a chunk
// nobody acknowledges is exactly the case worth reporting, and it is busy the whole time,
// so watching the acknowledged count rather than the send activity is what catches it.
//
// Not safe for concurrent use.
type StallDetector struct {
	transferId string

	lastAcknowledged int64
	haveSample       bool
	consecutiveFlat  int
	reported         bool
}

// NewStallDetector returns a detector for the named Transfer.
func NewStallDetector(transferId string) *StallDetector {
	return &StallDetector{transferId: transferId}
}

// Sample records one per-second acknowledged byte count and returns the stall indication at
// the moment the window completes, or nil.
//
// activeTransportName, goodput, and rtt are passed in because Req 13.6 requires the
// indication to name them, and they belong to the Transport rather than to the Transfer. The
// first sample never reports: there is nothing to compare it against.
func (d *StallDetector) Sample(
	acknowledgedBytes int64,
	activeTransportName string,
	goodputBytesPerSecond, roundTripMillis int64,
) *StallIndication {
	if !d.haveSample {
		d.lastAcknowledged = acknowledgedBytes
		d.haveSample = true
		return nil
	}

	if acknowledgedBytes > d.lastAcknowledged {
		d.lastAcknowledged = acknowledgedBytes
		d.consecutiveFlat = 0
		d.reported = false
		return nil
	}
	// A count that went backwards is nonsense - acknowledgements only accumulate - so it
	// is treated as flat rather than as progress, which is the conservative reading.
	d.lastAcknowledged = maxInt64(d.lastAcknowledged, acknowledgedBytes)

	d.consecutiveFlat++
	if d.consecutiveFlat < DetectionSamples || d.reported {
		return nil
	}
	d.reported = true
	return &StallIndication{
		TransferId:            d.transferId,
		ActiveTransportName:   activeTransportName,
		GoodputBytesPerSecond: goodputBytesPerSecond,
		RoundTripMillis:       roundTripMillis,
	}
}

// ConsecutiveFlatSamples is how many consecutive samples showed no increase.
func (d *StallDetector) ConsecutiveFlatSamples() int { return d.consecutiveFlat }

// Stalled reports whether the window has completed and progress has not since resumed.
func (d *StallDetector) Stalled() bool { return d.consecutiveFlat >= DetectionSamples }

// AcknowledgedBytes is the highest acknowledged count seen.
func (d *StallDetector) AcknowledgedBytes() int64 { return d.lastAcknowledged }

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
