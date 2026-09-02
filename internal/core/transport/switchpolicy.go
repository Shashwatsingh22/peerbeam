package transport

import "time"

// Timing bounds for a rank-based upgrade, fixed by Req 2.8.
const (
	// UpgradeStability is how long a higher ranked candidate must have been
	// continuously available before a Session moves to it (Req 2.8). It exists so
	// a Transport that flaps in and out does not drag the Session with it.
	UpgradeStability = 5 * time.Second
	// UpgradeCooldown is the minimum gap between Transport changes on one Session
	// (Req 2.8). It bounds how often a Session can be moved, independently of how
	// often candidates qualify.
	UpgradeCooldown = 30 * time.Second
)

// SwitchInputs is a snapshot of everything the switch decision depends on. It is
// a plain value on purpose: DecideSwitch holds no clock, spawns nothing, and
// touches no I/O, so the whole of Requirements 2.8, 2.10, 2.11 and 3.3 is
// decidable from data a test can write by hand.
//
// Now is a field rather than a Clock call so one snapshot always yields one
// decision, no matter when it is evaluated.
type SwitchInputs struct {
	// ActiveTransportName is the Transport the Session is currently bound to.
	ActiveTransportName string
	// ActiveExpectedGoodput is that Transport's Req 2.1 figure, which is what an
	// upgrade candidate must strictly beat.
	ActiveExpectedGoodput int64
	// BestCandidateName is the highest ranked candidate other than the active
	// Transport. "" means none remains.
	BestCandidateName string
	// BestCandidateGoodput is that candidate's Req 2.1 figure.
	BestCandidateGoodput int64
	// BestCandidateAvailableSince is when the best candidate last became
	// available. nil means it has no continuous-availability record yet, which
	// can never satisfy the 5-second stability rule.
	BestCandidateAvailableSince *time.Time
	// LastTransportChangeAt anchors the 30-second cooldown. For a Session that
	// has never switched, this is when it first connected.
	LastTransportChangeAt time.Time
	// PinnedTransportName is the user's pin, or "" for no pin (Req 2.10).
	PinnedTransportName string
	// ActiveIsAvailable is false once keepalive has struck the active Transport
	// out (Req 3.2).
	ActiveIsAvailable bool
	// ActiveUnavailableReason explains why the active Transport went away. It is
	// carried through into the disconnect reason because Req 2.11 asks the report
	// to name both the pinned Transport and why it became unavailable.
	ActiveUnavailableReason string
	Now                     time.Time
}

// SwitchDecision is a tagged result: exactly one of Stay / Upgrade / Rebind /
// GoDisconnected is set. Go has no sealed sum type, so the invariant is stated
// rather than enforced; Kind reports which branch holds so callers can switch on
// one value instead of testing four fields in the right order.
type SwitchDecision struct {
	Stay           bool
	Upgrade        string // Req 2.8: target Transport name
	Rebind         string // Req 3.3: target Transport name
	GoDisconnected string // Req 2.11 and 3.6: reason, never empty when set
}

// DecisionKind names the branch a SwitchDecision took.
type DecisionKind uint8

const (
	DecisionStay DecisionKind = iota
	DecisionUpgrade
	DecisionRebind
	DecisionGoDisconnected
	// DecisionInvalid means no branch was set, which only a hand-built zero value
	// can produce. DecideSwitch never returns it.
	DecisionInvalid
)

func (k DecisionKind) String() string {
	switch k {
	case DecisionStay:
		return "stay"
	case DecisionUpgrade:
		return "upgrade"
	case DecisionRebind:
		return "rebind"
	case DecisionGoDisconnected:
		return "disconnect"
	default:
		return "invalid"
	}
}

// Kind reports which single branch of the decision holds. The order of tests
// matters only for a malformed value with several fields set; DecideSwitch never
// builds one.
func (d SwitchDecision) Kind() DecisionKind {
	switch {
	case d.Stay:
		return DecisionStay
	case d.Upgrade != "":
		return DecisionUpgrade
	case d.Rebind != "":
		return DecisionRebind
	case d.GoDisconnected != "":
		return DecisionGoDisconnected
	default:
		return DecisionInvalid
	}
}

// Target is the Transport a switch or rebind moves to, or "" for the other two
// branches.
func (d SwitchDecision) Target() string {
	switch d.Kind() {
	case DecisionUpgrade:
		return d.Upgrade
	case DecisionRebind:
		return d.Rebind
	default:
		return ""
	}
}

// DecideSwitch is the whole switch rule table as one pure function. The branches
// are ordered by precedence, and that order is the specification:
//
//  1. A pin overrides everything (Req 2.10, 2.11). A pinned Session is never
//     upgraded and never rebound; it either stays or goes disconnected.
//  2. An unavailable active Transport rebinds to the best remaining candidate,
//     or disconnects when none remains (Req 3.3, 3.6).
//  3. A healthy Session upgrades only when a strictly faster candidate has been
//     continuously available for 5 seconds and 30 seconds have passed since the
//     last change (Req 2.8).
//  4. Otherwise it stays.
//
// On the pin branch, the decision assumes the pin is already reflected in the
// Session's binding: the Transport_Manager applies a pin by restricting the
// candidate set before the ladder runs, so the active Transport is the pinned one
// by construction. That is why an available pinned Session is Stay rather than a
// rebind onto the pin.
//
// "Strictly faster" is deliberate. A candidate that merely equals the active
// Transport's expected goodput is not worth the interruption, and equality with
// a >= test would make two same-speed Transports swap on every cooldown expiry.
func DecideSwitch(i SwitchInputs) SwitchDecision {
	// 1. Pin: use that Transport or nothing (Req 2.10, 2.11).
	if i.PinnedTransportName != "" {
		if i.ActiveIsAvailable {
			return SwitchDecision{Stay: true}
		}
		return SwitchDecision{GoDisconnected: pinnedUnavailableReason(i)}
	}

	// 2. Active Transport died: rebind, or disconnect if nothing remains.
	if !i.ActiveIsAvailable {
		if i.BestCandidateName != "" {
			return SwitchDecision{Rebind: i.BestCandidateName} // Req 3.3
		}
		return SwitchDecision{GoDisconnected: "no candidate transport available"} // Req 3.6
	}

	// 3. Healthy: consider an upgrade. All three conditions must hold (Req 2.8).
	if i.BestCandidateName == "" || i.BestCandidateAvailableSince == nil {
		return SwitchDecision{Stay: true}
	}
	fasterThanActive := i.BestCandidateGoodput > i.ActiveExpectedGoodput
	stableLongEnough := i.Now.Sub(*i.BestCandidateAvailableSince) >= UpgradeStability
	cooldownElapsed := i.Now.Sub(i.LastTransportChangeAt) >= UpgradeCooldown
	if fasterThanActive && stableLongEnough && cooldownElapsed {
		return SwitchDecision{Upgrade: i.BestCandidateName}
	}

	// 4. Nothing qualified.
	return SwitchDecision{Stay: true}
}

// pinnedUnavailableReason builds the Req 2.11 disconnect reason, which must name
// the pinned Transport and why it became unavailable.
func pinnedUnavailableReason(i SwitchInputs) string {
	reason := i.ActiveUnavailableReason
	if reason == "" {
		// Never leave the report vague. The default states what is actually
		// known: the Transport stopped answering.
		reason = "transport marked unavailable"
	}
	return "pinned transport " + i.PinnedTransportName + " unavailable: " + reason
}
