package session

// SequenceTracker is one Session's Message sequence state: the outbound counter
// Req 5.1 advances and the inbound set Req 5.10 uses to spot a duplicate. It is
// part of what Req 3.4 preserves across a Transport change, which is why it lives
// on the Session rather than on the Transport binding.
//
// Not safe for concurrent use. One Session is driven by one goroutine.
type SequenceTracker struct {
	nextOutbound uint64
	seenInbound  map[uint64]struct{}
	// highestInbound tracks the largest sequence accepted so far. It is kept only
	// so a caller can report progress; duplicate detection uses the set, because
	// a reordered Message that arrives after a higher one is not a duplicate.
	highestInbound uint64
	anyInbound     bool
}

// NewSequenceTracker returns a tracker whose first outbound sequence number is 0.
func NewSequenceTracker() *SequenceTracker {
	return &SequenceTracker{seenInbound: map[uint64]struct{}{}}
}

// NextSequence assigns the next outbound sequence number and advances the counter
// (Req 5.1). Assignment and advance are one operation on purpose: a caller that
// could read the counter without advancing it would be one early return away from
// sending two Messages under one number.
//
// Req 5.8 is the reason validation happens before this is called: a rejected
// submission must not advance the counter, so nothing here can be undone.
func (s *SequenceTracker) NextSequence() uint64 {
	n := s.nextOutbound
	s.nextOutbound++
	return n
}

// PeekNextSequence reports the number NextSequence would return, without advancing.
// It is for status output and tests; the send path must use NextSequence.
func (s *SequenceTracker) PeekNextSequence() uint64 { return s.nextOutbound }

// AcceptInbound records a received sequence number and reports whether it is new.
// It returns false for a sequence already seen on this Session, which Req 5.10
// turns into: discard the content, still acknowledge, display once only.
//
// The set is unbounded, which is a deliberate trade for now. A Session would have
// to receive on the order of a hundred million Messages before the map became a
// memory concern, and the alternative, a sliding window, would silently accept a
// duplicate that arrived after the window moved past it. Req 5.10 admits no such
// window, so correctness wins until a bound is actually needed.
func (s *SequenceTracker) AcceptInbound(sequence uint64) bool {
	if _, seen := s.seenInbound[sequence]; seen {
		return false
	}
	s.seenInbound[sequence] = struct{}{}
	if !s.anyInbound || sequence > s.highestInbound {
		s.highestInbound = sequence
		s.anyInbound = true
	}
	return true
}

// SeenInbound reports whether a sequence number has already been accepted, without
// recording it.
func (s *SequenceTracker) SeenInbound(sequence uint64) bool {
	_, seen := s.seenInbound[sequence]
	return seen
}

// HighestInbound is the largest sequence number accepted so far, and false before
// the first inbound Message.
func (s *SequenceTracker) HighestInbound() (uint64, bool) {
	return s.highestInbound, s.anyInbound
}

// InboundCount is how many distinct inbound sequence numbers have been accepted.
func (s *SequenceTracker) InboundCount() int { return len(s.seenInbound) }
