package discovery

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/clock"
)

// Registry bounds and defaults that the requirements state explicitly.
const (
	// MaxVisiblePeers is the size of the visible Peer list (Req 1.2).
	MaxVisiblePeers = 64
	// DefaultPeerTTL is how long a Peer may go unobserved on every medium before it
	// is expired (Req 1.5). Expire takes the ttl as a parameter so a caller can
	// sweep with a different window; this is the value the node wires.
	DefaultPeerTTL = 30 * time.Second

	// manualKeyPrefix keys a manually supplied entry whose fingerprint is not known
	// yet. It contains a colon, which is not a lowercase hex character, so a manual
	// key can never collide with a real 64-hex fingerprint key.
	manualKeyPrefix = "manual:"

	// maxHostNameChars and maxHostLabelChars are the DNS name limits used by the
	// syntactic host check.
	maxHostNameChars  = 253
	maxHostLabelChars = 63
)

// PeerRegistry holds the visible Peer list (Req 1.2). It is keyed by public key
// fingerprint, so two announcements carrying the same fingerprint collapse into one
// entry that lists every medium it was seen on (Req 1.8).
//
// Time comes from an injected Clock and nothing here calls time.Now, so the 30-second
// staleness window of Req 1.5 is exercised by advancing a manual clock rather than by
// sleeping. The design sketch passed a `now time.Time` into each method as well; that
// parameter is folded into the Clock so there is exactly one time source and a caller
// cannot hand the registry a timestamp that disagrees with expiry.
//
// Safe for concurrent use. This was originally documented as single-goroutine, on the
// assumption that one goroutine would own the beacon reads, the Bluetooth scan channel,
// and the expiry ticker. That assumption does not survive a node with two media: the LAN
// beacon and the Bluetooth scan are independent sources that discover peers at the same
// time, the expiry sweep runs on its own ticker, and the command layer reads the list
// while all three are running. The lock lives here rather than in each caller because
// this is the shared mutable state, and a lock per caller would mean four separate
// mutexes protecting one map.
//
// The mutex is a leaf: nothing under it calls back out except Clock.Now, so there is no
// lock ordering to respect.
type PeerRegistry struct {
	localVersion int
	clock        clock.Clock

	mu    sync.Mutex
	peers map[string]VisiblePeer // keyed by fingerprint, or by manualKeyPrefix+host
}

// NewPeerRegistry returns an empty registry. localVersion is the protocol version this
// node supports; it is compared against each announcement's declared version to set
// VisiblePeer.ProtocolSupported. An unsupported version is still listed (Req 1.2), just
// flagged, so the user can see the peer and be told why it cannot be used.
func NewPeerRegistry(localVersion int, clk clock.Clock) *PeerRegistry {
	return &PeerRegistry{
		localVersion: localVersion,
		clock:        clk,
		peers:        make(map[string]VisiblePeer),
	}
}

// ObserveOutcome is a tagged result: exactly one of Recorded / Malformed / AtCapacity
// is set. Go has no sealed sum type, so the invariant is stated rather than enforced.
// Callers MUST check Malformed and AtCapacity first; when both are empty, Recorded is
// non-nil and holds the entry as it now stands in the list.
type ObserveOutcome struct {
	Recorded   *ObservationRecorded
	Malformed  []string    // Req 1.11: the announcement was discarded, list unchanged
	AtCapacity *AtCapacity // Req 1.2: the list is full and this fingerprint is new
}

// ObservationRecorded reports an accepted observation. Peer is a copy of the stored
// entry after the upsert, so a caller can report what the list now says without
// reaching into the registry. Added distinguishes a new row from a merge, which is
// what a discovery event needs to say "peer appeared" rather than "peer refreshed".
type ObservationRecorded struct {
	Peer  VisiblePeer
	Added bool
}

// ManualOutcome is a tagged result: exactly one of Recorded / Rejected / AtCapacity is
// set. Callers MUST check Rejected and AtCapacity first; when both are nil, Recorded is
// non-nil. On anything other than Recorded the visible Peer list is unchanged
// (Req 1.10).
type ManualOutcome struct {
	Recorded   *ManualRecorded
	Rejected   *ManualRejected // Req 1.10: names whether the address or the port failed
	AtCapacity *AtCapacity
}

// ManualRecorded reports an accepted manual entry. Added is false when the address
// matched a Peer already in the list, which is the update-in-place case of Req 1.7.
type ManualRecorded struct {
	Peer  VisiblePeer
	Added bool
}

// ManualRejected is the rejection of Req 1.10. Both reasons are reported when both
// fields are bad, so the error always names the address when the address was at fault
// and always names the port when the port was at fault. At least one reason is
// non-empty.
type ManualRejected struct {
	Address       string
	Port          int
	AddressReason string // non-empty exactly when the address was rejected
	PortReason    string // non-empty exactly when the port was rejected
}

// RejectedAddress and RejectedPort let a caller branch on which field failed without
// parsing the message.
func (e *ManualRejected) RejectedAddress() bool { return e.AddressReason != "" }
func (e *ManualRejected) RejectedPort() bool    { return e.PortReason != "" }

func (e *ManualRejected) Error() string {
	var parts []string
	if e.AddressReason != "" {
		parts = append(parts, fmt.Sprintf("address %q rejected: %s", e.Address, e.AddressReason))
	}
	if e.PortReason != "" {
		parts = append(parts, fmt.Sprintf("port %d rejected: %s", e.Port, e.PortReason))
	}
	if len(parts) == 0 {
		return "manual peer rejected with no reason set"
	}
	return "manual peer " + strings.Join(parts, "; ")
}

// AtCapacity reports a Peer turned away because the visible Peer list already holds
// MaxVisiblePeers entries (Req 1.2).
//
// The choice here is rejection, not eviction. Evicting the least recently seen entry
// to make room would let a peer that fabricates fingerprints push every genuine peer
// out of the list one announcement at a time, and the list is the thing the user picks
// a peer from. Rejecting instead makes the list first-come-first-served and bounded,
// and expiry frees slots on its own within the Req 1.5 window. A fingerprint already
// in the list is never turned away: it updates in place, so a full list still tracks
// the peers it holds.
type AtCapacity struct {
	Attempted string // the fingerprint, or the host:port of a manual add
	Limit     int
}

func (e *AtCapacity) Error() string {
	return fmt.Sprintf("visible peer list holds the maximum of %d peers, %s was not added", e.Limit, e.Attempted)
}

// Observe folds an observed announcement into the list, upserting by fingerprint and
// merging the medium (Req 1.8). address is where the peer was reached on this medium:
// an IP literal for LAN, a device id for Bluetooth. It is not shape-checked, because a
// Bluetooth device id is not an address at all and the value came from the local
// transport rather than from user input; only an empty address is rejected.
//
// The announcement is re-validated here even though the beacon path already calls
// CheckAnnouncement. That is defence in depth on the one thing the registry cannot
// recover from: a malformed fingerprint becoming a map key would break the one-entry
// -per-fingerprint invariant of Req 1.8 for the lifetime of the process.
//
// Observing a fingerprint on a second medium merges rather than replaces: the entry
// ends up with an endpoint per medium, each holding the most recent address and port
// seen on that medium.
func (r *PeerRegistry) Observe(a Announcement, medium Medium, address string) ObserveOutcome {
	check := CheckAnnouncement(&a)
	if check.Malformed != nil {
		return ObserveOutcome{Malformed: check.Malformed}
	}
	if address == "" {
		return ObserveOutcome{Malformed: []string{"observed address is missing"}}
	}

	// Locked from here: the validation above is pure, and holding the lock across it would
	// serialise every source's parsing behind one peer's malformed record.
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.clock.Now()
	existing, found := r.peers[a.Fingerprint]

	// A manual entry supplies a host and port but no fingerprint, so it sits under a
	// placeholder key until the peer is actually heard from. This is that moment: the
	// placeholder is folded into the fingerprint-keyed entry and removed, which is what
	// keeps a manually added peer from showing up twice once it announces.
	promotedKey, promoted := r.manualKeyForAddress(medium, address)

	if !found && !promoted && len(r.peers) >= MaxVisiblePeers {
		return ObserveOutcome{AtCapacity: &AtCapacity{Attempted: a.Fingerprint, Limit: MaxVisiblePeers}}
	}

	entry := VisiblePeer{
		Fingerprint:             a.Fingerprint,
		DisplayName:             a.DisplayName,
		DeclaredProtocolVersion: a.ProtocolVersion,
		ProtocolSupported:       a.ProtocolVersion == r.localVersion,
		Endpoints:               map[Medium]PeerEndpoint{},
	}
	if found {
		entry.Endpoints = copyEndpoints(existing.Endpoints)
		// ManuallySupplied is sticky: the user's annotation should survive the peer
		// being discovered automatically afterwards.
		entry.ManuallySupplied = existing.ManuallySupplied
	}
	if promoted {
		entry.ManuallySupplied = true
		delete(r.peers, promotedKey)
	}
	// Most recent address and port win for this medium; other media keep theirs
	// (Req 1.8).
	entry.Endpoints[medium] = PeerEndpoint{
		Medium:   medium,
		Address:  address,
		Port:     a.Port,
		LastSeen: now,
	}
	r.peers[a.Fingerprint] = entry

	return ObserveOutcome{Recorded: &ObservationRecorded{Peer: copyPeer(entry), Added: !found}}
}

// AddManual records a user-supplied host and port (Req 1.6, 1.7, 1.10). The entry is
// accepted only when the port is within MinPort..MaxPort and the address is
// well-formed; on rejection the visible Peer list is left exactly as it was and the
// error names the address, the port, or both.
//
// A manual entry carries no fingerprint: the user knows an address, and the peer's key
// is not known until the peer is contacted and its announcement or handshake arrives.
// Three consequences, all deliberate:
//
//   - If the host already appears as the address of an existing entry, that entry is
//     updated in place and annotated (Req 1.7). Address is the only handle available,
//     so it is what identity is decided on here.
//   - Otherwise the entry is stored under a placeholder key derived from the host, with
//     an empty Fingerprint and DisplayName, and MediaFor cannot find it yet. Observe
//     folds the placeholder into the real fingerprint-keyed entry the first time the
//     peer is heard from, so no fingerprint ever ends up with two rows.
//   - Two different addresses for one peer stay two placeholder entries until that
//     promotion happens. Nothing at this layer can tell they are the same machine.
//
// A user-supplied host and port is an IP-network address, so it is recorded on
// MediumLAN. Bluetooth peers are not addressable by hand.
//
// A manual entry ages like any other: its endpoint carries the time it was added, and
// expiry applies one rule to every entry with no exemptions (see Expire). Keeping a
// manual entry alive without announcements is therefore the caller's job.
func (r *PeerRegistry) AddManual(host string, port int) ManualOutcome {
	rejected := &ManualRejected{Address: host, Port: port}
	if reason := hostRejectionReason(host); reason != "" {
		rejected.AddressReason = reason
	}
	if port < MinPort || port > MaxPort {
		rejected.PortReason = fmt.Sprintf("outside %d..%d", MinPort, MaxPort)
	}
	if rejected.AddressReason != "" || rejected.PortReason != "" {
		return ManualOutcome{Rejected: rejected}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.clock.Now()
	canonical := canonicalHost(host)

	// Req 1.7: an address already in the list updates that entry rather than adding a
	// second one. This also covers re-adding the same manual host on a different port.
	if key, found := r.keyForAddress(MediumLAN, canonical); found {
		entry := copyPeer(r.peers[key])
		entry.ManuallySupplied = true
		entry.Endpoints[MediumLAN] = PeerEndpoint{
			Medium:   MediumLAN,
			Address:  canonical,
			Port:     port,
			LastSeen: now,
		}
		r.peers[key] = entry
		return ManualOutcome{Recorded: &ManualRecorded{Peer: copyPeer(entry), Added: false}}
	}

	if len(r.peers) >= MaxVisiblePeers {
		return ManualOutcome{AtCapacity: &AtCapacity{
			Attempted: fmt.Sprintf("%s port %d", host, port),
			Limit:     MaxVisiblePeers,
		}}
	}

	entry := VisiblePeer{
		// Fingerprint and DisplayName stay empty: neither is known from an address.
		// They are filled in when Observe promotes this entry.
		ProtocolSupported: false,
		Endpoints: map[Medium]PeerEndpoint{
			MediumLAN: {Medium: MediumLAN, Address: canonical, Port: port, LastSeen: now},
		},
		ManuallySupplied: true,
	}
	r.peers[manualKeyPrefix+canonical] = entry
	return ManualOutcome{Recorded: &ManualRecorded{Peer: copyPeer(entry), Added: true}}
}

// Expire removes every Peer whose most recent observation on every medium is at least
// ttl old, and returns the keys removed in ascending order (Req 1.5). A Peer observed
// within ttl on at least one medium is retained, even if its other media have gone
// quiet: it is still reachable on the medium that answered.
//
// The returned key is the fingerprint for a discovered Peer and the placeholder key for
// a manual entry that has not been promoted yet, since that is what identifies the row
// that went.
//
// One rule applies to every entry, manual ones included. An exemption would make the
// list unbounded in practice, and "not seen for 30 seconds" means the same thing
// however the entry got there.
func (r *PeerRegistry) Expire(ttl time.Duration) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.clock.Now()
	var removed []string
	for key, peer := range r.peers {
		if !stale(peer, now, ttl) {
			continue
		}
		removed = append(removed, key)
		delete(r.peers, key)
	}
	sort.Strings(removed)
	return removed
}

// Visible returns the visible Peer list (Req 1.2), ordered by key so repeated calls
// agree. Every entry is a deep copy, including its Endpoints map, so a caller cannot
// mutate registry state through the returned slice.
func (r *PeerRegistry) Visible() []VisiblePeer {
	r.mu.Lock()
	defer r.mu.Unlock()

	keys := make([]string, 0, len(r.peers))
	for key := range r.peers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]VisiblePeer, 0, len(keys))
	for _, key := range keys {
		out = append(out, copyPeer(r.peers[key]))
	}
	return out
}

// MediaFor returns the media the fingerprint is currently present on (Req 1.8). The
// returned map is freshly built, so mutating it does not touch the registry. It is nil
// when the fingerprint is not in the list, which includes a manual entry that has not
// been promoted yet and therefore has no fingerprint to ask about.
func (r *PeerRegistry) MediaFor(fingerprint string) map[Medium]struct{} {
	if fingerprint == "" {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	peer, found := r.peers[fingerprint]
	if !found {
		return nil
	}
	media := make(map[Medium]struct{}, len(peer.Endpoints))
	for medium := range peer.Endpoints {
		media[medium] = struct{}{}
	}
	return media
}

// Len is the current size of the visible Peer list, bounded by MaxVisiblePeers.
func (r *PeerRegistry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.peers)
}

// stale reports whether every medium of peer has gone quiet for at least ttl. An entry
// with no endpoints cannot be reached on anything, so it counts as stale.
func stale(peer VisiblePeer, now time.Time, ttl time.Duration) bool {
	for _, endpoint := range peer.Endpoints {
		if now.Sub(endpoint.LastSeen) < ttl {
			return false
		}
	}
	return true
}

// keyForAddress finds the entry currently reachable at address on medium. Addresses are
// compared canonically, so the same host in different letter case is one peer.
//
// Two entries can legitimately share an address: two Peer_Nodes on one machine differ
// only by port, and they carry different fingerprints. Selection is therefore made
// deterministic rather than left to map iteration order: an unpromoted manual entry is
// preferred, since that is the one a manual add is refining, and otherwise the lowest
// key wins.
func (r *PeerRegistry) keyForAddress(medium Medium, canonical string) (string, bool) {
	best := ""
	for key, peer := range r.peers {
		endpoint, found := peer.Endpoints[medium]
		if !found || canonicalHost(endpoint.Address) != canonical {
			continue
		}
		if best == "" || preferredKey(key, best) {
			best = key
		}
	}
	return best, best != ""
}

// preferredKey reports whether candidate should win over current.
func preferredKey(candidate, current string) bool {
	candidateManual := strings.HasPrefix(candidate, manualKeyPrefix)
	currentManual := strings.HasPrefix(current, manualKeyPrefix)
	if candidateManual != currentManual {
		return candidateManual
	}
	return candidate < current
}

// manualKeyForAddress finds an unpromoted manual entry sitting at address, so Observe
// can fold it into the fingerprint-keyed entry.
func (r *PeerRegistry) manualKeyForAddress(medium Medium, address string) (string, bool) {
	if medium != MediumLAN {
		return "", false // manual entries are only ever recorded on the IP network
	}
	key, found := r.keyForAddress(medium, canonicalHost(address))
	if !found || !strings.HasPrefix(key, manualKeyPrefix) {
		return "", false
	}
	return key, true
}

func copyPeer(peer VisiblePeer) VisiblePeer {
	peer.Endpoints = copyEndpoints(peer.Endpoints)
	return peer
}

func copyEndpoints(endpoints map[Medium]PeerEndpoint) map[Medium]PeerEndpoint {
	out := make(map[Medium]PeerEndpoint, len(endpoints))
	for medium, endpoint := range endpoints {
		out[medium] = endpoint
	}
	return out
}

// canonicalHost is the form an address is stored and compared in. Hostnames are
// case-insensitive and so is hex in an IPv6 literal, so folding case means one host
// spelled two ways is one entry rather than two.
func canonicalHost(host string) string { return strings.ToLower(host) }

// hostRejectionReason returns why host is not a usable address, or "" when it is
// well-formed. Req 1.10 speaks of an address that "cannot be resolved", but this
// package is pure: no net, no DNS, no sockets, so resolution is not available here and
// the check is purely syntactic. A syntactically fine name that does not resolve is
// therefore accepted at this layer and fails later, at connect time, where the
// connection ladder reports it per Req 2.5.
func hostRejectionReason(host string) string {
	switch {
	case host == "":
		return "missing"
	case len(host) > maxHostNameChars:
		return fmt.Sprintf("longer than %d characters", maxHostNameChars)
	case strings.ContainsAny(host, " \t\r\n/\\@?#"):
		return "contains characters that are not valid in a host address"
	}

	// A bracketed literal is the [::1]:port spelling with the port already split off.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		if isIPv6Literal(host[1 : len(host)-1]) {
			return ""
		}
		return "not a valid IPv6 address"
	}
	if strings.Contains(host, ":") {
		if isIPv6Literal(host) {
			return ""
		}
		return "not a valid IPv6 address"
	}
	// Digits and dots can only be meant as IPv4, so a near-miss like 10.0.0.256 is
	// reported as a bad IPv4 rather than accepted as an odd hostname.
	if onlyDigitsAndDots(host) {
		if isIPv4Literal(host) {
			return ""
		}
		return "not a valid IPv4 address"
	}
	if isHostname(host) {
		return ""
	}
	return "not a valid host name"
}

func onlyDigitsAndDots(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// isIPv4Literal accepts exactly four decimal octets. Leading zeros are rejected because
// they read as octal to some parsers, and one spelling per address keeps the registry
// from holding the same host twice.
func isIPv4Literal(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		if len(part) > 1 && part[0] == '0' {
			return false
		}
		value := 0
		for i := 0; i < len(part); i++ {
			c := part[i]
			if c < '0' || c > '9' {
				return false
			}
			value = value*10 + int(c-'0')
		}
		if value > 255 {
			return false
		}
	}
	return true
}

// isIPv6Literal accepts eight groups of 1..4 hex digits, one "::" run standing in for
// any number of zero groups, and an IPv4 tail in the last two groups. A zone id
// (fe80::1%en0) is rejected: it names a local interface, and this layer cannot know
// which interfaces exist.
func isIPv6Literal(s string) bool {
	if s == "" || strings.Contains(s, "%") {
		return false
	}

	groups := 0
	compressed := false
	i := 0

	if s[0] == ':' {
		if !strings.HasPrefix(s, "::") {
			return false // a single leading colon is not a valid literal
		}
		compressed = true
		i = 2
		if i == len(s) {
			return true // "::" is the all-zero address
		}
	}

	for i < len(s) {
		end := i
		for end < len(s) && s[end] != ':' {
			end++
		}
		group := s[i:end]

		if strings.Contains(group, ".") {
			// An IPv4 tail occupies the last two groups and must end the literal.
			if !isIPv4Literal(group) || end != len(s) {
				return false
			}
			groups += 2
			break
		}
		if len(group) == 0 || len(group) > 4 || !isHexDigits(group) {
			return false
		}
		groups++

		i = end
		if i == len(s) {
			break
		}
		i++ // step over the separating colon
		switch {
		case i < len(s) && s[i] == ':':
			if compressed {
				return false // only one "::" run is allowed
			}
			compressed = true
			i++
			if i == len(s) {
				return groups <= 7 // trailing "::"
			}
		case i == len(s):
			return false // a trailing single colon is not a valid literal
		}
	}

	if compressed {
		return groups <= 7 // "::" must stand for at least one omitted group
	}
	return groups == 8
}

func isHexDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// isHostname accepts a DNS name: dot-separated labels of letters, digits, and hyphens,
// with an optional trailing dot for the fully qualified form.
func isHostname(s string) bool {
	if strings.HasSuffix(s, ".") {
		s = s[:len(s)-1]
	}
	if s == "" {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > maxHostLabelChars {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			alphanumeric := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			if !alphanumeric && c != '-' {
				return false
			}
		}
	}
	return true
}
