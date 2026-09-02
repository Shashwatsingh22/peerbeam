package transport

import (
	"context"
	"time"

	"github.com/peerbeam/peerbeam/internal/core/discovery"
)

// Transport is one way of reaching a Peer. The interface is deliberately narrow:
// everything above it (ranking, the connection ladder, the switch rule table) is
// pure logic over these six methods, so the whole of Requirements 2 and 3 can be
// exercised against fakes with no socket and no radio in sight.
//
// Concrete implementations live under internal/platform (lan.LanTransport,
// bt.BtTransport). This package must never import net or os.
type Transport interface {
	// Name is the stable identifier used in ranking tie-breaks (Req 2.2), pins
	// (Req 2.10), and failure reports (Req 2.5). It is one of NameLAN / NameBT.
	Name() string
	// Medium is the medium a Peer must be visible on for this Transport to be a
	// candidate (Req 2.1).
	Medium() discovery.Medium
	// ExpectedGoodputBytesPerSecond is the fixed ranking input from Req 2.1. It
	// is the *expected* figure, not a measurement: ranking must be deterministic,
	// so it never reads live metrics.
	ExpectedGoodputBytesPerSecond() int64
	// ChunkSizeBytes is the Transfer chunk size for this Transport (Req 7.10).
	// A rebind re-slices the remaining bytes at the new Transport's size (Req 3.5).
	ChunkSizeBytes() int
	// Connect opens one connection to endpoint. It MUST honour both ctx and
	// timeout and MUST NOT retry internally: retry policy belongs to
	// ConnectLadder, which attempts each Transport exactly once (Req 2.4).
	Connect(ctx context.Context, endpoint discovery.PeerEndpoint, timeout time.Duration) (TransportConnection, error)
	// Listen accepts inbound connections until ctx is done, calling onInbound
	// once per accepted connection.
	Listen(ctx context.Context, onInbound func(TransportConnection)) error
}

// TransportConnection is a bidirectional byte stream. It carries Wire_Frames and
// nothing else, which is what lets the same frame bytes cross either medium
// unchanged (Req 8.9).
type TransportConnection interface {
	// TransportName names the Transport that produced this connection, so a
	// Session can report its active Transport without holding the Transport.
	TransportName() string
	Write(bytes []byte) error
	// Read reads into `into` and returns the byte count, or (0, io.EOF) at end of
	// stream.
	Read(into []byte) (int, error)
	Close() error
}

// Transport names. These are constants rather than inline literals because they
// are compared against user-supplied pin arguments (Req 2.10) and printed in
// failure reports (Req 2.5), and because the ranking tie-break in Req 2.2 is
// defined over them: "BT_Transport" < "LAN_Transport" in byte order.
const (
	NameLAN = "LAN_Transport"
	NameBT  = "BT_Transport"
)

// Expected goodput and chunk sizes, fixed by Requirements 2.1 and 7.10.
const (
	// LANExpectedGoodput is 40 MiB/s (Req 2.1).
	LANExpectedGoodput int64 = 41_943_040
	// BTExpectedGoodput is 40 KiB/s (Req 2.1). The 1024x gap between the two is
	// why the ranker never needs to consult a measurement to order them.
	BTExpectedGoodput int64 = 40_960
	// LANChunkBytes is 64 KiB (Req 7.10).
	LANChunkBytes = 65_536
	// BTChunkBytes is the Bluetooth chunk size (Req 7.10).
	BTChunkBytes = 512
)

// Per-attempt timeouts. Both are per *attempt*, never per ladder: a ladder over
// two candidates is allowed to take two full timeouts.
const (
	// ConnectAttemptTimeout bounds one candidate's connection attempt when a
	// Session is first requested (Req 2.4).
	ConnectAttemptTimeout = 3 * time.Second
	// RebindAttemptTimeout bounds one candidate's attempt when an active
	// Transport died and the Session is rebinding (Req 3.8). It is longer than
	// ConnectAttemptTimeout because Req 3.3 gives the rebind 5 seconds.
	RebindAttemptTimeout = 5 * time.Second
)
