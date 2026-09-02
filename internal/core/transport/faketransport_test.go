package transport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"pgregory.net/rapid"

	"github.com/peerbeam/peerbeam/internal/core/discovery"
)

// This file holds the test doubles shared by ranker_test.go and ladder_test.go.
// They exist so every property in Requirements 2 and 3 runs with no socket, no
// radio, and no sleeping beyond a millisecond-scale attempt timeout.

// behaviour is what a fakeTransport does when Connect is called.
type behaviour uint8

const (
	behaveSucceed    behaviour = iota // returns a live fakeConnection
	behaveRefuse                      // returns an error immediately
	behaveTimeout                     // blocks until the attempt context expires
	behaveNoEndpoint                  // endpointFor reports no endpoint, so Connect is never called
	behaveNilNil                      // returns (nil, nil): a broken Transport
)

func (b behaviour) String() string {
	switch b {
	case behaveSucceed:
		return "succeed"
	case behaveRefuse:
		return "refuse"
	case behaveTimeout:
		return "timeout"
	case behaveNoEndpoint:
		return "no-endpoint"
	case behaveNilNil:
		return "nil-nil"
	default:
		return fmt.Sprintf("behaviour(%d)", uint8(b))
	}
}

// probe records what the ladder did. It is shared by every fakeTransport in one
// ladder run, which is what lets the test assert ordering and the
// one-attempt-at-a-time rule in Req 2.3 across the whole candidate set.
type probe struct {
	mu          sync.Mutex
	connectLog  []string // Transport names in the order Connect was called
	open        int      // attempts currently inside Connect
	maxOpen     int      // high-water mark; Req 2.3 requires this to stay at 1
	closedConns int
}

func (p *probe) enter(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.connectLog = append(p.connectLog, name)
	p.open++
	if p.open > p.maxOpen {
		p.maxOpen = p.open
	}
}

func (p *probe) leave() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.open--
}

func (p *probe) log() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.connectLog...)
}

func (p *probe) highWater() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.maxOpen
}

// fakeTransport is a Transport whose ranking inputs and connect outcome are both
// fixed by the test.
type fakeTransport struct {
	name      string
	medium    discovery.Medium
	goodput   int64
	chunk     int
	behave    behaviour
	probe     *probe
	listenErr error
}

func (f *fakeTransport) Name() string                         { return f.name }
func (f *fakeTransport) Medium() discovery.Medium             { return f.medium }
func (f *fakeTransport) ExpectedGoodputBytesPerSecond() int64 { return f.goodput }
func (f *fakeTransport) ChunkSizeBytes() int                  { return f.chunk }
func (f *fakeTransport) Listen(context.Context, func(TransportConnection)) error {
	return f.listenErr
}

var errRefused = errors.New("connection refused")

func (f *fakeTransport) Connect(ctx context.Context, _ discovery.PeerEndpoint, _ time.Duration) (TransportConnection, error) {
	if f.probe != nil {
		f.probe.enter(f.name)
		defer f.probe.leave()
	}
	switch f.behave {
	case behaveSucceed:
		return &fakeConnection{name: f.name, probe: f.probe}, nil
	case behaveRefuse:
		return nil, errRefused
	case behaveNilNil:
		return nil, nil
	case behaveTimeout:
		// Wait for the ladder's per-attempt deadline rather than sleeping a
		// fixed duration, so the test proves the deadline is what ends the
		// attempt (Req 2.4).
		<-ctx.Done()
		return nil, ctx.Err()
	default:
		return nil, fmt.Errorf("unexpected behaviour %s", f.behave)
	}
}

// fakeConnection is the minimum that satisfies TransportConnection. The ladder
// never reads or writes, so Read and Write only need to be present.
type fakeConnection struct {
	name  string
	probe *probe
}

func (c *fakeConnection) TransportName() string    { return c.name }
func (c *fakeConnection) Write([]byte) error       { return nil }
func (c *fakeConnection) Read([]byte) (int, error) { return 0, nil }
func (c *fakeConnection) Close() error {
	if c.probe != nil {
		c.probe.mu.Lock()
		c.probe.closedConns++
		c.probe.mu.Unlock()
	}
	return nil
}

// endpointLookupFor resolves an endpoint for every Transport except those whose
// behaviour is behaveNoEndpoint, which models a Peer that is visible on the
// medium but holds no reachable address for it.
func endpointLookupFor(specs map[string]behaviour) EndpointLookup {
	return func(t Transport) (discovery.PeerEndpoint, bool) {
		if specs[t.Name()] == behaveNoEndpoint {
			return discovery.PeerEndpoint{}, false
		}
		return discovery.PeerEndpoint{
			Medium:  t.Medium(),
			Address: "203.0.113.7",
			Port:    45771,
		}, true
	}
}

// realTransports builds the two production Transports as fakes carrying their
// real Req 2.1 goodput figures and Req 7.10 chunk sizes.
func realTransports(b behaviour, p *probe) (lan, bt *fakeTransport) {
	lan = &fakeTransport{
		name: NameLAN, medium: discovery.MediumLAN,
		goodput: LANExpectedGoodput, chunk: LANChunkBytes, behave: b, probe: p,
	}
	bt = &fakeTransport{
		name: NameBT, medium: discovery.MediumBluetooth,
		goodput: BTExpectedGoodput, chunk: BTChunkBytes, behave: b, probe: p,
	}
	return lan, bt
}

func names(ts []Transport) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Name())
	}
	return out
}

// requireEqualStrings keeps the property bodies readable. It takes rapid.TB, the
// interface both *testing.T and *rapid.T satisfy, so the same helper serves the
// property tests and the fixed-input unit tests.
func requireEqualStrings(t rapid.TB, got, want []string, what string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %v (%d), want %v (%d)", what, got, len(got), want, len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s: got %v, want %v", what, got, want)
		}
	}
}
