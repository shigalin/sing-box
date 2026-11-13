package snell

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-snell/snellv4"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestPSKUserUpdatesAreAtomic(t *testing.T) {
	for _, version := range []int{5, 6} {
		in, err := NewInbound(context.Background(), nil, log.NewNOPFactory().NewLogger("test"), "snell", option.SnellInboundOptions{Version: version, AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{UserPSK: true}})
		require.NoError(t, err)
		h := in.(*Inbound)
		alice := option.SnellUser{Name: "alice", PSK: "alice-independent-psk"}
		bob := option.SnellUser{Name: "bob", PSK: "bob-independent-psk"}
		require.NoError(t, h.UpdateUsers([]option.SnellUser{alice, bob}))
		old := h.psk.entries["alice"]
		require.NoError(t, h.UpdateUsers([]option.SnellUser{bob, alice}))
		require.Same(t, old, h.psk.entries["alice"])
		require.Error(t, h.UpdateUsers([]option.SnellUser{alice, {Name: "bob", PSK: alice.PSK}}))
		require.Same(t, old, h.psk.entries["alice"])
		require.Len(t, h.psk.entries, 2)
		require.Error(t, h.UpdateUsers([]option.SnellUser{{PSK: alice.PSK}}))
		require.NoError(t, h.UpdateUsers(nil))
		require.Empty(t, h.psk.entries)
		require.NoError(t, h.UpdateUsers([]option.SnellUser{alice}))
		require.NotSame(t, old, h.psk.entries["alice"])
	}
}

func TestPSKUnsafeRawIsRejectedEvenWithoutUsers(t *testing.T) {
	_, err := NewInbound(context.Background(), nil, log.NewNOPFactory().NewLogger("test"), "snell", option.SnellInboundOptions{Version: 6, AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{UserPSK: true}, V6Options: option.SnellV6Options{Mode: "unsafe-raw"}})
	require.Error(t, err)
}

func TestPSKDetourRequiresNamedShadowTLSGateway(t *testing.T) {
	in, err := NewInbound(context.Background(), nil, log.NewNOPFactory().NewLogger("test"), "snell", option.SnellInboundOptions{Version: 6, AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{UserPSK: true, AuthDetour: "shadowtls-in", Users: []option.SnellUser{{Name: "alice", PSK: "alice-independent-psk"}, {Name: "bob", PSK: "bob-independent-psk"}}}})
	require.NoError(t, err)
	h := in.(*Inbound)
	for _, meta := range []adapter.InboundContext{{}, {LastInbound: "other", InboundType: C.TypeShadowTLS, User: "alice"}, {LastInbound: "shadowtls-in", InboundType: C.TypeSOCKS, User: "alice"}} {
		_, _, err = h.selectPSK(nil, meta)
		require.Error(t, err)
	}
}

func TestPSKCloseInterruptsPendingAuthentication(t *testing.T) {
	in, err := NewInbound(context.Background(), nil, log.NewNOPFactory().NewLogger("test"), "snell", option.SnellInboundOptions{Version: 6, AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{UserPSK: true, Users: []option.SnellUser{{Name: "alice", PSK: "alice-independent-psk"}}}})
	require.NoError(t, err)
	h := in.(*Inbound)
	local, peer := net.Pipe()
	defer peer.Close()
	done := make(chan struct{})
	go func() { defer close(done); h.NewConnection(context.Background(), local, adapter.InboundContext{}, nil) }()
	require.Eventually(t, func() bool { h.psk.access.RLock(); defer h.psk.access.RUnlock(); return len(h.psk.conns) == 1 }, time.Second, time.Millisecond)
	require.NoError(t, h.closePSKConnections())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pending handshake survived inbound close")
	}
	require.Empty(t, h.psk.conns)
	require.ErrorIs(t, h.UpdateUsers(nil), net.ErrClosed)
}

// stalledConn reports that a probe reached its read and then delivers nothing.
type stalledConn struct {
	net.Conn
	reading chan<- struct{}
	release <-chan struct{}
}

func (c *stalledConn) Read([]byte) (int, error) {
	c.reading <- struct{}{}
	<-c.release
	return 0, io.EOF
}

func (*stalledConn) SetReadDeadline(time.Time) error { return nil }

// pskHello is the first flight a v4 client sends to a v5 server.
func pskHello(t *testing.T, psk string) []byte {
	client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(psk)})
	require.NoError(t, err)
	wire := &probeBufferConn{buffer: new(bytes.Buffer)}
	_, err = client.DialConn(wire, M.ParseSocksaddr("127.0.0.1:80"))
	require.NoError(t, err)
	return wire.buffer.Bytes()
}

func newPSKTestInbound(t *testing.T, psk string) (*Inbound, []byte) {
	in, err := NewInbound(context.Background(), nil, log.NewNOPFactory().NewLogger("test"), "snell", option.SnellInboundOptions{Version: 5, AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{UserPSK: true, Users: []option.SnellUser{{Name: "alice", PSK: psk}}}})
	require.NoError(t, err)
	return in.(*Inbound), pskHello(t, psk)
}

// Peers that connect and send nothing must not keep valid clients out.
func TestPSKSilentConnectionsHoldNoProbeSlot(t *testing.T) {
	h, hello := newPSKTestInbound(t, "alice-independent-psk")
	slots := pskProbeConcurrency
	reading := make(chan struct{}, slots)
	release := make(chan struct{})
	defer close(release)
	for i := 0; i < slots; i++ {
		go h.selectPSK(&stalledConn{reading: reading, release: release}, adapter.InboundContext{})
	}
	for i := 0; i < slots; i++ {
		select {
		case <-reading:
		case <-time.After(time.Second):
			t.Fatal("silent connection never reached its read")
		}
	}
	entry, _, err := h.selectPSK(&probeBufferConn{buffer: bytes.NewBuffer(hello)}, adapter.InboundContext{})
	require.NoError(t, err)
	require.Equal(t, "alice", entry.name)
}

func TestPSKLookupWaitsForProbeSlot(t *testing.T) {
	h, hello := newPSKTestInbound(t, "alice-independent-psk")
	holdPSKPermits(h.psk.admission, pskProbeBudget, pskProbeConcurrency)
	result := make(chan error, 1)
	lookup := func() {
		_, _, err := h.selectPSK(&probeBufferConn{buffer: bytes.NewBuffer(hello)}, adapter.InboundContext{})
		result <- err
	}
	finished := func() error {
		t.Helper()
		select {
		case err := <-result:
			return err
		case <-time.After(time.Second):
			t.Fatal("lookup is still waiting for a probe slot")
			return nil
		}
	}

	go lookup()
	select {
	case err := <-result:
		t.Fatal("lookup did not wait for a probe slot: ", err)
	case <-time.After(50 * time.Millisecond):
	}
	freePSKPermit(h.psk.admission, pskProbeBudget)
	require.NoError(t, finished())

	// Closing the inbound must not leave lookups queued until the deadline.
	holdPSKPermits(h.psk.admission, pskProbeBudget, 1)
	go lookup()
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, h.closePSKConnections())
	require.Error(t, finished())
}

// helloConn replays a client's first flight and discards what the server writes.
type helloConn struct {
	net.Conn
	reader *bytes.Reader
}

func (c *helloConn) Read(p []byte) (int, error)     { return c.reader.Read(p) }
func (*helloConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*helloConn) Close() error                     { return nil }
func (*helloConn) SetReadDeadline(time.Time) error  { return nil }
func (*helloConn) SetWriteDeadline(time.Time) error { return nil }

type userRouter struct {
	adapter.Router
	users chan string
}

func (r *userRouter) RouteConnectionEx(_ context.Context, _ net.Conn, metadata adapter.InboundContext, _ N.CloseHandlerFunc) {
	r.users <- metadata.User
}

// A source that already authenticated is matched without a probe slot, so it
// neither scans every user nor waits behind lookups from unknown sources.
func TestPSKReturningSourceNeedsNoProbeSlot(t *testing.T) {
	const alicePSK, bobPSK = "alice-independent-psk", "bob-independent-psk"
	router := &userRouter{users: make(chan string, 1)}
	in, err := NewInbound(context.Background(), router, log.NewNOPFactory().NewLogger("test"), "snell", option.SnellInboundOptions{Version: 5, AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{UserPSK: true, Users: []option.SnellUser{{Name: "alice", PSK: alicePSK}, {Name: "bob", PSK: bobPSK}}}})
	require.NoError(t, err)
	h := in.(*Inbound)
	known := adapter.InboundContext{Source: M.ParseSocksaddr("192.0.2.1:50000")}
	go h.NewConnection(context.Background(), &helloConn{reader: bytes.NewReader(pskHello(t, alicePSK))}, known, nil)
	select {
	case user := <-router.users:
		require.Equal(t, "alice", user)
	case <-time.After(time.Second):
		t.Fatal("first connection was not routed")
	}

	holdPSKPermits(h.psk.admission, pskProbeBudget, pskProbeConcurrency)
	lookup := func(metadata adapter.InboundContext) chan *pskEntry {
		result := make(chan *pskEntry, 1)
		go func() {
			entry, _, _ := h.selectPSK(&helloConn{reader: bytes.NewReader(pskHello(t, alicePSK))}, metadata)
			result <- entry
		}()
		return result
	}
	known.Source = M.ParseSocksaddr("192.0.2.1:50001")
	select {
	case entry := <-lookup(known):
		require.NotNil(t, entry)
		require.Equal(t, "alice", entry.name)
	case <-time.After(time.Second):
		t.Fatal("returning source waited for a probe slot")
	}
	unknown := lookup(adapter.InboundContext{Source: M.ParseSocksaddr("192.0.2.2:50000")})
	select {
	case <-unknown:
		t.Fatal("unknown source did not wait for a probe slot")
	case <-time.After(50 * time.Millisecond):
	}
	freePSKPermit(h.psk.admission, pskProbeBudget)
	select {
	case entry := <-unknown:
		require.NotNil(t, entry)
		require.Equal(t, "alice", entry.name)
	case <-time.After(time.Second):
		t.Fatal("lookup is still waiting for a probe slot")
	}

	// A removed user leaves no hint behind.
	require.NoError(t, h.UpdateUsers([]option.SnellUser{{Name: "bob", PSK: bobPSK}}))
	require.Empty(t, h.psk.hints)
}

func TestPSKSourceHintsAreBounded(t *testing.T) {
	state := &pskState{hints: make(map[netip.Addr][]*pskEntry)}
	source := netip.MustParseAddr("192.0.2.1")
	entries := make([]*pskEntry, pskHintsPerSource+1)
	for i := range entries {
		entries[i] = &pskEntry{name: strconv.Itoa(i)}
		state.rememberSource(source, entries[i])
	}
	require.Equal(t, []*pskEntry{entries[4], entries[3], entries[2], entries[1]}, state.hints[source])
	state.rememberSource(source, entries[2])
	require.Equal(t, []*pskEntry{entries[2], entries[4], entries[3], entries[1]}, state.hints[source])
	state.rememberSource(netip.Addr{}, entries[0])
	for i := 0; i < pskHintSources+8; i++ {
		state.rememberSource(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), entries[0])
	}
	require.Len(t, state.hints, pskHintSources)
}
