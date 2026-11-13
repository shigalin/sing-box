package snell

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

type observedProbeConn struct {
	net.Conn
	reads chan struct{}
}

func (c *observedProbeConn) Read(p []byte) (int, error) { c.reads <- struct{}{}; return c.Conn.Read(p) }

func TestPSKV6FragmentedHintAndShortHeader(t *testing.T) {
	for _, name := range []string{"long_cached", "long_cached_probe_queue_full", "short_uncached", "close_queued"} {
		longUser := strings.HasPrefix(name, "long_cached")
		t.Run(name, func(t *testing.T) {
			users := make([]option.SnellUser, 20)
			for i := range users {
				users[i] = option.SnellUser{Name: fmt.Sprint("user-", i), PSK: fmt.Sprint("independent-test-psk-", i)}
			}
			in, err := NewInbound(context.Background(), nil, log.NewNOPFactory().NewLogger("test"), "snell", option.SnellInboundOptions{Version: 6, AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{UserPSK: true, Users: users}})
			require.NoError(t, err)
			h := in.(*Inbound)
			short, long := h.psk.ordered[0], h.psk.ordered[len(users)-1]
			require.Less(t, short.service.PSKHeaderSize(), long.service.PSKHeaderSize())
			source := adapter.InboundContext{Source: M.ParseSocksaddr("192.0.2.1:50001")}
			h.psk.access.Lock()
			h.psk.rememberSource(source.Source.Addr, long)
			h.psk.access.Unlock()
			target := short
			if longUser {
				target = long
			}
			client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(target.key)})
			require.NoError(t, err)
			wire := &probeBufferConn{buffer: new(bytes.Buffer)}
			_, err = client.DialConn(wire, M.ParseSocksaddr("127.0.0.1:80"))
			require.NoError(t, err)
			hello := append([]byte(nil), wire.buffer.Bytes()...)
			first := short.service.PSKHeaderSize()
			holdPSKPermits(h.psk.admission, pskProbeBudget, pskProbeConcurrency)
			if name == "long_cached_probe_queue_full" {
				// The cached user needs no probe permit, so a probe queue with
				// no room left must not close the connection mid-header.
				h.psk.admission.access.Lock()
				h.psk.admission.budgets[pskProbeBudget].queued = pskProbeQueued
				h.psk.admission.access.Unlock()
			}
			raw, peer := net.Pipe()
			observed := &observedProbeConn{Conn: raw, reads: make(chan struct{}, 32)}
			t.Cleanup(func() { h.closePSKConnections(); raw.Close(); peer.Close() })
			type result struct {
				entry *pskEntry
				conn  net.Conn
				err   error
			}
			results := make(chan result, 1)
			go func() { entry, conn, e := h.selectPSK(observed, source); results <- result{entry, conn, e} }()
			peer.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, err = peer.Write(hello[:first])
			require.NoError(t, err)
			// The first read consumed the shortest header; wait for a second read to
			// prove lookup is still accepting fragments while every CPU slot is busy.
			<-observed.reads
			select {
			case <-observed.reads:
			case <-time.After(time.Second):
				t.Fatal("lookup waits for a probe slot instead of the cached user's fragment")
			}
			if name == "close_queued" {
				require.NoError(t, h.closePSKConnections())
				select {
				case got := <-results:
					require.ErrorIs(t, got.err, net.ErrClosed)
				case <-time.After(time.Second):
					t.Fatal("queued read survived inbound close")
				}
				return
			}
			if longUser {
				_, err = peer.Write(hello[first:long.service.PSKHeaderSize()])
				require.NoError(t, err)
			} else {
				// No bytes for the long hint arrive. Releasing a slot must allow the valid
				// short header to match without waiting for that speculative read.
				freePSKPermit(h.psk.admission, pskProbeBudget)
			}
			var got result
			select {
			case got = <-results:
			case <-time.After(time.Second):
				t.Fatal("lookup blocked on slots or a longer hinted header")
			}
			require.NoError(t, got.err)
			require.Same(t, target, got.entry)
			sent := first
			if longUser {
				sent = long.service.PSKHeaderSize()
			}
			written := make(chan error, 1)
			go func() { _, e := peer.Write(hello[sent:]); written <- e }()
			got.conn.SetReadDeadline(time.Now().Add(time.Second))
			replay := make([]byte, len(hello))
			_, err = io.ReadFull(got.conn, replay)
			require.NoError(t, err)
			require.Equal(t, hello, replay, "prefix and pending read must not lose or duplicate bytes")
			require.NoError(t, <-written)
			got.conn.Close()
		})
	}
}

// A cached short-header user that cannot be verified yet must not hold back a
// full-table match whose longer header has already arrived.
func TestPSKBusyHintBudgetDoesNotBlockFullTableLookup(t *testing.T) {
	users := make([]option.SnellUser, 20)
	for i := range users {
		users[i] = option.SnellUser{Name: fmt.Sprint("user-", i), PSK: fmt.Sprint("independent-test-psk-", i)}
	}
	in, err := NewInbound(context.Background(), nil, log.NewNOPFactory().NewLogger("test"), "snell", option.SnellInboundOptions{Version: 6, AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{UserPSK: true, Users: users}})
	require.NoError(t, err)
	h := in.(*Inbound)
	t.Cleanup(func() { h.closePSKConnections() })
	short, long := h.psk.ordered[0], h.psk.ordered[len(users)-1]
	require.Less(t, short.size, long.size)
	source := adapter.InboundContext{Source: M.ParseSocksaddr("192.0.2.1:50001")}
	h.psk.access.Lock()
	h.psk.rememberSource(source.Source.Addr, short)
	h.psk.access.Unlock()
	holdPSKPermits(h.psk.admission, pskHintBudget, pskHintConcurrency)
	client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(long.key)})
	require.NoError(t, err)
	wire := &probeBufferConn{buffer: new(bytes.Buffer)}
	_, err = client.DialConn(wire, M.ParseSocksaddr("127.0.0.1:80"))
	require.NoError(t, err)
	result := make(chan *pskEntry, 1)
	go func() { entry, _, _ := h.selectPSK(wire, source); result <- entry }()
	select {
	case entry := <-result:
		require.Same(t, long, entry)
	case <-time.After(time.Second):
		t.Fatal("full-table lookup waited for the cached candidate's budget")
	}
}
