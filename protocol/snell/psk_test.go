package snell

import (
	"context"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
	"time"
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
