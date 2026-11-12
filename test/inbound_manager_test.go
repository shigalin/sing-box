package main

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"

	"github.com/stretchr/testify/require"
)

const (
	inboundManagerPortA uint16 = 10320 + iota
	inboundManagerPortB
	inboundManagerBusyPort
)

func requireNotListening(t *testing.T, port uint16) {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+F.ToString(port), time.Second)
	if err == nil {
		conn.Close()
	}
	require.Error(t, err, "port %d must not accept connections", port)
}

// TestInboundManagerUpdate checks what the inbound manager does on a running
// instance: Remove closes the inbound, Create starts the inbound it adds and
// replaces a running one with the same tag, a failed Create leaves the
// manager as it was, and Close closes every inbound.
func TestInboundManagerUpdate(t *testing.T) {
	// The managers are looked up in the context, so the instance needs a
	// registry of its own instead of the one the other tests share.
	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: option.Options{
			Log:       &option.LogOptions{Level: "warning"},
			Inbounds:  []option.Inbound{mixedInbound(inboundManagerPortA)},
			Outbounds: []option.Outbound{{Type: C.TypeDirect}},
		},
	})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() {
		instance.Close()
		cancel()
	})
	manager := instance.Inbound()
	tags := func() []string {
		return common.Map(manager.Inbounds(), adapter.Inbound.Tag)
	}
	create := func(inbound option.Inbound) error {
		logger := instance.LogFactory().NewLogger("inbound/" + inbound.Type + "[" + inbound.Tag + "]")
		return manager.Create(ctx, instance.Router(), logger, inbound.Tag, inbound.Type, inbound.Options)
	}
	testTCP(t, inboundManagerPortA, updateTestPort)

	// Remove closes the inbound.
	require.NoError(t, manager.Remove("mixed-in"))
	requireNotListening(t, inboundManagerPortA)
	_, loaded := manager.Get("mixed-in")
	require.False(t, loaded)
	require.ErrorIs(t, manager.Remove("mixed-in"), os.ErrInvalid)

	// Create starts the inbound, on the port that was just released.
	require.NoError(t, create(mixedInbound(inboundManagerPortA)))
	testTCP(t, inboundManagerPortA, updateTestPort)

	// Create with the tag of a running inbound replaces it, also on the port
	// the running one listens on.
	previous, loaded := manager.Get("mixed-in")
	require.True(t, loaded)
	require.NoError(t, create(mixedInbound(inboundManagerPortA)))
	testTCP(t, inboundManagerPortA, updateTestPort)
	current, loaded := manager.Get("mixed-in")
	require.True(t, loaded)
	require.NotSame(t, previous, current)
	require.NoError(t, create(mixedInbound(inboundManagerPortB)))
	testTCP(t, inboundManagerPortB, updateTestPort)
	requireNotListening(t, inboundManagerPortA)
	require.Len(t, manager.Inbounds(), 1)

	// A replacement takes the place of the inbound it replaces.
	first := mixedInbound(inboundManagerPortA)
	first.Tag = "first"
	require.NoError(t, create(first))
	require.NoError(t, manager.Remove("mixed-in"))
	require.NoError(t, create(mixedInbound(inboundManagerPortB)))
	require.Equal(t, []string{"first", "mixed-in"}, tags())
	require.NoError(t, create(first))
	require.Equal(t, []string{"first", "mixed-in"}, tags())

	// An inbound that fails to start is not added. The inbound it was to
	// replace is not brought back from what it was created from, which could
	// let removed users back in: it stays closed, and the caller restores it.
	busy, err := net.Listen("tcp", ":"+F.ToString(inboundManagerBusyPort))
	require.NoError(t, err)
	defer busy.Close()
	other := mixedInbound(inboundManagerBusyPort)
	other.Tag = "other"
	require.Error(t, create(other))
	_, loaded = manager.Get("other")
	require.False(t, loaded)
	require.Equal(t, []string{"first", "mixed-in"}, tags())
	require.Error(t, create(mixedInbound(inboundManagerBusyPort)))
	_, loaded = manager.Get("mixed-in")
	require.False(t, loaded)
	requireNotListening(t, inboundManagerPortB)
	require.Equal(t, []string{"first"}, tags())
	testTCP(t, inboundManagerPortA, updateTestPort)
	require.NoError(t, create(mixedInbound(inboundManagerPortB)))
	testTCP(t, inboundManagerPortB, updateTestPort)

	// Close closes every inbound and can be repeated.
	require.NoError(t, manager.Close())
	requireNotListening(t, inboundManagerPortB)
	require.Empty(t, manager.Inbounds())
	require.NoError(t, manager.Close())
}
