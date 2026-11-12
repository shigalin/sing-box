package main

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
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

	// Create with the tag of a running inbound replaces it.
	require.NoError(t, create(mixedInbound(inboundManagerPortB)))
	testTCP(t, inboundManagerPortB, updateTestPort)
	requireNotListening(t, inboundManagerPortA)
	require.Len(t, manager.Inbounds(), 1)
	current, loaded := manager.Get("mixed-in")
	require.True(t, loaded)

	// An inbound that fails to start is not added and replaces nothing.
	busy, err := net.Listen("tcp", ":"+F.ToString(inboundManagerBusyPort))
	require.NoError(t, err)
	defer busy.Close()
	other := mixedInbound(inboundManagerBusyPort)
	other.Tag = "other"
	require.Error(t, create(other))
	_, loaded = manager.Get("other")
	require.False(t, loaded)
	require.Error(t, create(mixedInbound(inboundManagerBusyPort)))
	stillCurrent, loaded := manager.Get("mixed-in")
	require.True(t, loaded)
	require.Same(t, current, stillCurrent)
	require.Len(t, manager.Inbounds(), 1)
	testTCP(t, inboundManagerPortB, updateTestPort)

	// Close closes every inbound and can be repeated.
	require.NoError(t, manager.Close())
	requireNotListening(t, inboundManagerPortB)
	require.Empty(t, manager.Inbounds())
	require.NoError(t, manager.Close())
}
