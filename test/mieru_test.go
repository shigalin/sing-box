package main

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

const (
	mieruServerPort uint16 = 10200 + iota
	mieruClientPortA
	mieruClientPortB
	mieruClientPortC
	mieruClientPortD
	mieruClientPortE
	mieruTestPort
)

func mieruServerOptions(users []option.MieruUser) option.Options {
	return option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeMieru,
				Tag:  "mieru-in",
				Options: &option.MieruInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: mieruServerPort,
					},
					Users:     users,
					Transport: "TCP",
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeDirect,
			},
		},
	}
}

func mieruClientOptions(listenPort uint16, userName string, password string) option.Options {
	return option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeMixed,
				Tag:  "mixed-in",
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: listenPort,
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeMieru,
				Tag:  "mieru-out",
				Options: &option.MieruOutboundOptions{
					ServerOptions: option.ServerOptions{
						Server:     "127.0.0.1",
						ServerPort: mieruServerPort,
					},
					Transport: "TCP",
					UserName:  userName,
					Password:  password,
				},
			},
		},
	}
}

// mieruSocksConnectFails reports whether a SOCKS5 CONNECT through the client
// at clientPort fails within the timeout. A mieru server silently drops
// clients with unknown credentials, so failure shows up as a timeout or a
// closed connection rather than a SOCKS error reply.
func mieruSocksConnectFails(t *testing.T, clientPort uint16, timeout time.Duration) bool {
	conn, err := net.Dial("tcp", "127.0.0.1:"+F.ToString(clientPort))
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(timeout)))
	_, err = conn.Write([]byte{5, 1, 0})
	require.NoError(t, err)
	reply := make([]byte, 2)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	request := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(request[8:], mieruTestPort)
	_, err = conn.Write(request)
	require.NoError(t, err)
	reply = make([]byte, 4)
	_, err = io.ReadFull(conn, reply)
	if err != nil {
		return true
	}
	return reply[1] != 0
}

func TestMieruSelf(t *testing.T) {
	startInstance(t, mieruServerOptions([]option.MieruUser{{Name: "alice", Password: "alice-password"}}))
	startInstance(t, mieruClientOptions(mieruClientPortA, "alice", "alice-password"))
	testTCP(t, mieruClientPortA, mieruTestPort)
}

func TestMieruUpdateUsers(t *testing.T) {
	server := startInstance(t, mieruServerOptions([]option.MieruUser{{Name: "alice", Password: "alice-password"}}))
	startInstance(t, mieruClientOptions(mieruClientPortA, "alice", "alice-password"))
	testTCP(t, mieruClientPortA, mieruTestPort)

	// A client with credentials the server does not know is dropped.
	startInstance(t, mieruClientOptions(mieruClientPortB, "bob", "bob-password"))
	require.True(t, mieruSocksConnectFails(t, mieruClientPortB, 5*time.Second), "bob must be rejected before he is added")

	mieruInbound, loaded := server.Inbound().Get("mieru-in")
	require.True(t, loaded)
	updatable, ok := mieruInbound.(adapter.UpdatableInbound[option.MieruUser])
	require.True(t, ok, "mieru inbound must implement UpdatableInbound")
	require.NoError(t, updatable.UpdateUsers([]option.MieruUser{{Name: "bob", Password: "bob-password"}}))

	// mieru applies a new user set to underlays created afterwards, so a
	// fresh client is used: the rejected client above still holds the
	// underlay it opened against the old user set. The server itself was
	// not restarted, the same listener accepts bob now.
	startInstance(t, mieruClientOptions(mieruClientPortC, "bob", "bob-password"))
	testTCP(t, mieruClientPortC, mieruTestPort)

	// Alice was removed: a fresh client with her credentials is dropped.
	startInstance(t, mieruClientOptions(mieruClientPortD, "alice", "alice-password"))
	require.True(t, mieruSocksConnectFails(t, mieruClientPortD, 5*time.Second), "alice must be rejected after she was removed")

	// An empty update removes every user: a fresh client of the last user
	// is rejected too.
	require.NoError(t, updatable.UpdateUsers(nil))
	startInstance(t, mieruClientOptions(mieruClientPortE, "bob", "bob-password"))
	require.True(t, mieruSocksConnectFails(t, mieruClientPortE, 5*time.Second), "bob must be rejected after all users were removed")
}
