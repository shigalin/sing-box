package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/stretchr/testify/require"
)

func TestSnellLargeUDP(t *testing.T) {
	testSnellLargeUDP(t, false)
}

func TestSnellNATLargeUDP(t *testing.T) {
	testSnellLargeUDP(t, true)
}

func testSnellLargeUDP(t *testing.T, override bool) {
	t.Helper()
	for _, versions := range [][2]int{{5, 4}, {6, 6}} {
		for _, userPSK := range []bool{false, true} {
			for _, reuse := range []bool{false, true} {
				t.Run(fmt.Sprintf("v%d/user_psk=%v/reuse=%v", versions[0], userPSK, reuse), func(t *testing.T) {
					target, err := net.ListenPacket("udp", "127.0.0.1:0")
					require.NoError(t, err)
					done := make(chan struct{})
					go func() {
						defer close(done)
						b := make([]byte, 65535)
						for {
							n, addr, err := target.ReadFrom(b)
							if err != nil {
								return
							}
							if _, err = target.WriteTo(b[:n], addr); err != nil {
								return
							}
						}
					}()
					defer func() { target.Close(); <-done }()
					inbound := &option.SnellInboundOptions{
						Version: versions[0],
						AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{
							ListenOptions: serverListen(), PSK: snellUpdatePSK,
						},
					}
					if userPSK {
						inbound.PSK = ""
						inbound.UserPSK = true
						inbound.Users = []option.SnellUser{{Name: "alice", PSK: snellUpdatePSK}}
					}
					startInstance(t, option.Options{
						Inbounds:  []option.Inbound{{Type: C.TypeSnell, Options: inbound}},
						Outbounds: []option.Outbound{{Type: C.TypeDirect}},
					})
					destination := M.ParseSocksaddr(target.LocalAddr().String())
					var route *option.RouteOptions
					if override {
						destination = M.ParseSocksaddrHostPort("127.0.0.2", destination.Port)
						route = &option.RouteOptions{Rules: []option.Rule{snellUDPRouteRule(option.RuleAction{
							Action:              C.RuleActionTypeRouteOptions,
							RouteOptionsOptions: option.RouteOptionsActionOptions{OverrideAddress: "127.0.0.1"},
						})}}
					}
					startInstance(t, option.Options{
						Route:    route,
						Inbounds: []option.Inbound{mixedInbound(clientPort)},
						Outbounds: []option.Outbound{{
							Type: C.TypeSnell,
							Options: &option.SnellOutboundOptions{
								Version: versions[1],
								AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{
									ServerOptions: serverAddress(), PSK: snellUpdatePSK, Reuse: reuse,
								},
							},
						}},
					})
					client := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", clientPort), socks.Version5, "", "")
					conn, err := client.ListenPacket(context.Background(), destination)
					require.NoError(t, err)
					defer conn.Close()
					// Start large: small warm-up packets must not hide a record growth limit.
					sizes := []int{4096, 1, 1400, 1403, 2800, 8192, 257}
					// macOS limits a native UDP datagram to 9216 bytes by default.
					if runtime.GOOS == "linux" {
						sizes = append(sizes, 16124, 16125, 16364, 16365, 16374)
					}
					for _, size := range sizes {
						payload := make([]byte, size)
						for i := range payload {
							payload[i] = byte(i*31 + size)
						}
						require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
						_, err = conn.WriteTo(payload, destination.UDPAddr())
						require.NoError(t, err, "send %d-byte datagram", size)
						reply := make([]byte, 65535)
						n, _, err := conn.ReadFrom(reply)
						require.NoError(t, err, "receive %d-byte datagram", size)
						require.Equal(t, size, n, "datagram was truncated")
						require.True(t, bytes.Equal(payload, reply[:n]), "datagram contents changed")
					}
				})
			}
		}
	}
}

func TestSnellV5LargeFirstUDP(t *testing.T) {
	testSnellLargeFirstUDP(t, 5)
}

func TestSnellV6LargeFirstUDP(t *testing.T) {
	testSnellLargeFirstUDP(t, 6)
}

func testSnellLargeFirstUDP(t *testing.T, serverVersion int) {
	t.Helper()
	sniffRule := snellUDPRouteRule(option.RuleAction{Action: C.RuleActionTypeSniff})
	timeoutRule := snellUDPRouteRule(option.RuleAction{
		Action:              C.RuleActionTypeRouteOptions,
		RouteOptionsOptions: option.RouteOptionsActionOptions{UDPTimeout: badoption.Duration(30 * time.Second)},
	})
	for _, test := range []struct {
		name  string
		rules []option.Rule
	}{
		{"direct", nil},
		{"sniff", []option.Rule{sniffRule}},
		{"udp_timeout", []option.Rule{timeoutRule}},
		{"sniff_and_udp_timeout", []option.Rule{sniffRule, timeoutRule}},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer target.Close()
			conn := newSnellUDPTunnel(t, serverVersion, test.rules...)

			// Exceed the 8 KiB low-memory packet buffer on the very first request.
			payload := bytes.Repeat([]byte{0x73}, 8500)
			_, err = conn.WriteTo(payload, target.LocalAddr())
			require.NoError(t, err)
			require.NoError(t, target.SetReadDeadline(time.Now().Add(2*time.Second)))
			request := make([]byte, len(payload)+1)
			n, _, err := target.ReadFrom(request)
			require.NoError(t, err)
			require.Equal(t, len(payload), n)
			require.True(t, bytes.Equal(payload, request[:n]), "first datagram contents changed")
		})
	}
}

// Exercise the actual socket receive buffer, not just a record writer supplied
// with an already complete buffer. Above-limit replies must never arrive as a
// truncated, apparently valid datagram.
func TestSnellV5UDPResponseBoundary(t *testing.T) {
	testSnellUDPResponseBoundary(t, 5, 16376, 16364)
}

func TestSnellV5UDPConnectResponseBoundary(t *testing.T) {
	testSnellUDPResponseBoundary(t, 5, 16376, 16364, snellUDPRouteRule(option.RuleAction{
		Action:              C.RuleActionTypeRouteOptions,
		RouteOptionsOptions: option.RouteOptionsActionOptions{UDPConnect: true},
	}))
}

func TestSnellV6UDPResponseBoundary(t *testing.T) {
	// A v6 record has 65535 bytes, including the 7- or 19-byte response header.
	testSnellUDPResponseBoundary(t, 6, 65528, 65516)
}

func testSnellUDPResponseBoundary(t *testing.T, serverVersion int, ipv4Limit int, ipv6Limit int, rules ...option.Rule) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("large native UDP datagrams require the Linux test runner")
	}
	for _, network := range []string{"udp4", "udp6"} {
		host, limit, maxDatagram := "127.0.0.1", ipv4Limit, 65507
		if network == "udp6" {
			host, limit, maxDatagram = "::1", ipv6Limit, 65527
		}
		sizes := []int{maxDatagram}
		if limit+1 < maxDatagram {
			sizes = append([]int{limit - 1, limit, limit + 1}, sizes...)
		}
		for _, size := range sizes {
			t.Run(fmt.Sprintf("%s/size=%d", network, size), func(t *testing.T) {
				want := bytes.Repeat([]byte{0x73}, size)
				if size > limit {
					want = []byte("reply after oversized datagram")
				}
				target, err := net.ListenPacket(network, net.JoinHostPort(host, "0"))
				require.NoError(t, err)
				done := make(chan struct{})
				sent := make(chan error, 1)
				go func() {
					defer close(done)
					request := make([]byte, 2)
					n, addr, e := target.ReadFrom(request)
					if e != nil {
						sent <- e
						return
					}
					if n != 2 {
						sent <- fmt.Errorf("bad request length %d", n)
						return
					}
					payload := bytes.Repeat([]byte{0x73}, int(binary.BigEndian.Uint16(request)))
					_, e = target.WriteTo(payload, addr)
					if e == nil && size > limit {
						_, e = target.WriteTo(want, addr)
					}
					sent <- e
				}()
				defer func() { target.Close(); <-done }()
				conn := newSnellUDPTunnel(t, serverVersion, rules...)
				request := make([]byte, 2)
				binary.BigEndian.PutUint16(request, uint16(size))
				_, err = conn.WriteTo(request, target.LocalAddr())
				require.NoError(t, err)
				select {
				case err = <-sent:
					require.NoError(t, err)
				case <-time.After(2 * time.Second):
					t.Fatal("target did not send reply")
				}
				reply := make([]byte, 65535)
				n, _, err := conn.ReadFrom(reply)
				require.NoError(t, err)
				require.Equal(t, want, reply[:n])
			})
		}
	}
}

func snellUDPRouteRule(action option.RuleAction) option.Rule {
	return option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{Network: []string{N.NetworkUDP}},
			RuleAction:     action,
		},
	}
}

func newSnellUDPTunnel(t *testing.T, serverVersion int, rules ...option.Rule) N.NetPacketConn {
	t.Helper()
	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: C.TypeSnell,
			Options: &option.SnellInboundOptions{
				Version: serverVersion,
				AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{
					ListenOptions: serverListen(), PSK: snellUpdatePSK,
				},
			},
		}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
		Route:     &option.RouteOptions{Rules: rules},
	})
	var method snell.Method
	var err error
	if serverVersion == 5 {
		method, err = snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(snellUpdatePSK)})
	} else {
		method, err = snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(snellUpdatePSK)})
	}
	require.NoError(t, err)
	raw, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(serverAddress().ServerPort)), 2*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { raw.Close() })
	require.NoError(t, raw.SetDeadline(time.Now().Add(2*time.Second)))
	conn, err := method.DialPacketConn(raw)
	require.NoError(t, err)
	return conn
}
