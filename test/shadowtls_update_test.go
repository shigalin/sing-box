package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

const (
	shadowTLSUpdateHandshakePort uint16 = 10310 + iota
	shadowTLSUpdateDetourPort
)

// startShadowTLSHandshakeServer runs the TLS 1.3 server the ShadowTLS inbound
// relays handshakes to, so the test does not depend on a public website.
func startShadowTLSHandshakeServer(t *testing.T, certPem string, keyPem string) {
	certificate, err := tls.LoadX509KeyPair(certPem, keyPem)
	require.NoError(t, err)
	listener, err := listen("tcp", "127.0.0.1:"+F.ToString(shadowTLSUpdateHandshakePort))
	require.NoError(t, err)
	t.Cleanup(func() {
		listener.Close()
	})
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, tls.Server(conn, tlsConfig))
			}(conn)
		}
	}()
}

// A ShadowTLS inbound authenticates the users of a Snell inbound that has
// none of its own: the Snell requests carry the ShadowTLS user.
func testShadowTLSUpdateUsers(t *testing.T, serverVersion int, clientVersion int, reuse bool) {
	caPem, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	startShadowTLSHandshakeServer(t, certPem, keyPem)
	shadowTLSUser := func(name string) updateTestUser[option.ShadowTLSUser] {
		return updateTestUser[option.ShadowTLSUser]{secret: name + "-password", options: option.ShadowTLSUser{Name: name, Password: name + "-password"}}
	}
	alice := shadowTLSUser("alice")
	bob := shadowTLSUser("bob")
	listenOptions := serverListen()
	listenOptions.Detour = "snell-in"
	server := startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeShadowTLS,
				Tag:  "shadowtls-in",
				Options: &option.ShadowTLSInboundOptions{
					ListenOptions: listenOptions,
					Version:       3,
					Users:         []option.ShadowTLSUser{alice.options},
					Handshake: option.ShadowTLSHandshakeOptions{
						ServerOptions: option.ServerOptions{
							Server:     "127.0.0.1",
							ServerPort: shadowTLSUpdateHandshakePort,
						},
					},
					StrictMode: true,
				},
			},
			{
				Type: C.TypeSnell,
				Tag:  "snell-in",
				Options: &option.SnellInboundOptions{
					Version: serverVersion,
					AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     common.Ptr(badoption.Addr(netip.AddrFrom4([4]byte{127, 0, 0, 1}))),
							ListenPort: shadowTLSUpdateDetourPort,
						},
						PSK: snellUpdatePSK,
					},
				},
			},
		},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
	})
	runUserUpdateScenario(t, server, updatableInbound[option.ShadowTLSUser](t, server, "shadowtls-in"), alice, bob, func(listenPort uint16, password string) option.Options {
		return option.Options{
			Inbounds: []option.Inbound{mixedInbound(listenPort)},
			Outbounds: []option.Outbound{
				{
					Type: C.TypeSnell,
					Tag:  "snell-out",
					Options: &option.SnellOutboundOptions{
						Version: clientVersion,
						AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{
							DialerOptions: option.DialerOptions{Detour: "shadowtls-out"},
							ServerOptions: serverAddress(),
							PSK:           snellUpdatePSK,
							Reuse:         reuse,
						},
					},
				},
				{
					Type: C.TypeShadowTLS,
					Tag:  "shadowtls-out",
					Options: &option.ShadowTLSOutboundOptions{
						ServerOptions: serverAddress(),
						Version:       3,
						Password:      password,
						OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
							TLS: &option.OutboundTLSOptions{
								Enabled:         true,
								ServerName:      "example.org",
								CertificatePath: caPem,
							},
						},
					},
				},
			},
		}
	})
}

func TestShadowTLSUpdateUsers(t *testing.T) {
	testShadowTLSUpdateUsers(t, 5, 4, false)
}

// The update that removes a user closes the connection it is reusing.
func TestShadowTLSUpdateUsersReuse(t *testing.T) {
	testShadowTLSUpdateUsers(t, 5, 4, true)
}

func TestShadowTLSSnellV6UpdateUsers(t *testing.T) {
	testShadowTLSUpdateUsers(t, 6, 6, false)
}

func TestShadowTLSSnellV6UpdateUsersReuse(t *testing.T) {
	testShadowTLSUpdateUsers(t, 6, 6, true)
}
