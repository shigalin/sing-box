package main

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

const snellUpdatePSK = "snell-update-test-psk"

func testSnellUpdateUsers(t *testing.T, serverVersion int, clientVersion int, reuse bool) {
	snellUser := func(name string) updateTestUser[option.SnellUser] {
		return updateTestUser[option.SnellUser]{secret: name + "-key", options: option.SnellUser{Name: name, UserKey: name + "-key"}}
	}
	alice := snellUser("alice")
	bob := snellUser("bob")
	server := startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeSnell,
				Tag:  "snell-in",
				Options: &option.SnellInboundOptions{
					Version: serverVersion,
					AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{
						ListenOptions: serverListen(),
						PSK:           snellUpdatePSK,
						Users:         []option.SnellUser{alice.options},
					},
				},
			},
		},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
	})
	runUserUpdateScenario(t, server, updatableInbound[option.SnellUser](t, server, "snell-in"), alice, bob, func(listenPort uint16, userKey string) option.Options {
		return option.Options{
			Inbounds: []option.Inbound{mixedInbound(listenPort)},
			Outbounds: []option.Outbound{
				{
					Type: C.TypeSnell,
					Tag:  "snell-out",
					Options: &option.SnellOutboundOptions{
						Version: clientVersion,
						AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{
							ServerOptions: serverAddress(),
							PSK:           snellUpdatePSK,
							UserKey:       userKey,
							Reuse:         reuse,
						},
					},
				},
			},
		}
	})
}

func TestSnellUpdateUsers(t *testing.T) {
	testSnellUpdateUsers(t, 5, 4, false)
}

// A reused connection outlives the update that removes its user.
func TestSnellUpdateUsersReuse(t *testing.T) {
	testSnellUpdateUsers(t, 5, 4, true)
}

func TestSnellV6UpdateUsers(t *testing.T) {
	testSnellUpdateUsers(t, 6, 6, false)
}

func TestSnellV6UpdateUsersReuse(t *testing.T) {
	testSnellUpdateUsers(t, 6, 6, true)
}
