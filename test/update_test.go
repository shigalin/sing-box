package main

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

const (
	updateServerPort uint16 = 10300 + iota
	updateClientPortA
	updateClientPortB
	updateTestPort
)

// userTracker records the user each routed connection was attributed to.
type userTracker struct {
	access sync.Mutex
	users  []string
}

func (t *userTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	t.record(metadata.User)
	return conn
}

func (t *userTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	t.record(metadata.User)
	return conn
}

func (t *userTracker) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {
	t.record(metadata.User)
	return nil
}

func (t *userTracker) record(user string) {
	t.access.Lock()
	defer t.access.Unlock()
	t.users = append(t.users, user)
}

func (t *userTracker) reset() []string {
	t.access.Lock()
	defer t.access.Unlock()
	users := t.users
	t.users = nil
	return users
}

func requireTrackedUser(t *testing.T, tracker *userTracker, expected string) {
	users := tracker.reset()
	require.NotEmpty(t, users, "no connection was routed")
	for _, user := range users {
		require.Equal(t, expected, user)
	}
}

func requireTCPWorks(t *testing.T, clientPort uint16) {
	testTCP(t, clientPort, updateTestPort)
}

// requireTCPFails checks that a TCP connection through the SOCKS client at
// clientPort does not reach a listener on updateTestPort. Servers reject a
// removed user after the client already got its SOCKS reply, so both a failed
// dial and a connection that closes before the reply arrives count as failure.
func requireTCPFails(t *testing.T, clientPort uint16) {
	listener, err := listen("tcp", ":"+F.ToString(updateTestPort))
	require.NoError(t, err)
	defer listener.Close()
	reached := make(chan struct{}, 1)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case reached <- struct{}{}:
			default:
			}
			conn.Close()
		}
	}()
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", clientPort), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", updateTestPort))
	if err == nil {
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		_, err = conn.Write([]byte("ping"))
		if err == nil {
			_, err = io.ReadFull(conn, make([]byte, 4))
		}
		conn.Close()
	}
	require.Error(t, err, "connection must not reach the destination")
	select {
	case <-reached:
		require.Fail(t, "connection reached the destination")
	case <-time.After(500 * time.Millisecond):
	}
}

func mixedInbound(listenPort uint16) option.Inbound {
	return option.Inbound{
		Type: C.TypeMixed,
		Tag:  "mixed-in",
		Options: &option.HTTPMixedInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
				ListenPort: listenPort,
			},
		},
	}
}

func serverListen() option.ListenOptions {
	return option.ListenOptions{
		Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
		ListenPort: updateServerPort,
	}
}

func serverAddress() option.ServerOptions {
	return option.ServerOptions{
		Server:     "127.0.0.1",
		ServerPort: updateServerPort,
	}
}

type updateTestUser[T any] struct {
	secret  string
	options T
}

// runUserUpdateScenario checks the UpdateUsers contract of a server inbound:
// users keep their identity when the list is reordered, removed users are
// rejected, and an empty update rejects everyone.
func runUserUpdateScenario[T any](t *testing.T, server *box.Box, update func([]T) error, alice updateTestUser[T], bob updateTestUser[T], clientOptions func(listenPort uint16, secret string) option.Options) {
	tracker := &userTracker{}
	server.Router().AppendTracker(tracker)
	startInstance(t, clientOptions(updateClientPortA, alice.secret))
	startInstance(t, clientOptions(updateClientPortB, bob.secret))

	requireTCPWorks(t, updateClientPortA)
	requireTrackedUser(t, tracker, "alice")
	requireTCPFails(t, updateClientPortB)
	tracker.reset()

	// bob is added in front of alice: alice keeps her identity.
	require.NoError(t, update([]T{bob.options, alice.options}))
	requireTCPWorks(t, updateClientPortA)
	requireTrackedUser(t, tracker, "alice")
	requireTCPWorks(t, updateClientPortB)
	requireTrackedUser(t, tracker, "bob")

	// alice is removed.
	require.NoError(t, update([]T{bob.options}))
	requireTCPFails(t, updateClientPortA)
	requireTCPWorks(t, updateClientPortB)
	requireTrackedUser(t, tracker, "bob")

	// An empty update removes every user.
	require.NoError(t, update(nil))
	requireTCPFails(t, updateClientPortB)
}

func updatableInbound[T any](t *testing.T, server *box.Box, tag string) func([]T) error {
	serverInbound, loaded := server.Inbound().Get(tag)
	require.True(t, loaded)
	updatable, ok := serverInbound.(adapter.UpdatableInbound[T])
	require.True(t, ok, "inbound must implement UpdatableInbound")
	return updatable.UpdateUsers
}

func TestTrojanUpdateUsers(t *testing.T) {
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	trojanUser := func(name string, password string) updateTestUser[option.TrojanUser] {
		return updateTestUser[option.TrojanUser]{secret: password, options: option.TrojanUser{Name: name, Password: password}}
	}
	alice := trojanUser("alice", "alice-password")
	bob := trojanUser("bob", "bob-password")
	server := startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeTrojan,
				Tag:  "trojan-in",
				Options: &option.TrojanInboundOptions{
					ListenOptions: serverListen(),
					Users:         []option.TrojanUser{alice.options},
					InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
						TLS: &option.InboundTLSOptions{
							Enabled:         true,
							ServerName:      "example.org",
							CertificatePath: certPem,
							KeyPath:         keyPem,
						},
					},
				},
			},
		},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
	})
	runUserUpdateScenario(t, server, updatableInbound[option.TrojanUser](t, server, "trojan-in"), alice, bob, func(listenPort uint16, password string) option.Options {
		return option.Options{
			Inbounds: []option.Inbound{mixedInbound(listenPort)},
			Outbounds: []option.Outbound{
				{
					Type: C.TypeTrojan,
					Tag:  "trojan-out",
					Options: &option.TrojanOutboundOptions{
						ServerOptions: serverAddress(),
						Password:      password,
						OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
							TLS: &option.OutboundTLSOptions{
								Enabled:         true,
								ServerName:      "example.org",
								CertificatePath: certPem,
							},
						},
					},
				},
			},
		}
	})
}

func TestVLESSUpdateUsers(t *testing.T) {
	vlessUser := func(name string) updateTestUser[option.VLESSUser] {
		id := uuid.Must(uuid.NewV4()).String()
		return updateTestUser[option.VLESSUser]{secret: id, options: option.VLESSUser{Name: name, UUID: id}}
	}
	alice := vlessUser("alice")
	bob := vlessUser("bob")
	server := startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeVLESS,
				Tag:  "vless-in",
				Options: &option.VLESSInboundOptions{
					ListenOptions: serverListen(),
					Users:         []option.VLESSUser{alice.options},
				},
			},
		},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
	})
	runUserUpdateScenario(t, server, updatableInbound[option.VLESSUser](t, server, "vless-in"), alice, bob, func(listenPort uint16, id string) option.Options {
		return option.Options{
			Inbounds: []option.Inbound{mixedInbound(listenPort)},
			Outbounds: []option.Outbound{
				{
					Type: C.TypeVLESS,
					Tag:  "vless-out",
					Options: &option.VLESSOutboundOptions{
						ServerOptions: serverAddress(),
						UUID:          id,
					},
				},
			},
		}
	})
}

func TestVMessUpdateUsers(t *testing.T) {
	vmessUser := func(name string) updateTestUser[option.VMessUser] {
		id := uuid.Must(uuid.NewV4()).String()
		return updateTestUser[option.VMessUser]{secret: id, options: option.VMessUser{Name: name, UUID: id}}
	}
	alice := vmessUser("alice")
	bob := vmessUser("bob")
	server := startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeVMess,
				Tag:  "vmess-in",
				Options: &option.VMessInboundOptions{
					ListenOptions: serverListen(),
					Users:         []option.VMessUser{alice.options},
				},
			},
		},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
	})
	runUserUpdateScenario(t, server, updatableInbound[option.VMessUser](t, server, "vmess-in"), alice, bob, func(listenPort uint16, id string) option.Options {
		return option.Options{
			Inbounds: []option.Inbound{mixedInbound(listenPort)},
			Outbounds: []option.Outbound{
				{
					Type: C.TypeVMess,
					Tag:  "vmess-out",
					Options: &option.VMessOutboundOptions{
						ServerOptions: serverAddress(),
						UUID:          id,
						Security:      "auto",
					},
				},
			},
		}
	})
}

func TestShadowsocksUpdateUsers(t *testing.T) {
	method := "2022-blake3-aes-128-gcm"
	serverPassword := mkBase64(t, 16)
	ssUser := func(name string) updateTestUser[option.ShadowsocksUser] {
		password := mkBase64(t, 16)
		return updateTestUser[option.ShadowsocksUser]{secret: password, options: option.ShadowsocksUser{Name: name, Password: password}}
	}
	alice := ssUser("alice")
	bob := ssUser("bob")
	server := startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeShadowsocks,
				Tag:  "ss-in",
				Options: &option.ShadowsocksInboundOptions{
					ListenOptions: serverListen(),
					Method:        method,
					Password:      serverPassword,
					Users:         []option.ShadowsocksUser{alice.options},
				},
			},
		},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
	})
	serverInbound, loaded := server.Inbound().Get("ss-in")
	require.True(t, loaded)
	updatable, ok := serverInbound.(adapter.UpdatableShadowsocksInbound)
	require.True(t, ok, "shadowsocks inbound must implement UpdatableShadowsocksInbound")
	runUserUpdateScenario(t, server, updatable.UpdateUsersByOptions, alice, bob, ssClientOptions(method, serverPassword))
}

func ssClientOptions(method string, serverPassword string) func(listenPort uint16, password string) option.Options {
	return func(listenPort uint16, password string) option.Options {
		return option.Options{
			Inbounds: []option.Inbound{mixedInbound(listenPort)},
			Outbounds: []option.Outbound{
				{
					Type: C.TypeShadowsocks,
					Tag:  "ss-out",
					Options: &option.ShadowsocksOutboundOptions{
						ServerOptions: serverAddress(),
						Method:        method,
						Password:      serverPassword + ":" + password,
					},
				},
			},
		}
	}
}

// TestShadowsocksUpdateUsersRollback checks that an update the service
// rejects leaves the accepted user set in place, on the service and in the
// user table alike.
func TestShadowsocksUpdateUsersRollback(t *testing.T) {
	method := "2022-blake3-aes-128-gcm"
	serverPassword := mkBase64(t, 16)
	alice := option.ShadowsocksUser{Name: "alice", Password: mkBase64(t, 16)}
	server := startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeShadowsocks,
				Tag:  "ss-in",
				Options: &option.ShadowsocksInboundOptions{
					ListenOptions: serverListen(),
					Method:        method,
					Password:      serverPassword,
					Users:         []option.ShadowsocksUser{alice},
				},
			},
		},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
	})
	serverInbound, loaded := server.Inbound().Get("ss-in")
	require.True(t, loaded)
	updatable, ok := serverInbound.(adapter.UpdatableShadowsocksInbound)
	require.True(t, ok, "shadowsocks inbound must implement UpdatableShadowsocksInbound")
	startInstance(t, ssClientOptions(method, serverPassword)(updateClientPortA, alice.Password))
	requireTCPWorks(t, updateClientPortA)

	require.Error(t, updatable.UpdateUsersByOptions([]option.ShadowsocksUser{alice, {Name: "bob", Password: "not a key"}}), "an invalid PSK must be rejected")
	requireTCPWorks(t, updateClientPortA)
	require.Error(t, updatable.UpdateUsersByOptions([]option.ShadowsocksUser{{Name: "bob", Password: mkBase64(t, 8)}}), "a short PSK must be rejected")
	requireTCPWorks(t, updateClientPortA)

	require.NoError(t, updatable.UpdateUsersByOptions([]option.ShadowsocksUser{{Name: "bob", Password: mkBase64(t, 16)}}))
	requireTCPFails(t, updateClientPortA)
}

func rejectRuleSetRules(tags ...string) []option.Rule {
	return []option.Rule{
		{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					RuleSet: tags,
				},
				RuleAction: option.RuleAction{
					Action:        C.RuleActionTypeReject,
					RejectOptions: option.RejectActionOptions{Method: C.RuleActionRejectMethodDefault},
				},
			},
		},
	}
}

func inlineIPRuleSet(tag string, cidr string) option.RuleSet {
	return option.RuleSet{
		Type: C.RuleSetTypeInline,
		Tag:  []string{tag},
		InlineOptions: option.PlainRuleSet{
			Rules: []option.HeadlessRule{
				{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultHeadlessRule{
						IPCIDR: []string{cidr},
					},
				},
			},
		},
	}
}

func localRuleSet(tag string, path string) option.RuleSet {
	return option.RuleSet{
		Type:         C.RuleSetTypeLocal,
		Tag:          []string{tag},
		Format:       C.RuleSetFormatSource,
		LocalOptions: option.LocalRuleSet{Path: path},
	}
}

// TestRouterUpdateRules checks that UpdateRules binds the new rules to the
// new rule-sets, keeps unchanged rule-sets, and keeps the current state when
// an update fails.
func TestRouterUpdateRules(t *testing.T) {
	const harmless = "10.255.255.255/32"
	const loopback = "127.0.0.1/32"
	localPath := filepath.Join(t.TempDir(), "local.json")
	require.NoError(t, os.WriteFile(localPath, []byte(`{"version":1,"rules":[{"ip_cidr":["`+harmless+`"]}]}`), 0o644))
	local := localRuleSet("local", localPath)
	rules := rejectRuleSetRules("blocked", "local")

	instance := startInstance(t, option.Options{
		Inbounds:  []option.Inbound{mixedInbound(updateClientPortA)},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
		Route: &option.RouteOptions{
			Rules:   rules,
			RuleSet: []option.RuleSet{inlineIPRuleSet("blocked", harmless), local},
		},
	})
	router := instance.Router()
	ruleSet := func(tag string) adapter.RuleSet {
		return routerRuleSet(t, router, tag)
	}
	requireTCPWorks(t, updateClientPortA)
	initialLocal := ruleSet("local")

	// A changed rule-set is replaced, and the new rules match against it.
	require.NoError(t, router.UpdateRules(rules, []option.RuleSet{inlineIPRuleSet("blocked", loopback), local}))
	requireTCPFails(t, updateClientPortA)
	require.Same(t, initialLocal, ruleSet("local"), "unchanged rule-set must be reused")

	// Restoring the rule-set lifts the block.
	require.NoError(t, router.UpdateRules(rules, []option.RuleSet{inlineIPRuleSet("blocked", harmless), local}))
	requireTCPWorks(t, updateClientPortA)
	restoredBlocked := ruleSet("blocked")

	// An update with identical rule-sets reuses them.
	require.NoError(t, router.UpdateRules(rules, []option.RuleSet{inlineIPRuleSet("blocked", harmless), local}))
	require.Same(t, restoredBlocked, ruleSet("blocked"))
	require.Same(t, initialLocal, ruleSet("local"))
	requireTCPWorks(t, updateClientPortA)

	// A failing update keeps the current rules and rule-sets.
	require.NoError(t, router.UpdateRules(rules, []option.RuleSet{inlineIPRuleSet("blocked", loopback), local}))
	requireTCPFails(t, updateClientPortA)
	blocking := ruleSet("blocked")
	require.Error(t, router.UpdateRules(rejectRuleSetRules("blocked", "missing"), []option.RuleSet{inlineIPRuleSet("blocked", harmless), local}), "a rule with an unknown rule-set must fail")
	require.Same(t, blocking, ruleSet("blocked"))
	require.Same(t, initialLocal, ruleSet("local"))
	requireTCPFails(t, updateClientPortA)
	require.Error(t, router.UpdateRules(rules, []option.RuleSet{inlineIPRuleSet("blocked", harmless), inlineIPRuleSet("blocked", loopback), local}), "duplicate rule-set tags must fail")
	require.Same(t, blocking, ruleSet("blocked"))
	requireTCPFails(t, updateClientPortA)

	// Dropping a rule-set retires it; the instance closes it on shutdown.
	require.NoError(t, router.UpdateRules(rejectRuleSetRules("blocked"), []option.RuleSet{inlineIPRuleSet("blocked", harmless)}))
	requireTCPWorks(t, updateClientPortA)
	_, loaded := router.RuleSet("local")
	require.False(t, loaded)
}

// TestRouterUpdateRulesNotifiesHooks checks that UpdateRules publishes the
// new rule options and notifies registered hooks, which the reference
// manager relies on to re-evaluate which outbounds are referenced.
func TestRouterUpdateRulesNotifiesHooks(t *testing.T) {
	const harmless = "10.255.255.255/32"
	instance := startInstance(t, option.Options{
		Inbounds:  []option.Inbound{mixedInbound(updateClientPortA)},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
		Route: &option.RouteOptions{
			RuleSet: []option.RuleSet{inlineIPRuleSet("blocked", harmless)},
		},
	})
	router, isRouter := instance.Router().(*route.Router)
	require.True(t, isRouter)
	require.Empty(t, router.RuleOptions())

	hook := observable.NewSubscriber[struct{}](1)
	defer hook.Close()
	router.AddRuleUpdateHook(hook)
	subscription, done := hook.Subscription()

	rules := rejectRuleSetRules("blocked")
	require.NoError(t, router.UpdateRules(rules, []option.RuleSet{inlineIPRuleSet("blocked", harmless)}))
	select {
	case <-subscription:
	case <-done:
		t.Fatal("hook closed before notification")
	case <-time.After(time.Second):
		t.Fatal("UpdateRules did not notify hooks")
	}
	require.Equal(t, rules, router.RuleOptions())
}

func routerRuleSet(t *testing.T, router adapter.Router, tag string) adapter.RuleSet {
	set, loaded := router.RuleSet(tag)
	require.True(t, loaded, "rule-set ", tag, " must exist")
	return set
}

// dnsRuleSetOptions returns DNS options with one rule that holds the given
// rule-set.
func dnsRuleSetOptions(tag string) *option.DNSOptions {
	return &option.DNSOptions{
		RawDNSOptions: option.RawDNSOptions{
			Servers: []option.DNSServerOptions{
				{
					Type:    C.DNSTypeLocal,
					Tag:     "local-dns",
					Options: &option.LocalDNSServerOptions{},
				},
			},
			Rules: []option.DNSRule{
				{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultDNSRule{
						RawDefaultDNSRule: option.RawDefaultDNSRule{
							RuleSet: []string{tag},
						},
						DNSRuleAction: option.DNSRuleAction{
							Action:       C.RuleActionTypeRoute,
							RouteOptions: option.DNSRouteActionOptions{Server: "local-dns"},
						},
					},
				},
			},
		},
	}
}

// TestRouterUpdateRulesWithDNSRuleSet checks the handling of a rule-set that
// DNS rules hold: DNS keeps the object it resolved at start, its replacement
// is loaded again when route rules start using it, and the held object is
// closed with the instance (goleak catches its file watcher otherwise).
func TestRouterUpdateRulesWithDNSRuleSet(t *testing.T) {
	// The rule-sets match on the port: an IP CIDR rule-set in a DNS rule
	// would select the legacy address filter mode, which is rejected.
	dir := t.TempDir()
	harmlessPath := filepath.Join(dir, "harmless.json")
	loopbackPath := filepath.Join(dir, "loopback.json")
	require.NoError(t, os.WriteFile(harmlessPath, []byte(`{"version":1,"rules":[{"port":[1]}]}`), 0o644))
	require.NoError(t, os.WriteFile(loopbackPath, []byte(`{"version":1,"rules":[{"port":[`+F.ToString(updateTestPort)+`]}]}`), 0o644))

	instance := startInstance(t, option.Options{
		DNS:       dnsRuleSetOptions("shared"),
		Inbounds:  []option.Inbound{mixedInbound(updateClientPortA)},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
		Route: &option.RouteOptions{
			RuleSet: []option.RuleSet{localRuleSet("shared", harmlessPath)},
		},
	})
	router := instance.Router()
	requireTCPWorks(t, updateClientPortA)
	held := routerRuleSet(t, router, "shared")

	// Only DNS rules use the rule-set: its replacement is published, but the
	// DNS rules keep the object they hold.
	require.NoError(t, router.UpdateRules(nil, []option.RuleSet{localRuleSet("shared", loopbackPath)}))
	replaced := routerRuleSet(t, router, "shared")
	require.NotSame(t, held, replaced)

	// The unreferenced replacement released its content; a route rule that
	// starts using it with unchanged options must still match.
	require.NoError(t, router.UpdateRules(rejectRuleSetRules("shared"), []option.RuleSet{localRuleSet("shared", loopbackPath)}))
	requireTCPFails(t, updateClientPortA)

	// Now a route rule holds it, so it is reused.
	current := routerRuleSet(t, router, "shared")
	require.NoError(t, router.UpdateRules(rejectRuleSetRules("shared"), []option.RuleSet{localRuleSet("shared", loopbackPath)}))
	require.Same(t, current, routerRuleSet(t, router, "shared"))
	requireTCPFails(t, updateClientPortA)
}
