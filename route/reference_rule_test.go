package route

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"

	"github.com/stretchr/testify/require"
)

func routeRule(ruleType string, action string, outbound string) option.Rule {
	return option.Rule{
		Type: ruleType,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{Domain: []string{"example.com"}},
			RuleAction: option.RuleAction{
				Action:       action,
				RouteOptions: option.RouteActionOptions{Outbound: outbound},
			},
		},
	}
}

func dnsRule(ruleType string, action string, server string) option.DNSRule {
	return option.DNSRule{
		Type: ruleType,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{Domain: []string{"example.com"}},
			DNSRuleAction: option.DNSRuleAction{
				Action:       action,
				RouteOptions: option.DNSRouteActionOptions{Server: server},
			},
		},
	}
}

// Rules built in code may omit Type, which the rule constructors read as
// default. The reference collection must see the same outbound regardless of
// whether the type is spelled out.
func TestCollectRuleReferencesImplicitType(t *testing.T) {
	for _, ruleType := range []string{C.RuleTypeDefault, ""} {
		var outbounds, transports []string
		collectRuleReferences([]option.Rule{routeRule(ruleType, C.RuleActionTypeRoute, "proxy")}, "", &outbounds, &transports)
		require.Equal(t, []string{"proxy"}, outbounds, "type=%q", ruleType)

		transports = nil
		collectDNSRuleReferences([]option.DNSRule{dnsRule(ruleType, C.RuleActionTypeRoute, "remote")}, "", &transports)
		require.Equal(t, []string{"remote"}, transports, "type=%q", ruleType)
	}
}

// An empty Action is not route: the constructors build a nil action, which
// matches no case in the routers and lets matching continue with the next
// rule. The collection must therefore neither count it as a reference nor as
// a final rule that shadows what follows.
func TestCollectRuleReferencesEmptyAction(t *testing.T) {
	emptyRoute := routeRule(C.RuleTypeDefault, "", "unused")
	emptyRoute.DefaultOptions.RawDefaultRule = option.RawDefaultRule{}
	action, err := R.NewRuleAction(context.Background(), nil, emptyRoute.DefaultOptions.RuleAction)
	require.NoError(t, err)
	require.Nil(t, action, "constructor must build no action for an empty Action")

	var outbounds, transports []string
	shadowed := collectRuleReferences([]option.Rule{emptyRoute, routeRule(C.RuleTypeDefault, C.RuleActionTypeRoute, "proxy")}, "", &outbounds, &transports)
	require.False(t, shadowed, "an unconditional rule without action must not shadow later rules")
	require.Equal(t, []string{"proxy"}, outbounds)

	emptyDNS := dnsRule(C.RuleTypeDefault, "", "unused")
	emptyDNS.DefaultOptions.RawDefaultDNSRule = option.RawDefaultDNSRule{}
	require.Nil(t, R.NewDNSRuleAction(nil, emptyDNS.DefaultOptions.DNSRuleAction), "constructor must build no action for an empty Action")

	transports = nil
	shadowed = collectDNSRuleReferences([]option.DNSRule{emptyDNS, dnsRule(C.RuleTypeDefault, C.RuleActionTypeRoute, "remote")}, "", &transports)
	require.False(t, shadowed, "an unconditional DNS rule without action must not shadow later rules")
	require.Equal(t, []string{"remote"}, transports)
}
