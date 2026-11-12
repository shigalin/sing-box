package route

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
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
	action, err := R.NewRuleAction(nil, emptyRoute.DefaultOptions.RuleAction)
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

// Rules built in code may leave Type empty, which the rule constructors read
// as default; the condition scan must see such rules too.
func TestHasRuleImplicitType(t *testing.T) {
	for _, ruleType := range []string{C.RuleTypeDefault, ""} {
		rule := routeRule(ruleType, C.RuleActionTypeRoute, "proxy")
		require.False(t, hasRule([]option.Rule{rule}, isProcessRule), "type=%q", ruleType)
		rule.DefaultOptions.ProcessName = []string{"curl"}
		require.True(t, hasRule([]option.Rule{rule}, isProcessRule), "type=%q", ruleType)

		dns := dnsRule(ruleType, C.RuleActionTypeRoute, "remote")
		require.False(t, hasDNSRule([]option.DNSRule{dns}, isProcessDNSRule), "type=%q", ruleType)
		dns.DefaultOptions.ProcessName = []string{"curl"}
		require.True(t, hasDNSRule([]option.DNSRule{dns}, isProcessDNSRule), "type=%q", ruleType)
	}
}

// Once the router is started, rules that need a searcher or resolver that is
// not there are rejected, unless the rules they replace needed it as well.
func TestCheckRuleRequirements(t *testing.T) {
	plain := routeRule(C.RuleTypeDefault, C.RuleActionTypeRoute, "proxy")
	process := routeRule("", C.RuleActionTypeRoute, "proxy")
	process.DefaultOptions.ProcessName = []string{"curl"}
	neighbor := routeRule("", C.RuleActionTypeRoute, "proxy")
	neighbor.DefaultOptions.SourceHostname = []string{"host"}

	// Before start nothing is rejected: start sets up what is needed.
	requirements, err := (&Router{}).checkRuleRequirements([]option.Rule{process, neighbor}, nil)
	require.NoError(t, err)
	require.Equal(t, ruleRequirements{process: true, neighbor: true}, requirements)

	logger := log.NewNOPFactory().Logger()
	for _, rule := range []option.Rule{process, neighbor} {
		// Nothing wanted the service at start: a restart sets it up.
		router := &Router{logger: logger, started: true}
		_, err = router.checkRuleRequirements([]option.Rule{plain}, nil)
		require.NoError(t, err)
		_, err = router.checkRuleRequirements([]option.Rule{rule}, nil)
		require.ErrorIs(t, err, adapter.ErrRestartRequired)

		// The service was wanted at start but is not there: a restart would
		// not help.
		router = &Router{logger: logger, started: true, needFindProcess: true, needFindNeighbor: true}
		_, err = router.checkRuleRequirements([]option.Rule{rule}, nil)
		require.ErrorIs(t, err, adapter.ErrRuleRequirementUnavailable)
		require.NotErrorIs(t, err, adapter.ErrRestartRequired)

		// The rules in effect already need it, as start accepted them: the
		// update is accepted too, so that the other rules can change.
		router.ruleRequirements = ruleRequirements{process: true, neighbor: true}
		_, err = router.checkRuleRequirements([]option.Rule{rule}, nil)
		require.NoError(t, err)
	}
}
