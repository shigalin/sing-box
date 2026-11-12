package route

import (
	"bytes"
	"context"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/process"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/common/task"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

var _ adapter.Router = (*Router)(nil)

type Router struct {
	ctx               context.Context
	logger            log.ContextLogger
	inbound           adapter.InboundManager
	outbound          adapter.OutboundManager
	dns               adapter.DNSRouter
	dnsTransport      adapter.DNSTransportManager
	connection        adapter.ConnectionManager
	network           adapter.NetworkManager
	httpClientManager adapter.HTTPClientManager
	rules             atomic.Pointer[[]adapter.Rule]
	// ruleOptions mirrors rules as options, for holders that evaluate rules
	// statically, such as the reference manager. Both are replaced together
	// by UpdateRules, which then notifies ruleUpdateHooks.
	ruleOptions      atomic.Pointer[[]option.Rule]
	ruleUpdateAccess sync.Mutex
	// updateAccess serializes UpdateRules with itself and with the cleanups
	// that close the rules and rule-sets, after which closed is set and
	// updates are refused. ruleSetAccess guards ruleSetMap, which RuleSet
	// reads while an update replaces it.
	updateAccess sync.Mutex
	closed       bool
	// ruleRequirements is what the rules in effect need, see
	// checkRuleRequirements.
	ruleRequirements ruleRequirements
	ruleSetAccess    sync.RWMutex
	ruleUpdateHooks  []*observable.Subscriber[struct{}]
	needFindProcess  bool
	needFindNeighbor bool
	leaseFiles       []string
	ruleSets         []adapter.RuleSet
	ruleSetMap       map[string]adapter.RuleSet
	ruleSetOptions   map[string]option.RuleSet
	ruleSetTags      map[string]bool
	dnsRuleSetTags   map[string]bool
	// dnsRuleSets holds, per tag, the rule-set the DNS rules resolved at
	// start. DNS rules keep matching against that object, so it must stay
	// alive with its content until the router is closed, even after
	// UpdateRules replaced it; dnsRetainedRuleSets collects those replaced.
	dnsRuleSets         map[string]adapter.RuleSet
	dnsRetainedRuleSets []adapter.RuleSet
	ruleSetUpdater      *R.RuleSetUpdater
	retiredAccess       sync.Mutex
	retired             []*retiredRules
	processSearcher     process.Searcher
	processCache        *freelru.Cache[processCacheKey, processCacheEntry]
	neighborResolver    adapter.NeighborResolver
	pauseManager        pause.Manager
	trackers            []adapter.ConnectionTracker
	platformInterface   adapter.PlatformInterface
	started             bool
}

func NewRouter(ctx context.Context, logFactory log.Factory, options option.RouteOptions, dnsOptions option.DNSOptions) *Router {
	return &Router{
		ctx:               ctx,
		logger:            logFactory.NewLogger("router"),
		inbound:           service.FromContext[adapter.InboundManager](ctx),
		outbound:          service.FromContext[adapter.OutboundManager](ctx),
		dns:               service.FromContext[adapter.DNSRouter](ctx),
		dnsTransport:      service.FromContext[adapter.DNSTransportManager](ctx),
		connection:        service.FromContext[adapter.ConnectionManager](ctx),
		network:           service.FromContext[adapter.NetworkManager](ctx),
		httpClientManager: service.FromContext[adapter.HTTPClientManager](ctx),
		ruleSetMap:        make(map[string]adapter.RuleSet),
		ruleSetOptions:    make(map[string]option.RuleSet),
		dnsRuleSetTags:    collectDNSRuleSetTags(dnsOptions.Rules, make(map[string]bool)),
		needFindProcess:   hasRule(options.Rules, isProcessRule) || hasDNSRule(dnsOptions.Rules, isProcessDNSRule) || options.FindProcess,
		needFindNeighbor:  hasRule(options.Rules, isNeighborRule) || hasDNSRule(dnsOptions.Rules, isNeighborDNSRule) || hasLocalNeighborDNSServer(dnsOptions.Servers) || options.FindNeighbor,
		leaseFiles:        options.DHCPLeaseFiles,
		pauseManager:      service.FromContext[pause.Manager](ctx),
		platformInterface: service.FromContext[adapter.PlatformInterface](ctx),
	}
}

func (r *Router) Initialize(rules []option.Rule, ruleSets []option.RuleSet) error {
	ruleList := make([]adapter.Rule, 0, len(rules))
	for i, options := range rules {
		err := R.ValidateNoNestedRuleActions(options)
		if err != nil {
			return E.Cause(err, "parse rule[", i, "]")
		}
		rule, err := R.NewRule(r.ctx, r.logger, options, false)
		if err != nil {
			return E.Cause(err, "parse rule[", i, "]")
		}
		ruleList = append(ruleList, rule)
	}
	r.rules.Store(&ruleList)
	r.ruleOptions.Store(&rules)
	r.ruleSetTags = collectRuleSetTags(rules, make(map[string]bool))
	for i, options := range ruleSets {
		for _, tag := range options.Tag {
			if _, exists := r.ruleSetMap[tag]; exists {
				return E.New("duplicate rule-set tag: ", tag)
			}
			ruleSet, err := R.NewRuleSet(r.ctx, r.logger, tag, options)
			if err != nil {
				return E.Cause(err, "parse rule-set[", i, "]")
			}
			r.ruleSets = append(r.ruleSets, ruleSet)
			r.ruleSetMap[tag] = ruleSet
			r.ruleSetOptions[tag] = options
		}
	}
	return nil
}

func (r *Router) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	monitor := taskmonitor.New(r.logger, C.StartTimeout)
	switch stage {
	case adapter.StartStateInitialize:
		// UpdateRules replaces rules and rule-sets at runtime, so the scope
		// closes whatever is current at shutdown instead of the initial ones.
		scope.Add(r.closeRuleSets)
		if r.needFindNeighbor {
			if r.platformInterface != nil && r.platformInterface.UsePlatformNeighborResolver() {
				monitor.Start("initialize neighbor resolver")
				resolver := newPlatformNeighborResolver(r.logger, r.platformInterface)
				err := resolver.Start()
				monitor.Finish()
				if err != nil {
					r.logger.Error(E.Cause(err, "start neighbor resolver"))
				} else {
					r.neighborResolver = resolver
					scope.Add(resolver.Close)
				}
			} else {
				monitor.Start("initialize neighbor resolver")
				resolver, err := newNeighborResolver(r.logger, r.leaseFiles)
				monitor.Finish()
				if err != nil {
					if err != os.ErrInvalid {
						r.logger.Error(E.Cause(err, "create neighbor resolver"))
					}
				} else {
					err = resolver.Start()
					if err != nil {
						r.logger.Error(E.Cause(err, "start neighbor resolver"))
					} else {
						r.neighborResolver = resolver
						scope.Add(resolver.Close)
					}
				}
			}
		}
	case adapter.StartStateStart:
		var startContext *adapter.HTTPStartContext
		if len(r.ruleSets) > 0 {
			monitor.Start("initialize rule-set")
			startContext = adapter.NewHTTPStartContext()
			var ruleSetStartGroup task.Group
			for i, ruleSet := range r.ruleSets {
				ruleSetInPlace := ruleSet
				ruleSetStartGroup.Append0(func(ctx context.Context) error {
					err := ruleSetInPlace.StartContext(ctx, startContext)
					if err != nil {
						return E.Cause(err, "initialize rule-set[", i, "]")
					}
					return nil
				})
			}
			ruleSetStartGroup.Concurrency(5)
			ruleSetStartGroup.FastFail()
			err := ruleSetStartGroup.Run(r.ctx)
			monitor.Finish()
			if err != nil {
				return err
			}
		}
		if startContext != nil {
			startContext.Close()
		}
		r.dnsRuleSets = make(map[string]adapter.RuleSet)
		for tag := range r.dnsRuleSetTags {
			if ruleSet, loaded := r.ruleSetMap[tag]; loaded {
				r.dnsRuleSets[tag] = ruleSet
			}
		}
		r.ruleSetUpdater = R.NewRuleSetUpdater(r.ctx, r.ruleSets)
		scope.Add(r.closeRuleSetUpdater)
		r.network.Initialize(r.ruleSets)
		needFindProcess := r.needFindProcess
		for _, ruleSet := range r.ruleSets {
			metadata := ruleSet.Metadata()
			if metadata.ContainsProcessRule {
				needFindProcess = true
			}
		}
		if C.IsAndroid && r.platformInterface != nil {
			needFindProcess = true
		}
		r.needFindProcess = needFindProcess
		if needFindProcess {
			if r.platformInterface != nil && r.platformInterface.UsePlatformConnectionOwnerFinder() {
				r.processSearcher = newPlatformSearcher(r.platformInterface)
			} else {
				monitor.Start("initialize process searcher")
				searcher, err := process.NewSearcher(process.Config{
					Logger:         r.logger,
					PackageManager: r.network.PackageManager(),
				})
				monitor.Finish()
				if err != nil {
					if err != os.ErrInvalid {
						r.logger.Warn(E.Cause(err, "create process searcher"))
					}
				} else {
					r.processSearcher = searcher
				}
			}
		}
		if r.processSearcher != nil {
			scope.Add(r.processSearcher.Close)
			processCache := common.Must1(freelru.New[processCacheKey, processCacheEntry](256, maphash.NewHasher[processCacheKey]().Hash32, true))
			processCache.SetLifetime(200 * time.Millisecond)
			r.processCache = processCache
		}
	case adapter.StartStatePostStart:
		scope.Add(r.closeRules)
		for i, rule := range r.Rules() {
			monitor.Start("initialize rule[", i, "]")
			err := rule.Start()
			monitor.Finish()
			if err != nil {
				return E.Cause(err, "initialize rule[", i, "]")
			}
		}
		if r.ruleSetUpdater != nil {
			r.ruleSetUpdater.Start()
		}
		r.updateAccess.Lock()
		r.ruleRequirements = ruleRequirements{
			process:  hasRule(r.RuleOptions(), isProcessRule),
			neighbor: hasRule(r.RuleOptions(), isNeighborRule),
		}
		for _, ruleSet := range r.ruleSets {
			if ruleSet.Metadata().ContainsProcessRule {
				r.ruleRequirements.process = true
			}
		}
		r.started = true
		r.updateAccess.Unlock()
		return nil
	case adapter.StartStateStarted:
		for _, ruleSet := range r.ruleSets {
			ruleSet.Cleanup()
		}
		runtime.GC()
	}
	return nil
}

func (r *Router) closeRules() error {
	r.updateAccess.Lock()
	defer r.updateAccess.Unlock()
	r.closed = true
	var err error
	for i, rule := range r.Rules() {
		err = E.Append(err, rule.Close(), func(err error) error {
			return E.Cause(err, "close rule[", i, "]")
		})
	}
	r.closeRetired()
	return err
}

func (r *Router) closeRuleSetUpdater() error {
	r.updateAccess.Lock()
	defer r.updateAccess.Unlock()
	r.closed = true
	if r.ruleSetUpdater == nil {
		return nil
	}
	return r.ruleSetUpdater.Close()
}

func (r *Router) closeRuleSets() error {
	r.updateAccess.Lock()
	defer r.updateAccess.Unlock()
	r.closed = true
	var err error
	for i, ruleSet := range r.ruleSets {
		err = E.Append(err, ruleSet.Close(), func(err error) error {
			return E.Cause(err, "close rule-set[", i, "]")
		})
	}
	for _, ruleSet := range r.dnsRetainedRuleSets {
		err = E.Append(err, ruleSet.Close(), func(err error) error {
			return E.Cause(err, "close replaced DNS rule-set ", ruleSet.Name())
		})
	}
	return err
}

func (r *Router) RuleSet(tag string) (adapter.RuleSet, bool) {
	r.ruleSetAccess.RLock()
	defer r.ruleSetAccess.RUnlock()
	ruleSet, loaded := r.ruleSetMap[tag]
	return ruleSet, loaded
}

func (r *Router) Rules() []adapter.Rule {
	rules := r.rules.Load()
	if rules == nil {
		return nil
	}
	return *rules
}

func (r *Router) AppendTracker(tracker adapter.ConnectionTracker) {
	r.trackers = append(r.trackers, tracker)
}

func (r *Router) NeedFindProcess() bool {
	return r.needFindProcess
}

// UpdateRules replaces the route rules and rule-sets of the router.
//
// Rule-sets that the current rules reference and whose options did not change
// are kept, so that they are not loaded again and other holders of them, such
// as DNS rules, keep a live reference. New rules resolve their rule-sets from
// the new set before they are published; if anything fails, the router keeps
// its current rules and rule-sets. Replaced rules and rule-sets are closed
// after a grace period, once connections matched against them have finished.
// Updates are applied one at a time, and refused once the router is closing.
func (r *Router) UpdateRules(rules []option.Rule, ruleSets []option.RuleSet) error {
	r.updateAccess.Lock()
	defer r.updateAccess.Unlock()
	if r.closed {
		return os.ErrClosed
	}
	newRules := make([]adapter.Rule, 0, len(rules))
	for i, options := range rules {
		err := R.ValidateNoNestedRuleActions(options)
		if err != nil {
			return E.Cause(err, "parse rule[", i, "]")
		}
		rule, err := R.NewRule(r.ctx, r.logger, options, false)
		if err != nil {
			return E.Cause(err, "parse rule[", i, "]")
		}
		newRules = append(newRules, rule)
	}
	newRuleSets := make([]adapter.RuleSet, 0, len(ruleSets))
	newRuleSetMap := make(map[string]adapter.RuleSet)
	newRuleSetOptions := make(map[string]option.RuleSet)
	reusedRuleSets := make(map[adapter.RuleSet]bool)
	var createdRuleSets []adapter.RuleSet
	for i, options := range ruleSets {
		for _, tag := range options.Tag {
			if _, exists := newRuleSetMap[tag]; exists {
				closeRuleSets(createdRuleSets)
				return E.New("duplicate rule-set tag: ", tag)
			}
			ruleSet, reused := r.reusableRuleSet(tag, options)
			if reused {
				reusedRuleSets[ruleSet] = true
			} else {
				var err error
				ruleSet, err = R.NewRuleSet(r.ctx, r.logger, tag, options)
				if err != nil {
					closeRuleSets(createdRuleSets)
					return E.Cause(err, "parse rule-set[", i, "]")
				}
				createdRuleSets = append(createdRuleSets, ruleSet)
			}
			newRuleSets = append(newRuleSets, ruleSet)
			newRuleSetMap[tag] = ruleSet
			newRuleSetOptions[tag] = options
		}
	}
	if r.started {
		err := startRuleSets(r.ctx, createdRuleSets)
		if err != nil {
			closeRuleSets(createdRuleSets)
			return err
		}
	}
	requirements, err := r.checkRuleRequirements(rules, newRuleSets)
	if err != nil {
		closeRuleSets(createdRuleSets)
		return err
	}
	oldRules := r.Rules()
	oldRuleSets := r.ruleSets
	oldRuleSetMap := r.ruleSetMap
	oldRuleSetUpdater := r.ruleSetUpdater
	// Rules resolve their rule-sets when they start, so the new map must be
	// in place before the new rules start.
	r.ruleSetAccess.Lock()
	r.ruleSetMap = newRuleSetMap
	r.ruleSetAccess.Unlock()
	if r.started {
		for i, rule := range newRules {
			err := rule.Start()
			if err != nil {
				for _, startedRule := range newRules[:i+1] {
					startedRule.Close()
				}
				r.ruleSetAccess.Lock()
				r.ruleSetMap = oldRuleSetMap
				r.ruleSetAccess.Unlock()
				closeRuleSets(createdRuleSets)
				return E.Cause(err, "initialize rule[", i, "]")
			}
		}
	}
	r.rules.Store(&newRules)
	r.ruleOptions.Store(&rules)
	r.ruleSets = newRuleSets
	r.ruleSetOptions = newRuleSetOptions
	r.ruleSetTags = collectRuleSetTags(rules, make(map[string]bool))
	r.ruleRequirements = requirements
	if !r.started {
		// The searcher and the resolver are set up at start if needed.
		r.needFindProcess = r.needFindProcess || requirements.process
		r.needFindNeighbor = r.needFindNeighbor || requirements.neighbor
	}
	r.notifyRulesUpdated()
	var retiredRuleSets []adapter.RuleSet
	for _, ruleSet := range oldRuleSets {
		if reusedRuleSets[ruleSet] {
			continue
		}
		// DNS rules resolve their rule-sets once at start and keep matching
		// against that object, so it must stay alive with its content; it is
		// closed with the router.
		if r.started && r.dnsRuleSets[ruleSet.Name()] == ruleSet {
			r.logger.Warn("rule-set ", ruleSet.Name(), " changed, but DNS rules keep using its previous content until restart")
			r.dnsRetainedRuleSets = append(r.dnsRetainedRuleSets, ruleSet)
			continue
		}
		retiredRuleSets = append(retiredRuleSets, ruleSet)
	}
	if !r.started {
		closeRuleSets(retiredRuleSets)
		return nil
	}
	r.ruleSetUpdater = R.NewRuleSetUpdater(r.ctx, newRuleSets)
	r.network.Initialize(newRuleSets)
	if r.ruleSetUpdater != nil {
		r.ruleSetUpdater.Start()
	}
	if oldRuleSetUpdater != nil {
		oldRuleSetUpdater.Close()
	}
	r.retire(oldRules, retiredRuleSets)
	for _, ruleSet := range createdRuleSets {
		ruleSet.Cleanup()
	}
	return nil
}

// RuleOptions returns the options of the rules currently in effect.
func (r *Router) RuleOptions() []option.Rule {
	rules := r.ruleOptions.Load()
	if rules == nil {
		return nil
	}
	return *rules
}

// AddRuleUpdateHook registers a subscriber that is notified after UpdateRules
// published new rules.
func (r *Router) AddRuleUpdateHook(hook *observable.Subscriber[struct{}]) {
	r.ruleUpdateAccess.Lock()
	defer r.ruleUpdateAccess.Unlock()
	r.ruleUpdateHooks = append(r.ruleUpdateHooks, hook)
}

func (r *Router) notifyRulesUpdated() {
	r.ruleUpdateAccess.Lock()
	defer r.ruleUpdateAccess.Unlock()
	for _, hook := range r.ruleUpdateHooks {
		hook.Emit(struct{}{})
	}
}

// reusableRuleSet returns the current rule-set with the given tag if it can
// serve the given options as it is. Only rule-sets that a rule references are
// reused: a rule-set without references may have released its content. A
// tag that DNS rules use only counts if the current object is the one they
// hold; a replacement of it has no DNS reference.
func (r *Router) reusableRuleSet(tag string, options option.RuleSet) (adapter.RuleSet, bool) {
	ruleSet, loaded := r.ruleSetMap[tag]
	if !loaded || !(r.ruleSetTags[tag] || r.dnsRuleSets[tag] == ruleSet) {
		return nil, false
	}
	currentOptions, loaded := r.ruleSetOptions[tag]
	if !loaded || !ruleSetOptionsEqual(currentOptions, options) {
		return nil, false
	}
	return ruleSet, true
}

func ruleSetOptionsEqual(left option.RuleSet, right option.RuleSet) bool {
	leftContent, err := json.Marshal(left)
	if err != nil {
		return false
	}
	rightContent, err := json.Marshal(right)
	if err != nil {
		return false
	}
	return bytes.Equal(leftContent, rightContent)
}

func startRuleSets(ctx context.Context, ruleSets []adapter.RuleSet) error {
	if len(ruleSets) == 0 {
		return nil
	}
	startContext := adapter.NewHTTPStartContext()
	defer startContext.Close()
	var ruleSetStartGroup task.Group
	for _, ruleSet := range ruleSets {
		ruleSetInPlace := ruleSet
		ruleSetStartGroup.Append0(func(ctx context.Context) error {
			err := ruleSetInPlace.StartContext(ctx, startContext)
			if err != nil {
				return E.Cause(err, "initialize rule-set: ", ruleSetInPlace.Name())
			}
			return nil
		})
	}
	ruleSetStartGroup.Concurrency(5)
	ruleSetStartGroup.FastFail()
	return ruleSetStartGroup.Run(ctx)
}

func closeRuleSets(ruleSets []adapter.RuleSet) {
	for _, ruleSet := range ruleSets {
		ruleSet.Close()
	}
}

// ruleRequirements is what a set of route rules needs from the router.
type ruleRequirements struct {
	process  bool
	neighbor bool
}

// checkRuleRequirements reports what the new rules need. The process searcher
// and the neighbor resolver are only set up at start, and only if something
// needed them then, so once the router is started, rules that need one that
// is not there would be installed and never match:
//
//   - if nothing needed it at start, it was never set up, and the rules are
//     rejected with adapter.ErrRestartRequired as the cause;
//   - if it was needed at start but could not be set up, a restart would not
//     help, and the rules are rejected with
//     adapter.ErrRuleRequirementUnavailable as the cause;
//   - unless the rules they replace needed it as well: start accepts such
//     rules with a warning, and so does the update, so that the other rules
//     of an instance in that state can still be updated.
func (r *Router) checkRuleRequirements(rules []option.Rule, ruleSets []adapter.RuleSet) (ruleRequirements, error) {
	requirements := ruleRequirements{
		process:  hasRule(rules, isProcessRule),
		neighbor: hasRule(rules, isNeighborRule),
	}
	if !r.started {
		return requirements, nil
	}
	// Rule-set metadata is only loaded once the rule-set is started.
	for _, ruleSet := range ruleSets {
		if ruleSet.Metadata().ContainsProcessRule {
			requirements.process = true
		}
	}
	if requirements.process && r.processSearcher == nil {
		err := r.missingRequirement("process information", r.needFindProcess, r.ruleRequirements.process)
		if err != nil {
			return requirements, err
		}
	}
	if requirements.neighbor && r.neighborResolver == nil {
		err := r.missingRequirement("neighbor information", r.needFindNeighbor, r.ruleRequirements.neighbor)
		if err != nil {
			return requirements, err
		}
	}
	return requirements, nil
}

func (r *Router) missingRequirement(name string, wantedAtStart bool, neededByCurrentRules bool) error {
	if !wantedAtStart {
		return E.Cause(adapter.ErrRestartRequired, "rules need ", name, ", which was not set up at start")
	}
	if !neededByCurrentRules {
		return E.Cause(adapter.ErrRuleRequirementUnavailable, "rules need ", name)
	}
	r.logger.Warn("rules need ", name, ", which is not available: these rules will not match")
	return nil
}

// ruleRetireDelay is how long replaced rules and rule-sets stay usable after
// they were replaced. Matching a connection can wait for a DNS lookup, so the
// delay is longer than the DNS timeout.
const ruleRetireDelay = 30 * time.Second

type retiredRules struct {
	rules    []adapter.Rule
	ruleSets []adapter.RuleSet
	timer    *time.Timer
}

// retire closes the given rules and rule-sets after ruleRetireDelay, or when
// the router is closed, whichever comes first.
func (r *Router) retire(rules []adapter.Rule, ruleSets []adapter.RuleSet) {
	if len(rules) == 0 && len(ruleSets) == 0 {
		return
	}
	entry := &retiredRules{rules: rules, ruleSets: ruleSets}
	r.retiredAccess.Lock()
	defer r.retiredAccess.Unlock()
	r.retired = append(r.retired, entry)
	entry.timer = time.AfterFunc(ruleRetireDelay, func() {
		r.retiredAccess.Lock()
		index := slices.Index(r.retired, entry)
		if index >= 0 {
			r.retired = slices.Delete(r.retired, index, index+1)
		}
		r.retiredAccess.Unlock()
		if index >= 0 {
			entry.close()
		}
	})
}

func (r *Router) closeRetired() {
	r.retiredAccess.Lock()
	retired := r.retired
	r.retired = nil
	r.retiredAccess.Unlock()
	for _, entry := range retired {
		entry.timer.Stop()
		entry.close()
	}
}

func (e *retiredRules) close() {
	for _, rule := range e.rules {
		rule.Close()
	}
	closeRuleSets(e.ruleSets)
}

func (r *Router) NeedFindNeighbor() bool {
	return r.needFindNeighbor
}

func (r *Router) NeighborResolver() adapter.NeighborResolver {
	return r.neighborResolver
}

func (r *Router) ResetNetwork() {
	r.httpClientManager.ResetNetwork()
	r.dns.ResetNetwork()
	if r.processCache != nil {
		r.processCache.Purge()
	}
	if r.processSearcher != nil {
		r.processSearcher.ResetCache()
	}
}
