package snell

import (
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var errPSKOverloaded = errors.New("snell: authentication capacity exceeded")

const (
	pskMaxPending  = 1024
	pskColdPending = 768 // Reserve capacity for sources with cached candidates.
	// A shared NAT may burst into most of each capacity. The remainder stays
	// available to other sources while one source is saturated.
	pskSourcePending    = pskColdPending - 64
	pskProbeConcurrency = 16
	// Candidates matched per probe permit. A permit is not preempted, so this
	// bounds how long a waiting source can be kept from its turn, whatever the
	// size of the table.
	pskProbeChunk        = 256
	pskProbeQueued       = 512
	pskSourceProbeQueued = pskProbeQueued - 32
	pskHintConcurrency   = 8
	// Cached candidates wait in their own capacity: a full probe queue must not
	// close a connection whose cached user is still being read or verified.
	pskHintQueued       = 256
	pskSourceHintQueued = pskHintQueued - 32
	pskAdmissionSources = 8192
)

type pskBudgetKind int

const (
	pskProbeBudget pskBudgetKind = iota // full-table lookups
	pskHintBudget                       // cached candidates of a source
	pskBudgetKinds
)

// A budget hands out concurrent CPU permits. A source may hold every permit
// while nobody else waits; once lookups wait, each freed permit goes to the
// next waiting source in turn: to a lookup of that source that already
// started, otherwise to its oldest waiting lookup.
type pskBudget struct {
	limit, active                        int
	queueLimit, sourceQueueLimit, queued int
	rate                                 *rate.Limiter
	// Sources with waiting lookups, each exactly once, next to be served first.
	ring []*pskSourceAdmission
}

type pskSourceBudget struct {
	queued  int
	rate    *rate.Limiter         // nil for the shared overflow source
	waiters []*pskAdmissionTicket // oldest first
}

// Admission state is separate from authenticated sessions. A connection holds
// its pending capacity until its first request is valid; a bad PSK never bans
// an IP.
type pskAdmission struct {
	access        sync.Mutex
	now           func() time.Time // read under access, so limiter time never runs backwards
	pending, cold int
	sources       map[netip.Addr]*pskSourceAdmission
	// Shared by sources that arrive while the accounting table is full.
	overflow  *pskSourceAdmission
	nextSweep time.Time
	budgets   [pskBudgetKinds]pskBudget
}

type pskSourceAdmission struct {
	pending  int
	lastUsed time.Time
	budgets  [pskBudgetKinds]pskSourceBudget
}

type pskTicketBudget struct {
	charged bool // rate token taken; once per lookup, not once per v6 length group
	queued  bool // counted in the queue: waiting for a token or a permit
	waiting bool // listed in the source's waiters
	granted bool
	// Held a permit before. Such a lookup resumes ahead of its source's new
	// lookups and is never refused by a full queue: finishing it frees capacity
	// sooner than starting another, and newer arrivals must not evict it.
	started bool
}

type pskAdmissionTicket struct {
	guard     *pskAdmission
	source    *pskSourceAdmission
	cold      bool
	untracked bool
	closed    bool // close belongs to the goroutine serving the connection.
	// Signalled when a waiting lookup is granted a permit.
	ready   chan struct{}
	budgets [pskBudgetKinds]pskTicketBudget
}

func newPSKAdmission() *pskAdmission {
	a := &pskAdmission{
		now:      time.Now,
		sources:  make(map[netip.Addr]*pskSourceAdmission),
		overflow: &pskSourceAdmission{},
	}
	a.budgets[pskProbeBudget] = pskBudget{limit: pskProbeConcurrency, queueLimit: pskProbeQueued, sourceQueueLimit: pskSourceProbeQueued, rate: rate.NewLimiter(1024, 4096)}
	a.budgets[pskHintBudget] = pskBudget{limit: pskHintConcurrency, queueLimit: pskHintQueued, sourceQueueLimit: pskSourceHintQueued, rate: rate.NewLimiter(2048, 512)}
	return a
}

func newPSKSourceAdmission() *pskSourceAdmission {
	s := &pskSourceAdmission{}
	s.budgets[pskProbeBudget].rate = rate.NewLimiter(32, 128)
	s.budgets[pskHintBudget].rate = rate.NewLimiter(256, 512)
	return s
}

func (a *pskAdmission) enter(source netip.Addr, hinted bool) (*pskAdmissionTicket, error) {
	a.access.Lock()
	defer a.access.Unlock()
	if a.pending >= pskMaxPending || (!hinted && a.cold >= pskColdPending) {
		return nil, errPSKOverloaded
	}
	now := a.now()
	source = source.Unmap()
	s := a.sources[source]
	untracked := false
	if s == nil {
		// Sweeps are amortized, not an O(map size) operation on every rejected
		// connection. Idle entries survive long enough to retain rate debt.
		if len(a.sources) >= pskAdmissionSources && !now.Before(a.nextSweep) {
			a.nextSweep = now.Add(10 * time.Second)
			for key, entry := range a.sources {
				if entry.pending == 0 && now.Sub(entry.lastUsed) >= time.Minute &&
					!slices.ContainsFunc(entry.budgets[:], func(budget pskSourceBudget) bool {
						return budget.rate.TokensAt(now) < float64(budget.rate.Burst())
					}) {
					delete(a.sources, key)
				}
			}
		}
		if len(a.sources) >= pskAdmissionSources {
			// Keep admitting new addresses under the global budgets instead of
			// turning a full per-source accounting table into an IP-wide ban.
			s, untracked = a.overflow, true
		} else {
			s = newPSKSourceAdmission()
			a.sources[source] = s
		}
	}
	if !untracked && s.pending >= pskSourcePending {
		return nil, errPSKOverloaded
	}
	s.pending++
	s.lastUsed = now
	a.pending++
	if !hinted {
		a.cold++
	}
	return &pskAdmissionTicket{guard: a, source: s, cold: !hinted, untracked: untracked, ready: make(chan struct{}, 1)}, nil
}

func (t *pskAdmissionTicket) close() {
	if t.closed {
		return
	}
	t.closed = true
	a := t.guard
	a.access.Lock()
	a.leaveLocked(t)
	t.source.pending--
	t.source.lastUsed = a.now()
	a.pending--
	if t.cold {
		a.cold--
	}
	a.access.Unlock()
}

// leave returns every permit and queue position the lookup still has.
func (t *pskAdmissionTicket) leave() {
	t.guard.access.Lock()
	t.guard.leaveLocked(t)
	t.guard.access.Unlock()
}

func (a *pskAdmission) leaveLocked(t *pskAdmissionTicket) {
	for kind := range t.budgets {
		state, budget, source := &t.budgets[kind], &a.budgets[kind], &t.source.budgets[kind]
		if state.waiting {
			state.waiting = false
			index := slices.Index(source.waiters, t)
			source.waiters = slices.Delete(source.waiters, index, index+1)
			if len(source.waiters) == 0 {
				source.waiters = nil
				index = slices.Index(budget.ring, t.source)
				budget.ring = slices.Delete(budget.ring, index, index+1)
			}
		}
		if state.queued {
			state.queued = false
			budget.queued--
			source.queued--
		}
		if state.granted {
			state.granted = false
			budget.active--
			a.dispatchLocked(pskBudgetKind(kind))
		}
	}
}

// All rate operations use access, so checking both buckets before consuming
// either does not spend one bucket's budget when the other refuses admission.
func tokenReady(limiter *rate.Limiter, now time.Time) time.Time {
	if limiter == nil {
		return time.Time{}
	}
	missing := 1 - limiter.TokensAt(now)
	if missing <= 0 {
		return time.Time{}
	}
	return now.Add(time.Duration(missing/float64(limiter.Limit())*float64(time.Second)) + time.Nanosecond)
}

// acquire reports a held permit, the time to ask again when a rate token is
// missing, or neither while the lookup waits for ready. It fails only when the
// lookup would have to wait and the queue is full. Only actual CPU work holds
// a permit; reads hold none.
func (t *pskAdmissionTicket) acquire(kind pskBudgetKind) (bool, time.Time, error) {
	a := t.guard
	a.access.Lock()
	defer a.access.Unlock()
	state, budget, source := &t.budgets[kind], &a.budgets[kind], &t.source.budgets[kind]
	if state.granted || state.waiting {
		return state.granted, time.Time{}, nil
	}
	if !state.charged {
		now := a.now()
		ready := tokenReady(budget.rate, now)
		if local := tokenReady(source.rate, now); local.After(ready) {
			ready = local
		}
		if !ready.IsZero() {
			return false, ready, a.queueLocked(t, kind)
		}
		budget.rate.AllowN(now, 1)
		if source.rate != nil {
			source.rate.AllowN(now, 1)
		}
		state.charged = true
	}
	if budget.active < budget.limit && len(budget.ring) == 0 {
		if state.queued {
			state.queued = false
			budget.queued--
			source.queued--
		}
		budget.active++
		state.granted, state.started = true, true
		return true, time.Time{}, nil
	}
	if err := a.queueLocked(t, kind); err != nil {
		return false, time.Time{}, err
	}
	if len(source.waiters) == 0 {
		budget.ring = append(budget.ring, t.source)
	}
	if state.started {
		source.waiters = slices.Insert(source.waiters, 0, t)
	} else {
		source.waiters = append(source.waiters, t)
	}
	state.waiting = true
	// The lookup stays listed until it is granted a permit or leaves, so a
	// later arrival cannot take its turn.
	a.dispatchLocked(kind)
	return state.granted, time.Time{}, nil
}

func (a *pskAdmission) queueLocked(t *pskAdmissionTicket, kind pskBudgetKind) error {
	state, budget, source := &t.budgets[kind], &a.budgets[kind], &t.source.budgets[kind]
	if state.queued {
		return nil
	}
	if !state.started && (budget.queued >= budget.queueLimit || (!t.untracked && source.queued >= budget.sourceQueueLimit)) {
		return errPSKOverloaded
	}
	state.queued = true
	budget.queued++
	source.queued++
	return nil
}

func (t *pskAdmissionTicket) release(kind pskBudgetKind) {
	a := t.guard
	a.access.Lock()
	t.budgets[kind].granted = false
	a.budgets[kind].active--
	a.dispatchLocked(kind)
	a.access.Unlock()
}

// dispatchLocked hands free permits to waiting lookups, one source at a time.
func (a *pskAdmission) dispatchLocked(kind pskBudgetKind) {
	budget := &a.budgets[kind]
	for budget.active < budget.limit && len(budget.ring) > 0 {
		next := budget.ring[0]
		budget.ring = slices.Delete(budget.ring, 0, 1)
		source := &next.budgets[kind]
		t := source.waiters[0]
		source.waiters = slices.Delete(source.waiters, 0, 1)
		if len(source.waiters) == 0 {
			source.waiters = nil
		} else {
			budget.ring = append(budget.ring, next)
		}
		state := &t.budgets[kind]
		state.waiting, state.queued, state.granted, state.started = false, false, true, true
		budget.queued--
		source.queued--
		budget.active++
		select {
		case t.ready <- struct{}{}:
		default:
		}
	}
}
