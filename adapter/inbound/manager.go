package inbound

import (
	"context"
	"os"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.InboundManager = (*Manager)(nil)

type Manager struct {
	registry adapter.InboundRegistry
	endpoint adapter.EndpointManager
	// updateAccess serializes Create, Remove and Close, which start and
	// close inbounds without holding access.
	updateAccess sync.Mutex
	access       sync.Mutex
	scope        *adapter.Scope
	started      bool
	stage        adapter.StartStage
	inbounds     []adapter.Inbound
	inboundByTag map[string]adapter.Inbound
}

func NewManager(registry adapter.InboundRegistry, endpoint adapter.EndpointManager) *Manager {
	return &Manager{
		registry:     registry,
		endpoint:     endpoint,
		inboundByTag: make(map[string]adapter.Inbound),
	}
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
	m.scope = scope
	m.started = true
	m.stage = stage
	inbounds := m.inbounds
	m.access.Unlock()
	for _, inbound := range inbounds {
		err := scope.Start(inboundName(inbound), inbound, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

// Close closes every inbound and forgets them, while the rest of the instance
// keeps running. Inbounds created afterwards are not started.
func (m *Manager) Close() error {
	m.updateAccess.Lock()
	defer m.updateAccess.Unlock()
	m.access.Lock()
	if !m.started {
		m.access.Unlock()
		return nil
	}
	m.started = false
	scope := m.scope
	inbounds := m.inbounds
	m.inbounds = nil
	m.inboundByTag = make(map[string]adapter.Inbound)
	m.access.Unlock()
	var err error
	for _, inbound := range inbounds {
		err = E.Errors(err, scope.CloseChild(inbound))
	}
	return err
}

func (m *Manager) Inbounds() []adapter.Inbound {
	m.access.Lock()
	defer m.access.Unlock()
	return m.inbounds
}

func (m *Manager) Get(tag string) (adapter.Inbound, bool) {
	m.access.Lock()
	inbound, found := m.inboundByTag[tag]
	m.access.Unlock()
	if found {
		return inbound, true
	}
	return m.endpoint.Get(tag)
}

// Remove removes the inbound with the given tag, and closes it if the manager
// is started.
func (m *Manager) Remove(tag string) error {
	m.updateAccess.Lock()
	defer m.updateAccess.Unlock()
	m.access.Lock()
	inbound, found := m.inboundByTag[tag]
	if !found {
		m.access.Unlock()
		return os.ErrInvalid
	}
	m.removeLocked(inbound)
	scope := m.scope
	started := m.started
	m.access.Unlock()
	if !started {
		return nil
	}
	return scope.CloseChild(inbound)
}

// Create creates an inbound and adds it. If the manager is started, a running
// inbound with the same tag is closed first, so that the new one can take over
// its listen address, and the new inbound is started through the stages the
// manager has reached. If it fails to start, it is closed, and the inbound it
// was to replace stays closed and is removed: the manager does not know the
// users that inbound had been updated to, so creating it again from what it
// was created from could let removed users back in. The caller restores it.
func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	inbound, err := m.registry.Create(ctx, router, logger, tag, inboundType, options)
	if err != nil {
		return err
	}
	m.updateAccess.Lock()
	defer m.updateAccess.Unlock()
	m.access.Lock()
	scope := m.scope
	started := m.started
	stage := m.stage
	existing, loaded := m.inboundByTag[tag]
	if !started {
		defer m.access.Unlock()
		if loaded {
			return E.New("duplicate inbound tag: ", tag)
		}
		m.addLocked(inbound)
		return nil
	}
	m.access.Unlock()
	var closeErr error
	if loaded {
		closeErr = scope.CloseChild(existing)
		if closeErr != nil {
			closeErr = E.Cause(closeErr, "close ", inboundName(existing))
		}
	}
	err = startInbound(scope, stage, inbound)
	m.access.Lock()
	defer m.access.Unlock()
	if err != nil {
		if loaded {
			m.removeLocked(existing)
		}
		return E.Errors(err, closeErr)
	}
	if loaded {
		m.replaceLocked(existing, inbound)
	} else {
		m.addLocked(inbound)
	}
	return closeErr
}

// startInbound starts the inbound through the stages up to stage, and closes
// it again if one of them fails.
func startInbound(scope *adapter.Scope, stage adapter.StartStage, inbound adapter.Inbound) error {
	for _, startStage := range adapter.ListStartStages {
		if startStage > stage {
			break
		}
		err := scope.Start(inboundName(inbound), inbound, startStage)
		if err != nil {
			return E.Errors(err, scope.CloseChild(inbound))
		}
	}
	return nil
}

func (m *Manager) addLocked(inbound adapter.Inbound) {
	m.inbounds = append(m.inbounds, inbound)
	m.inboundByTag[inbound.Tag()] = inbound
}

// replaceLocked puts the inbound in the place of one with the same tag, so
// that the order of the inbounds is kept.
func (m *Manager) replaceLocked(existing adapter.Inbound, inbound adapter.Inbound) {
	index := slices.Index(m.inbounds, existing)
	if index == -1 {
		panic("invalid inbound index")
	}
	m.inbounds = slices.Clone(m.inbounds)
	m.inbounds[index] = inbound
	m.inboundByTag[inbound.Tag()] = inbound
}

// removeLocked builds a new list, since Inbounds hands the current one out.
func (m *Manager) removeLocked(inbound adapter.Inbound) {
	delete(m.inboundByTag, inbound.Tag())
	index := slices.Index(m.inbounds, inbound)
	if index == -1 {
		panic("invalid inbound index")
	}
	m.inbounds = slices.Delete(slices.Clone(m.inbounds), index, index+1)
}

func inboundName(inbound adapter.Inbound) string {
	return "inbound/" + inbound.Type() + "[" + inbound.Tag() + "]"
}
