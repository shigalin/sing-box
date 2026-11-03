package route

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

type networkTestRouter struct {
	adapter.Router
	resets  atomic.Int32
	onReset func()
}

func (r *networkTestRouter) ResetNetwork() {
	r.resets.Add(1)
	if r.onReset != nil {
		r.onReset()
	}
}

type networkTestEndpoints struct{ adapter.EndpointManager }

func (networkTestEndpoints) Endpoints() []adapter.Endpoint { return nil }

type networkTestInbounds struct{ adapter.InboundManager }

func (networkTestInbounds) Inbounds() []adapter.Inbound { return nil }

type networkTestOutbound struct {
	adapter.Outbound
	contexts chan context.Context
}

func (o *networkTestOutbound) InterfaceUpdated(ctx context.Context) { o.contexts <- ctx }

type networkTestOutbounds struct {
	adapter.OutboundManager
	outbound *networkTestOutbound
}

func (m networkTestOutbounds) Outbounds() []adapter.Outbound { return []adapter.Outbound{m.outbound} }

type networkTestMonitor struct {
	tun.DefaultInterfaceMonitor
	mu        sync.Mutex
	callbacks list.List[tun.DefaultInterfaceUpdateCallback]
	iif       control.Interface
}

func (*networkTestMonitor) Start() error                           { return nil }
func (*networkTestMonitor) Close() error                           { return nil }
func (m *networkTestMonitor) DefaultInterface() *control.Interface { return &m.iif }
func (*networkTestMonitor) AndroidVPNEnabled() bool                { return false }
func (m *networkTestMonitor) RegisterCallback(callback tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callbacks.PushBack(callback)
}
func (m *networkTestMonitor) UnregisterCallback(element *list.Element[tun.DefaultInterfaceUpdateCallback]) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks.Remove(element)
}
func (m *networkTestMonitor) emit() {
	m.mu.Lock()
	callbacks := m.callbacks.Array()
	m.mu.Unlock()
	for _, callback := range callbacks {
		callback(&m.iif, 0)
	}
}

type networkTestLogger struct {
	log.ContextLogger
	updates chan struct{}
}

func (l *networkTestLogger) Info(args ...any) {
	if len(args) > 0 && args[0] == "updated default interface " {
		l.updates <- struct{}{}
	}
}

type networkTestFixture struct {
	manager  *NetworkManager
	monitor  *networkTestMonitor
	router   *networkTestRouter
	outbound *networkTestOutbound
	logger   *networkTestLogger
}

func newNetworkTestFixture(t *testing.T) *networkTestFixture {
	t.Helper()
	router := new(networkTestRouter)
	ctx := service.ContextWith[adapter.Router](pause.WithDefaultManager(context.Background()), router)
	monitor := &networkTestMonitor{iif: control.Interface{Name: "test", Index: 0}}
	outbound := &networkTestOutbound{contexts: make(chan context.Context, 16)}
	logger := &networkTestLogger{ContextLogger: log.NewNOPFactory().Logger(), updates: make(chan struct{}, 16)}
	manager := &NetworkManager{
		ctx:              ctx,
		logger:           logger,
		interfaceMonitor: monitor,
		pauseManager:     service.FromContext[pause.Manager](ctx),
		endpoint:         networkTestEndpoints{},
		inbound:          networkTestInbounds{},
		outbound:         networkTestOutbounds{outbound: outbound},
	}
	if err := manager.Start(adapter.StartStateInitialize); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})
	return &networkTestFixture{manager, monitor, router, outbound, logger}
}

func waitNetworkSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for network callback")
	}
}

func (f *networkTestFixture) waitUpdate(t *testing.T) {
	t.Helper()
	waitNetworkSignal(t, f.logger.updates)
	// The log is emitted under resetRunAccess. Acquiring it after the signal
	// waits for the callback to finish without relying on a scheduling sleep.
	f.manager.resetRunAccess.Lock()
	f.manager.resetRunAccess.Unlock()
}

func TestNetworkManagerStartupDoesNotResetConnections(t *testing.T) {
	f := newNetworkTestFixture(t)
	if err := f.manager.Start(adapter.StartStatePostStart); err != nil {
		t.Fatal(err)
	}
	f.waitUpdate(t)
	if f.router.resets.Load() != 0 {
		t.Fatal("normal startup reset existing connections")
	}
}

func TestNetworkManagerDefersStartupUpdatesAndKeepsContext(t *testing.T) {
	f := newNetworkTestFixture(t)
	f.monitor.emit()
	f.monitor.emit()
	if f.router.resets.Load() != 0 {
		t.Fatal("network reset before startup completed")
	}
	if err := f.manager.Start(adapter.StartStatePostStart); err != nil {
		t.Fatal(err)
	}
	f.waitUpdate(t)
	if f.router.resets.Load() != 1 {
		t.Fatal("startup network changes were not coalesced and applied")
	}
	first := <-f.outbound.contexts
	if first.Err() != nil {
		t.Fatal("completed callback cancelled a context still used by an outbound")
	}
	f.monitor.emit()
	f.waitUpdate(t)
	if f.router.resets.Load() != 2 {
		t.Fatal("network change after startup was not applied")
	}
	second := <-f.outbound.contexts
	if first.Err() == nil || second.Err() != nil {
		t.Fatal("network change did not replace the previous update context")
	}
	if err := f.manager.Close(); err != nil {
		t.Fatal(err)
	}
	if second.Err() == nil {
		t.Fatal("shutdown did not cancel the network update context")
	}
	f.monitor.mu.Lock()
	registered := len(f.monitor.callbacks.Array())
	f.monitor.mu.Unlock()
	if registered != 0 {
		t.Fatal("shutdown left the interface callback registered")
	}
}

func TestNetworkManagerStartupConcurrentInterfaceUpdate(t *testing.T) {
	f := newNetworkTestFixture(t)
	start := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		<-start
		done <- f.manager.Start(adapter.StartStatePostStart)
	}()
	close(start)
	f.monitor.emit()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	f.waitUpdate(t)
}

func TestNetworkManagerCloseWaitsForRunningUpdate(t *testing.T) {
	f := newNetworkTestFixture(t)
	if err := f.manager.Start(adapter.StartStatePostStart); err != nil {
		t.Fatal(err)
	}
	f.waitUpdate(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	f.router.onReset = func() { close(entered); <-release }
	f.monitor.emit()
	waitNetworkSignal(t, entered)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := f.manager.Close(); err != nil {
			t.Error(err)
		}
	}()
	waitNetworkSignal(t, f.manager.startedCtx.Done())
	select {
	case <-done:
		t.Fatal("shutdown returned while a network reset was still running")
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	waitNetworkSignal(t, done)
}
