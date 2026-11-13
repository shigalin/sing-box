package snell

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// holdPSKPermits occupies permits the way running lookups would.
func holdPSKPermits(a *pskAdmission, kind pskBudgetKind, count int) {
	a.access.Lock()
	a.budgets[kind].active += count
	a.access.Unlock()
}

func freePSKPermit(a *pskAdmission, kind pskBudgetKind) {
	a.access.Lock()
	a.budgets[kind].active--
	a.dispatchLocked(kind)
	a.access.Unlock()
}

func pskQueued(a *pskAdmission, kind pskBudgetKind) int {
	a.access.Lock()
	defer a.access.Unlock()
	return a.budgets[kind].queued
}

func pskPending(a *pskAdmission) int {
	a.access.Lock()
	defer a.access.Unlock()
	return a.pending
}

// gatedPSKService reports the header of each lookup that reached verification
// and holds it there until released. A lookup sending the apart header is
// released separately.
type gatedPSKService struct {
	pskService
	entered      chan []byte
	release      <-chan struct{}
	apart        []byte
	apartRelease <-chan struct{}
}

func (s *gatedPSKService) MatchPSKHeader(header []byte) bool {
	s.entered <- bytes.Clone(header)
	if s.apart != nil && bytes.Equal(header, s.apart) {
		<-s.apartRelease
	} else {
		<-s.release
	}
	return s.pskService.MatchPSKHeader(header)
}

func TestPSKSharedSourceProbeConcurrencyLeavesRoomForOthers(t *testing.T) {
	h, hello := newPSKTestInbound(t, "shared-source-test-key")
	release := make(chan struct{})
	gate := &gatedPSKService{pskService: h.psk.ordered[0].service, entered: make(chan []byte, 8), release: release}
	h.psk.ordered[0].service = gate
	var workers sync.WaitGroup
	t.Cleanup(func() { close(release); workers.Wait(); h.closePSKConnections() })
	start := func(address string) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, _, err := h.selectPSK(&probeBufferConn{buffer: bytes.NewBuffer(hello)}, adapter.InboundContext{Source: M.ParseSocksaddr(address)})
			if err != nil {
				t.Errorf("shared-source connection was rejected instead of queued: %v", err)
			}
		}()
	}
	entered := func() {
		t.Helper()
		select {
		case <-gate.entered:
		case <-time.After(time.Second):
			t.Fatal("permitted source did not reach PSK verification")
		}
	}
	for i := 0; i < 5; i++ {
		start("192.0.2.1:10000")
		entered()
	}
	start("192.0.2.2:10000")
	entered()
}

// One source holds every probe permit and keeps a backlog waiting for more.
// A second source must be served from the next freed permits, not after the
// whole backlog.
func TestPSKSaturatedSourceYieldsFreedProbeSlots(t *testing.T) {
	const key, backlog = "saturated-source-test-key", 32
	h, busyHello := newPSKTestInbound(t, key)
	otherHello := pskHello(t, key)
	require.NotEqual(t, busyHello[:h.psk.ordered[0].size], otherHello[:h.psk.ordered[0].size])
	release := make(chan struct{})
	gate := &gatedPSKService{pskService: h.psk.ordered[0].service, entered: make(chan []byte, pskProbeConcurrency+backlog+1), release: release}
	h.psk.ordered[0].service = gate
	var workers sync.WaitGroup
	t.Cleanup(func() { close(release); workers.Wait(); h.closePSKConnections() })
	start := func(address string, hello []byte) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, _, err := h.selectPSK(&probeBufferConn{buffer: bytes.NewBuffer(hello)}, adapter.InboundContext{Source: M.ParseSocksaddr(address)})
			if err != nil {
				t.Errorf("queued connection was rejected: %v", err)
			}
		}()
	}
	entered := func() []byte {
		t.Helper()
		select {
		case header := <-gate.entered:
			return header
		case <-time.After(time.Second):
			t.Fatal("no lookup reached PSK verification")
			return nil
		}
	}
	for i := 0; i < pskProbeConcurrency; i++ {
		start("192.0.2.1:10000", busyHello)
		entered()
	}
	for i := 0; i < backlog; i++ {
		start("192.0.2.1:10000", busyHello)
	}
	require.Eventually(t, func() bool { return pskQueued(h.psk.admission, pskProbeBudget) == backlog }, time.Second, time.Millisecond)
	start("192.0.2.2:10000", otherHello)
	require.Eventually(t, func() bool { return pskQueued(h.psk.admission, pskProbeBudget) == backlog+1 }, time.Second, time.Millisecond)
	// Two freed permits: one continues the busy source, one serves the other.
	release <- struct{}{}
	release <- struct{}{}
	served := [][]byte{entered(), entered()}
	require.Contains(t, served, otherHello[:h.psk.ordered[0].size], "second source waited behind the saturated source's backlog")
	require.Equal(t, backlog-1, pskQueued(h.psk.admission, pskProbeBudget))
}

// A table larger than one chunk is scanned a chunk per permit. Between chunks
// the permit goes to another waiting source, then back to the lookup that had
// started rather than to a new lookup of its source.
func TestPSKChunkedScanYieldsBetweenChunks(t *testing.T) {
	users := make([]option.SnellUser, 2*pskProbeChunk+8)
	for i := range users {
		users[i] = option.SnellUser{Name: fmt.Sprint("user-", i), PSK: fmt.Sprint("independent-test-psk-", i)}
	}
	in, err := NewInbound(context.Background(), nil, log.NewNOPFactory().NewLogger("test"), "snell", option.SnellInboundOptions{Version: 5, AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{UserPSK: true, Users: users}})
	require.NoError(t, err)
	h := in.(*Inbound)
	require.Len(t, h.psk.groups, 3)
	var regrouped []*pskEntry
	for _, group := range h.psk.groups {
		require.LessOrEqual(t, len(group), pskProbeChunk)
		regrouped = append(regrouped, group...)
	}
	require.Equal(t, h.psk.ordered, regrouped)

	size := h.psk.ordered[0].size
	busyHello := pskHello(t, users[len(users)-1].PSK) // matches in the last chunk
	otherHello := pskHello(t, users[1].PSK)           // matches in the first chunk
	release, otherRelease := make(chan struct{}), make(chan struct{})
	first := &gatedPSKService{pskService: h.psk.ordered[0].service, entered: make(chan []byte, 32), release: release, apart: otherHello[:size], apartRelease: otherRelease}
	second := &gatedPSKService{pskService: h.psk.ordered[pskProbeChunk].service, entered: make(chan []byte, 32), release: release}
	h.psk.ordered[0].service, h.psk.ordered[pskProbeChunk].service = first, second
	var workers sync.WaitGroup
	t.Cleanup(func() { close(release); workers.Wait(); h.closePSKConnections() })
	start := func(address string, hello []byte, expected *pskEntry) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			entry, _, err := h.selectPSK(&probeBufferConn{buffer: bytes.NewBuffer(hello)}, adapter.InboundContext{Source: M.ParseSocksaddr(address)})
			if err != nil || entry != expected {
				t.Errorf("lookup from %s selected %v: %v", address, entry, err)
			}
		}()
	}
	entered := func(gate *gatedPSKService, message string) []byte {
		t.Helper()
		select {
		case header := <-gate.entered:
			return header
		case <-time.After(time.Second):
			t.Fatal(message)
			return nil
		}
	}
	queued := func(count int) {
		t.Helper()
		require.Eventually(t, func() bool { return pskQueued(h.psk.admission, pskProbeBudget) == count }, time.Second, time.Millisecond)
	}
	last := h.psk.ordered[len(users)-1]
	for i := 0; i < pskProbeConcurrency; i++ {
		start("192.0.2.1:10000", busyHello, last)
		entered(first, "busy source did not reach verification")
	}
	start("192.0.2.2:10000", otherHello, h.psk.ordered[1])
	queued(1)
	start("192.0.2.1:10000", busyHello, last) // a new lookup of the busy source
	queued(2)
	// One busy lookup finishes its first chunk. The other source is served next.
	release <- struct{}{}
	require.Equal(t, otherHello[:size], entered(first, "another source waited for more than one chunk"))
	queued(2) // the started lookup and the new one, both of the busy source
	// The other source finishes. Its permit resumes the started lookup.
	close(otherRelease)
	require.Equal(t, busyHello[:size], entered(second, "a started lookup did not resume ahead of its source's new lookup"))
	queued(1)
	require.Empty(t, first.entered, "a new lookup started ahead of one in progress")
}

// A lookup between chunks is not refused by a queue that filled up meanwhile.
func TestPSKStartedLookupIsNotRefusedByFullQueue(t *testing.T) {
	admission := newPSKAdmission()
	source := netip.MustParseAddr("192.0.2.1")
	started, err := admission.enter(source, false)
	require.NoError(t, err)
	granted, _, err := started.acquire(pskProbeBudget)
	require.NoError(t, err)
	require.True(t, granted)
	holdPSKPermits(admission, pskProbeBudget, pskProbeConcurrency-1)
	admission.access.Lock()
	admission.budgets[pskProbeBudget].queued = pskProbeQueued
	admission.access.Unlock()
	fresh, err := admission.enter(source, false)
	require.NoError(t, err)
	_, _, err = fresh.acquire(pskProbeBudget)
	require.ErrorIs(t, err, errPSKOverloaded)
	started.release(pskProbeBudget)
	holdPSKPermits(admission, pskProbeBudget, 1)
	granted, _, err = started.acquire(pskProbeBudget)
	require.NoError(t, err, "a full queue closed a lookup that had already started")
	require.False(t, granted)
	freePSKPermit(admission, pskProbeBudget)
	granted, _, err = started.acquire(pskProbeBudget)
	require.NoError(t, err)
	require.True(t, granted)
}

func TestPSKSourceCannotExhaustSharedCapacity(t *testing.T) {
	admission := newPSKAdmission()
	busy, other := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	holdPSKPermits(admission, pskProbeBudget, pskProbeConcurrency)
	for i := 0; i < pskSourcePending; i++ {
		ticket, err := admission.enter(busy, false)
		require.NoError(t, err)
		if i < pskSourceProbeQueued+1 {
			_, _, err = ticket.acquire(pskProbeBudget)
			if i < pskSourceProbeQueued {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, errPSKOverloaded, "one source filled the probe queue")
			}
		}
	}
	_, err := admission.enter(busy, false)
	require.ErrorIs(t, err, errPSKOverloaded, "one source filled the pending capacity")
	ticket, err := admission.enter(other, false)
	require.NoError(t, err)
	granted, _, err := ticket.acquire(pskProbeBudget)
	require.NoError(t, err)
	require.False(t, granted)
	// The other source is next in turn despite the busy source's longer queue.
	freePSKPermit(admission, pskProbeBudget)
	freePSKPermit(admission, pskProbeBudget)
	granted, _, err = ticket.acquire(pskProbeBudget)
	require.NoError(t, err)
	require.True(t, granted)
	ticket.close()
	require.Equal(t, pskProbeConcurrency, admission.budgets[pskProbeBudget].active, "a closed ticket's permit passes to the next waiter")
}

func TestPSKSharedSourcePendingBurstIsNotRejectedAtOldLimit(t *testing.T) {
	h, _ := newPSKTestInbound(t, "pending-limit-test-key")
	var workers sync.WaitGroup
	t.Cleanup(func() { h.closePSKConnections(); workers.Wait() })
	source := adapter.InboundContext{Source: M.ParseSocksaddr("192.0.2.1:12345")}
	for i := 0; i < 256; i++ {
		raw, peer := net.Pipe()
		t.Cleanup(func() { peer.Close() })
		read := make(chan struct{}, 1)
		workers.Add(1)
		go func() {
			defer workers.Done()
			h.NewConnection(context.Background(), &observedProbeConn{Conn: raw, reads: read}, source, nil)
		}()
		select {
		case <-read:
		case <-time.After(time.Second):
			t.Fatal("shared-source burst was rejected before the pending limit")
		}
	}
	raw, peer := net.Pipe()
	defer peer.Close()
	workers.Add(1)
	go func() { defer workers.Done(); h.NewConnection(context.Background(), raw, source, nil) }()
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
	_, err := peer.Read(make([]byte, 1))
	var netErr net.Error
	require.ErrorAs(t, err, &netErr, "a shared-source burst above the former per-source cap must remain pending")
	require.True(t, netErr.Timeout())
}

func TestPSKSharedSourceHintConcurrencyAllowsFiveUsers(t *testing.T) {
	admission := newPSKAdmission()
	source := M.ParseSocksaddr("192.0.2.1:12345").Addr
	tickets := make([]*pskAdmissionTicket, 5)
	for i := range tickets {
		ticket, err := admission.enter(source, true)
		require.NoError(t, err)
		tickets[i] = ticket
	}
	for _, ticket := range tickets {
		granted, _, err := ticket.acquire(pskHintBudget)
		require.NoError(t, err)
		require.True(t, granted, "same-source users above the former four-hint cap must be verified")
	}
	require.Equal(t, 5, admission.budgets[pskHintBudget].active)
	for _, ticket := range tickets {
		ticket.close()
	}
	require.Zero(t, admission.budgets[pskHintBudget].active)
}

func TestPSKFullSourceTableFallsBackToGlobalBudgets(t *testing.T) {
	admission := newPSKAdmission()
	now := time.Now()
	admission.now = func() time.Time { return now }
	admission.nextSweep = now.Add(time.Hour)
	for i := 0; i < pskAdmissionSources; i++ {
		admission.sources[netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})] = newPSKSourceAdmission()
	}
	ticket, err := admission.enter(netip.MustParseAddr("192.0.2.10"), false)
	require.NoError(t, err)
	require.True(t, ticket.untracked)
	granted, _, err := ticket.acquire(pskHintBudget)
	require.NoError(t, err)
	require.True(t, granted)
	ticket.release(pskHintBudget)
	probe := &admission.budgets[pskProbeBudget]
	probe.rate = rate.NewLimiter(1, 1)
	probe.rate.AllowN(now, 1)
	granted, retry, err := ticket.acquire(pskProbeBudget)
	require.NoError(t, err)
	require.False(t, granted)
	require.True(t, retry.After(now), "untracked sources must share the global probe rate budget")
	require.Equal(t, 1, probe.queued, "a rate-limited lookup waits in the queue")
	now = now.Add(2 * time.Second)
	granted, _, err = ticket.acquire(pskProbeBudget)
	require.NoError(t, err)
	require.True(t, granted)
	require.Zero(t, probe.queued)
	ticket.release(pskProbeBudget)
	ticket.close()
	require.Len(t, admission.sources, pskAdmissionSources)
	require.Zero(t, admission.pending)
	require.Zero(t, admission.cold)
}

// pskFirstFlight is what a client of the inbound's version sends first.
func pskFirstFlight(t *testing.T, version int, psk string) []byte {
	if version == 5 {
		return pskHello(t, psk)
	}
	client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(psk)})
	require.NoError(t, err)
	wire := &probeBufferConn{buffer: new(bytes.Buffer)}
	_, err = client.DialConn(wire, M.ParseSocksaddr("127.0.0.1:80"))
	require.NoError(t, err)
	return wire.buffer.Bytes()
}

// More users than a source can have cached share one address and authenticate
// at once while both budgets are busy, first cold and then with the cache full.
func TestPSKSharedSourceConcurrentUsersBeyondHintLimit(t *testing.T) {
	for _, version := range []int{5, 6} {
		t.Run(fmt.Sprint("v", version), func(t *testing.T) {
			users := make([]option.SnellUser, pskHintsPerSource+2)
			for i := range users {
				users[i] = option.SnellUser{Name: fmt.Sprint("user-", i), PSK: fmt.Sprint("independent-test-psk-", i)}
			}
			router := &userRouter{users: make(chan string, len(users))}
			in, err := NewInbound(context.Background(), router, log.NewNOPFactory().NewLogger("test"), "snell", option.SnellInboundOptions{Version: version, AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{UserPSK: true, Users: users}})
			require.NoError(t, err)
			h := in.(*Inbound)
			ctx, cancel := context.WithCancel(context.Background())
			var workers sync.WaitGroup
			t.Cleanup(func() { cancel(); h.closePSKConnections(); workers.Wait() })
			admission := h.psk.admission
			source := netip.MustParseAddr("192.0.2.1")
			for round, cached := range []int{0, pskHintsPerSource} {
				holdPSKPermits(admission, pskProbeBudget, pskProbeConcurrency)
				holdPSKPermits(admission, pskHintBudget, pskHintConcurrency)
				for i, user := range users {
					hello := pskFirstFlight(t, version, user.PSK)
					metadata := adapter.InboundContext{Source: M.SocksaddrFrom(source, uint16(10000+round*100+i))}
					workers.Add(1)
					go func() {
						defer workers.Done()
						h.NewConnection(ctx, &helloConn{reader: bytes.NewReader(hello)}, metadata, nil)
					}()
				}
				// Everyone waits: for the full table, and for the cached users once there are any.
				require.Eventually(t, func() bool {
					return pskQueued(admission, pskProbeBudget) == len(users) && (cached == 0 || pskQueued(admission, pskHintBudget) == len(users))
				}, time.Second, time.Millisecond)
				for i := 0; i < pskHintConcurrency; i++ {
					freePSKPermit(admission, pskHintBudget)
				}
				for i := 0; i < pskProbeConcurrency; i++ {
					freePSKPermit(admission, pskProbeBudget)
				}
				routed := make([]string, 0, len(users))
				for range users {
					select {
					case user := <-router.users:
						routed = append(routed, user)
					case <-time.After(2 * time.Second):
						t.Fatalf("round %d: only %v authenticated", round, routed)
					}
				}
				expected := make([]string, len(users))
				for i, user := range users {
					expected[i] = user.Name
				}
				require.ElementsMatch(t, expected, routed)
				// The reuse sessions stay open, but none still holds admission capacity.
				require.Eventually(t, func() bool { return pskPending(admission) == 0 }, time.Second, time.Millisecond)
				h.psk.access.RLock()
				remembered := len(h.psk.hints[source])
				h.psk.access.RUnlock()
				require.Equal(t, pskHintsPerSource, remembered)
			}
		})
	}
}

type deadlineConn struct {
	net.Conn
	armed atomic.Bool
}

func (c *deadlineConn) SetReadDeadline(deadline time.Time) error {
	c.armed.Store(!deadline.IsZero())
	return c.Conn.SetReadDeadline(deadline)
}

// A matching header alone is not an authenticated connection: it keeps its
// pending slot and deadline, and leaves no cache entry, until the first request
// is valid.
func TestPSKPendingSlotHeldUntilFirstRequest(t *testing.T) {
	for _, version := range []int{5, 6} {
		for _, complete := range []bool{false, true} {
			t.Run(fmt.Sprint("v", version, "/complete=", complete), func(t *testing.T) {
				const psk = "first-request-test-key"
				router := &userRouter{users: make(chan string, 1)}
				in, err := NewInbound(context.Background(), router, log.NewNOPFactory().NewLogger("test"), "snell", option.SnellInboundOptions{Version: version, AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{UserPSK: true, Users: []option.SnellUser{{Name: "alice", PSK: psk}}}})
				require.NoError(t, err)
				h := in.(*Inbound)
				h.psk.timeout = 300 * time.Millisecond
				entry := h.psk.ordered[0]
				hello := pskFirstFlight(t, version, psk)
				require.Greater(t, len(hello), entry.size)
				raw, peer := net.Pipe()
				conn := &deadlineConn{Conn: raw}
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				t.Cleanup(func() { cancel(); peer.Close(); h.closePSKConnections(); <-done })
				metadata := adapter.InboundContext{Source: M.ParseSocksaddr("192.0.2.1:50000")}
				go func() { defer close(done); h.NewConnection(ctx, conn, metadata, nil) }()
				require.NoError(t, peer.SetDeadline(time.Now().Add(2*time.Second)))
				_, err = peer.Write(hello[:entry.size])
				require.NoError(t, err)
				selected := func() bool {
					h.psk.access.RLock()
					defer h.psk.access.RUnlock()
					for _, user := range h.psk.conns {
						return user == entry
					}
					return false
				}
				require.Eventually(t, selected, time.Second, time.Millisecond)
				remembered := func() int {
					h.psk.access.RLock()
					defer h.psk.access.RUnlock()
					return len(h.psk.hints)
				}
				require.Equal(t, 1, pskPending(h.psk.admission), "header match released the pending slot")
				require.True(t, conn.armed.Load(), "header match cleared the handshake deadline")
				require.Zero(t, remembered(), "header match was remembered before the request was valid")
				if !complete {
					// The rest of the request never arrives.
					_, err = peer.Read(make([]byte, 1))
					require.ErrorIs(t, err, io.EOF, "connection outlived the handshake deadline")
					<-done
					require.Zero(t, pskPending(h.psk.admission))
					require.Zero(t, remembered())
					return
				}
				_, err = peer.Write(hello[entry.size:])
				require.NoError(t, err)
				select {
				case user := <-router.users:
					require.Equal(t, "alice", user)
				case <-time.After(time.Second):
					t.Fatal("complete request was not routed")
				}
				// The reuse session is established and still open.
				require.Zero(t, pskPending(h.psk.admission), "an established session kept its pending slot")
				require.False(t, conn.armed.Load(), "an established session kept the handshake deadline")
				require.Equal(t, 1, remembered())
				select {
				case <-done:
					t.Fatal("established session ended")
				case <-time.After(2 * h.psk.timeout):
				}
			})
		}
	}
}
