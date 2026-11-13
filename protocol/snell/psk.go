package snell

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/prefixconn"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type pskService interface {
	snellprotocol.Service
	PSKHeaderSize() int
	MatchPSKHeader([]byte) bool
}
type pskEntry struct {
	name, key string
	service   pskService
	size      int // service.PSKHeaderSize(), fixed for the entry's lifetime
}
type pskState struct {
	closed      bool
	done        chan struct{}
	admission   *pskAdmission
	replayCache *snellv5.ReplayCache
	options     option.SnellInboundOptions
	// Bounds header lookup and the first request together.
	timeout time.Duration
	access  sync.RWMutex
	entries map[string]*pskEntry
	ordered []*pskEntry
	// ordered split by header size, shortest first, and into chunks of at most
	// pskProbeChunk candidates; rebuilt with ordered.
	groups [][]*pskEntry
	conns  map[*pskConn]*pskEntry
	// Users that last authenticated from a source address, most recent first.
	// Only successful authentications add entries, and access guards them.
	hints map[netip.Addr][]*pskEntry
}
type pskContextKey struct{}

const (
	pskHintSources    = 4096
	pskHintsPerSource = 4
)

// rememberSource requires access to be held for writing.
func (s *pskState) rememberSource(source netip.Addr, entry *pskEntry) {
	source = source.Unmap()
	if !source.IsValid() {
		return
	}
	hints := s.hints[source]
	index := slices.Index(hints, entry)
	switch {
	case index == 0:
		return
	case index > 0:
		copy(hints[1:index+1], hints[:index])
	default:
		if hints == nil && len(s.hints) >= pskHintSources {
			for evicted := range s.hints {
				delete(s.hints, evicted)
				break
			}
		}
		if len(hints) < pskHintsPerSource {
			hints = append(hints, nil)
		}
		copy(hints[1:], hints)
	}
	hints[0] = entry
	s.hints[source] = hints
}

func (h *Inbound) updatePSKUsers(users []option.SnellUser) error {
	h.updateAccess.Lock()
	defer h.updateAccess.Unlock()
	if h.psk.replayCache == nil {
		h.psk.replayCache = &snellv5.ReplayCache{}
	}
	options := h.psk.options
	var mode snellv6.Mode
	var obfs snellprotocol.ObfsMode
	var err error
	switch options.Version {
	case 5:
		obfs, err = snellprotocol.ParseObfsMode(options.ObfsOptions.ObfsMode)
	case 6:
		mode, err = snellv6.ParseMode(options.V6Options.Mode)
		if mode == snellv6.ModeUnsafeRaw {
			return E.New("snell: user_psk requires an encrypted mode")
		}
	default:
		return E.New("snell: unsupported user_psk version")
	}
	if err != nil {
		return err
	}
	if obfs == snellprotocol.ObfsModeTLS {
		return E.New("snell: user_psk supports none or http obfs")
	}
	h.psk.access.RLock()
	if h.psk.closed {
		h.psk.access.RUnlock()
		return net.ErrClosed
	}
	old := h.psk.entries
	h.psk.access.RUnlock()
	next := make(map[string]*pskEntry, len(users))
	keys := make(map[string]bool, len(users))
	ordered := make([]*pskEntry, 0, len(users))
	for _, user := range users {
		if user.Name == "" || user.PSK == "" || user.UserKey != "" {
			return E.New("snell: user_psk requires a name and PSK, without userkey")
		}
		if next[user.Name] != nil || keys[user.PSK] {
			return E.New("snell: duplicate user name or PSK")
		}
		keys[user.PSK] = true
		entry := old[user.Name]
		if entry == nil || entry.key != user.PSK {
			entry = &pskEntry{name: user.Name, key: user.PSK}
			if options.Version == 5 {
				entry.service, err = snellv5.NewService(snellv5.ServiceOptions{PSK: []byte(user.PSK), Handler: h, ReplayCache: h.psk.replayCache})
			} else {
				entry.service, err = snellv6.NewService(snellv6.ServerOptions{PSK: []byte(user.PSK), Mode: mode, Handler: h})
			}
			if err != nil {
				return err
			}
			entry.size = entry.service.PSKHeaderSize()
		}
		next[user.Name] = entry
		ordered = append(ordered, entry)
	}
	// Read only the next smallest required prefix: a wrong v6 profile must not
	// stall a valid shorter handshake. Each candidate is tried at most once.
	slices.SortStableFunc(ordered, func(a, b *pskEntry) int { return a.size - b.size })
	// Group here, once per update, rather than on every pass of every lookup.
	var groups [][]*pskEntry
	for start := 0; start < len(ordered); {
		end := start + 1
		for end < len(ordered) && end-start < pskProbeChunk && ordered[end].size == ordered[start].size {
			end++
		}
		groups = append(groups, ordered[start:end:end])
		start = end
	}
	var removed []*pskConn
	h.psk.access.Lock()
	h.psk.entries, h.psk.ordered, h.psk.groups = next, ordered, groups
	for source, hints := range h.psk.hints {
		hints = slices.DeleteFunc(hints, func(entry *pskEntry) bool { return next[entry.name] != entry })
		if len(hints) == 0 {
			delete(h.psk.hints, source)
		} else {
			h.psk.hints[source] = hints
		}
	}
	for conn, entry := range h.psk.conns {
		if (entry == nil && len(next) == 0) || (entry != nil && next[entry.name] != entry) {
			removed = append(removed, conn)
		}
	}
	h.psk.access.Unlock()
	for _, conn := range removed {
		conn.Close()
	}
	return nil
}

func (h *Inbound) newPSKConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ticket, err := h.admitPSK(metadata)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	defer ticket.close()
	tracked := &pskConn{Conn: conn, state: h.psk, done: make(chan struct{})}
	h.psk.access.Lock()
	if h.psk.closed {
		h.psk.access.Unlock()
		N.CloseOnHandshakeFailure(conn, onClose, net.ErrClosed)
		return
	}
	// Register before reading so removal of the inbound also closes slow probes.
	h.psk.conns[tracked] = nil
	h.psk.access.Unlock()
	onClose = N.OnceClose(N.AppendClose(onClose, func(error) { tracked.Close() }))
	entry, transport, err := h.selectPSKAdmitted(tracked, metadata, ticket, tracked.done)
	if err != nil {
		N.CloseOnHandshakeFailure(transport, onClose, err)
		return
	}
	h.psk.access.Lock()
	if h.psk.closed || h.psk.entries[entry.name] != entry {
		h.psk.access.Unlock()
		N.CloseOnHandshakeFailure(transport, onClose, os.ErrPermission)
		return
	}
	h.psk.conns[tracked] = entry
	h.psk.access.Unlock()
	metadata.User = entry.name
	ctx = context.WithValue(adapter.WithContext(ctx, &metadata), pskContextKey{}, entry)
	// A matching header can be replayed and is not yet a valid request. Until the
	// protocol accepts the first request, the connection keeps its pending slot
	// and its deadline, and its source is not remembered. A failed or timed-out
	// request returns the slot through the deferred close above.
	ctx = snellprotocol.ContextWithRequestAccepted(ctx, func() {
		transport.SetReadDeadline(time.Time{})
		h.psk.access.Lock()
		if !h.psk.closed && h.psk.entries[entry.name] == entry {
			h.psk.rememberSource(metadata.Source.Addr, entry)
		}
		h.psk.access.Unlock()
		ticket.close()
	})
	err = entry.service.NewConnection(ctx, transport, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(transport, onClose, err)
	}
}

func (h *Inbound) closePSKConnections() error {
	h.updateAccess.Lock()
	defer h.updateAccess.Unlock()
	h.psk.access.Lock()
	if !h.psk.closed {
		close(h.psk.done)
	}
	h.psk.closed = true
	h.psk.entries = nil
	h.psk.ordered = nil
	h.psk.groups = nil
	h.psk.hints = nil
	pending := make([]*pskConn, 0, len(h.psk.conns))
	for conn := range h.psk.conns {
		pending = append(pending, conn)
	}
	h.psk.access.Unlock()
	for _, conn := range pending {
		conn.Close()
	}
	return nil
}

func (h *Inbound) admitPSK(metadata adapter.InboundContext) (*pskAdmissionTicket, error) {
	if source := h.psk.options.AuthDetour; source != "" {
		// Only the configured ShadowTLS gateway can reach this internal listener.
		// Its shared password does not select a user: the inner PSK does.
		if metadata.LastInbound != source || metadata.InboundType != C.TypeShadowTLS || metadata.User == "" {
			return nil, os.ErrPermission
		}
	}
	h.psk.access.RLock()
	closed := h.psk.closed
	hinted := len(h.psk.hints[metadata.Source.Addr.Unmap()]) > 0
	h.psk.access.RUnlock()
	if closed {
		return nil, net.ErrClosed
	}
	return h.psk.admission.enter(metadata.Source.Addr, hinted)
}

func (h *Inbound) selectPSK(conn net.Conn, metadata adapter.InboundContext) (*pskEntry, net.Conn, error) {
	ticket, err := h.admitPSK(metadata)
	if err != nil {
		return nil, conn, err
	}
	defer ticket.close()
	entry, transport, err := h.selectPSKAdmitted(conn, metadata, ticket, nil)
	if err == nil {
		err = transport.SetReadDeadline(time.Time{})
	}
	return entry, transport, err
}

// selectPSKAdmitted leaves the read deadline armed on success: it also bounds
// the first request, which is only validated by the selected service.
func (h *Inbound) selectPSKAdmitted(conn net.Conn, metadata adapter.InboundContext, ticket *pskAdmissionTicket, closed <-chan struct{}) (*pskEntry, net.Conn, error) {
	var hinted, untried [pskHintsPerSource]*pskEntry
	h.psk.access.RLock()
	groups := h.psk.groups
	hints := hinted[:copy(hinted[:], h.psk.hints[metadata.Source.Addr.Unmap()])]
	h.psk.access.RUnlock()
	copy(untried[:], hints)
	if len(groups) == 0 {
		return nil, conn, os.ErrPermission
	}
	// Header sizes are fixed by the supported wire formats, not peer input.
	maxSize := groups[len(groups)-1][0].size
	if groups[0][0].size <= 0 || maxSize > 4096 {
		return nil, conn, E.New("snell: invalid PSK probe size")
	}
	if h.psk.options.Version == 5 {
		mode, _ := snellprotocol.ParseObfsMode(h.psk.options.ObfsOptions.ObfsMode)
		conn = (snellprotocol.ObfsConfig{Mode: mode}).ServerConn(conn)
	}
	deadline := time.Now().Add(h.psk.timeout)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, conn, err
	}
	prefix := make([]byte, 0, maxSize)
	reader := &pskReadAhead{Conn: conn}
	handedOff := false
	defer func() {
		ticket.leave()
		if !handedOff && reader.pending != nil {
			conn.Close()
		}
	}()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	// Cached candidates and the full table advance independently, each as far
	// as the received bytes and its own budget allow: neither a short cached
	// header waiting for its budget nor a busy probe budget holds back the other.
	for {
		select {
		case <-h.psk.done:
			return nil, conn, net.ErrClosed
		case <-closed:
			return nil, conn, net.ErrClosed
		default:
		}
		if time.Now().After(deadline) {
			return nil, conn, os.ErrDeadlineExceeded
		}
		waiting := false
		var retryAt time.Time
		if slices.ContainsFunc(untried[:], func(hint *pskEntry) bool { return hint != nil && hint.size <= len(prefix) }) {
			// A full queue fails this attempt only; the lookup ends below once
			// nothing else can make progress.
			if granted, retry, err := ticket.acquire(pskHintBudget); granted {
				var matched *pskEntry
				for index, candidate := range untried {
					if candidate == nil || candidate.size > len(prefix) {
						continue
					}
					untried[index] = nil
					if candidate.service.MatchPSKHeader(prefix) {
						matched = candidate
						break
					}
				}
				ticket.release(pskHintBudget)
				if matched != nil {
					handedOff = true
					return matched, prefixconn.New(reader.handoff(), prefix), nil
				}
			} else if err == nil {
				waiting, retryAt = true, retry
			}
		}
		// Hinted candidates only use the hint budget.
		for len(groups) > 0 && !slices.ContainsFunc(groups[0], func(entry *pskEntry) bool { return !slices.Contains(hints, entry) }) {
			groups = groups[1:]
		}
		if len(groups) > 0 && groups[0][0].size <= len(prefix) {
			if granted, retry, err := ticket.acquire(pskProbeBudget); granted {
				entry, err := h.psk.match(groups[0], hints, prefix, deadline)
				ticket.release(pskProbeBudget)
				if err != nil {
					return nil, conn, err
				}
				if entry != nil {
					handedOff = true
					return entry, prefixconn.New(reader.handoff(), prefix), nil
				}
				groups = groups[1:]
				continue
			} else if err == nil {
				waiting = true
				if !retry.IsZero() && (retryAt.IsZero() || retry.Before(retryAt)) {
					retryAt = retry
				}
			}
		}
		// The smallest prefix either lookup still lacks.
		need := 0
		if len(groups) > 0 && groups[0][0].size > len(prefix) {
			need = groups[0][0].size
		}
		hintsLeft := false
		for _, hint := range untried {
			if hint == nil {
				continue
			}
			hintsLeft = true
			if hint.size > len(prefix) && (need == 0 || hint.size < need) {
				need = hint.size
			}
		}
		if len(groups) == 0 && !hintsLeft {
			return nil, conn, os.ErrPermission
		}
		if !waiting {
			if need == 0 {
				// Every remaining candidate was refused by a full queue.
				return nil, conn, errPSKOverloaded
			}
			// Keep whatever else already arrived: a first flight is longer
			// than its header, so this usually reads enough for every size.
			n, err := io.ReadAtLeast(reader, prefix[len(prefix):maxSize], need-len(prefix))
			prefix = prefix[:len(prefix)+n]
			if err != nil {
				return nil, conn, err
			}
			continue
		}
		// At most one read runs while waiting for a budget.
		if need > 0 {
			reader.start(maxSize - len(prefix))
		}
		var rateTimer *time.Timer
		var rateReady <-chan time.Time
		if !retryAt.IsZero() {
			rateTimer = time.NewTimer(time.Until(retryAt))
			rateReady = rateTimer.C
		}
		var waitErr error
		select {
		case <-ticket.ready:
		case <-rateReady:
		case result := <-reader.pending:
			reader.pending = nil
			if result.err != nil {
				reader.terminalErr = result.err
			}
			prefix = append(prefix, result.data...)
		case <-h.psk.done:
			waitErr = net.ErrClosed
		case <-closed:
			waitErr = net.ErrClosed
		case <-timer.C:
			waitErr = os.ErrDeadlineExceeded
		}
		if rateTimer != nil {
			rateTimer.Stop()
		}
		if waitErr != nil {
			return nil, conn, waitErr
		}
	}
}

// match runs with the permit already acquired by selectPSK. It performs no I/O:
// receiving another hinted header must remain possible while slots are busy.
func (s *pskState) match(candidates []*pskEntry, hints []*pskEntry, prefix []byte, deadline time.Time) (*pskEntry, error) {
	for _, entry := range candidates {
		if slices.Contains(hints, entry) {
			continue
		}
		if time.Now().After(deadline) {
			return nil, os.ErrDeadlineExceeded
		}
		if entry.service.MatchPSKHeader(prefix) {
			return entry, nil
		}
	}
	return nil, nil
}

type pskConn struct {
	net.Conn
	state    *pskState
	done     chan struct{}
	once     sync.Once
	closeErr error
}

func (c *pskConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		c.state.access.Lock()
		delete(c.state.conns, c)
		c.state.access.Unlock()
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *pskConn) Upstream() any           { return c.Conn }
func (c *pskConn) ReaderReplaceable() bool { return true }
func (c *pskConn) WriterReplaceable() bool { return true }
