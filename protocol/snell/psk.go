package snell

import (
	"context"
	"io"
	"net"
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
}
type pskState struct {
	closed      bool
	probeSlots  chan struct{}
	replayCache *snellv5.ReplayCache
	options     option.SnellInboundOptions
	access      sync.RWMutex
	entries     map[string]*pskEntry
	ordered     []*pskEntry
	conns       map[*pskConn]*pskEntry
}
type pskContextKey struct{}

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
		}
		next[user.Name] = entry
		ordered = append(ordered, entry)
	}
	// Read only the next smallest required prefix: a wrong v6 profile must not
	// stall a valid shorter handshake. Each candidate is tried at most once.
	slices.SortStableFunc(ordered, func(a, b *pskEntry) int { return a.service.PSKHeaderSize() - b.service.PSKHeaderSize() })
	var removed []*pskConn
	h.psk.access.Lock()
	h.psk.entries, h.psk.ordered = next, ordered
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
	tracked := &pskConn{Conn: conn, state: h.psk}
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
	entry, transport, err := h.selectPSK(tracked, metadata)
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
	err = entry.service.NewConnection(ctx, transport, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(transport, onClose, err)
	}
}

func (h *Inbound) closePSKConnections() error {
	h.updateAccess.Lock()
	defer h.updateAccess.Unlock()
	h.psk.access.Lock()
	h.psk.closed = true
	h.psk.entries = nil
	h.psk.ordered = nil
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

func (h *Inbound) selectPSK(conn net.Conn, metadata adapter.InboundContext) (*pskEntry, net.Conn, error) {
	if source := h.psk.options.AuthDetour; source != "" {
		// Only the configured ShadowTLS gateway can reach this internal listener.
		// Its shared password does not select a user: the inner PSK does.
		if metadata.LastInbound != source || metadata.InboundType != C.TypeShadowTLS || metadata.User == "" {
			return nil, conn, os.ErrPermission
		}
	}
	h.psk.access.RLock()
	candidates := h.psk.ordered
	h.psk.access.RUnlock()
	if len(candidates) == 0 {
		return nil, conn, os.ErrPermission
	}
	// Bound unauthenticated CPU work and slow handshakes on this listener.
	select {
	case h.psk.probeSlots <- struct{}{}:
		defer func() { <-h.psk.probeSlots }()
	default:
		return nil, conn, E.New("snell: too many pending PSK authentications")
	}
	if h.psk.options.Version == 5 {
		mode, _ := snellprotocol.ParseObfsMode(h.psk.options.ObfsOptions.ObfsMode)
		conn = (snellprotocol.ObfsConfig{Mode: mode}).ServerConn(conn)
	}
	if err := conn.SetReadDeadline(time.Now().Add(C.TCPTimeout)); err != nil {
		return nil, conn, err
	}
	defer conn.SetReadDeadline(time.Time{})
	deadline := time.Now().Add(C.TCPTimeout)
	var prefix []byte
	for _, entry := range candidates {
		if time.Now().After(deadline) {
			return nil, conn, os.ErrDeadlineExceeded
		}
		size := entry.service.PSKHeaderSize()
		// Header sizes are fixed by the supported wire formats, not peer input.
		if size <= 0 || size > 4096 {
			return nil, conn, E.New("snell: invalid PSK probe size")
		}
		if size > len(prefix) {
			previous := len(prefix)
			prefix = append(prefix, make([]byte, size-previous)...)
			if _, err := io.ReadFull(conn, prefix[previous:]); err != nil {
				return nil, conn, err
			}
		}
		if entry.service.MatchPSKHeader(prefix) {
			return entry, prefixconn.New(conn, prefix), nil
		}
	}
	return nil, conn, os.ErrPermission
}

type pskConn struct {
	net.Conn
	state *pskState
}

func (c *pskConn) Close() error {
	c.state.access.Lock()
	delete(c.state.conns, c)
	c.state.access.Unlock()
	return c.Conn.Close()
}

func (c *pskConn) Upstream() any           { return c.Conn }
func (c *pskConn) ReaderReplaceable() bool { return true }
func (c *pskConn) WriterReplaceable() bool { return true }
