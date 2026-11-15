package reuse

import (
	"net"
	"sync/atomic"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

// Conn watches a pooled transport without consuming bytes from the next reply.
type Conn struct {
	net.Conn
	watch *watch
}

type watch struct {
	done chan struct{}
	data [1]byte
	n    int
	err  error
}

func (c *Conn) Ready(state *atomic.Uint32, from State) bool {
	if from != StateActive && !state.CompareAndSwap(uint32(from), uint32(StateActive)) {
		return false
	}
	idle := &watch{done: make(chan struct{})}
	c.watch = idle
	if !state.CompareAndSwap(uint32(StateActive), uint32(StateReady)) {
		c.watch = nil
		return false
	}
	go func() {
		idle.n, idle.err = c.Conn.Read(idle.data[:])
		// Finish the old watch's state transition before its byte can be consumed
		// and the same session can be returned to the pool again.
		if state.CompareAndSwap(uint32(StateReady), uint32(StateClosed)) {
			c.Conn.Close()
		}
		close(idle.done)
	}()
	return true
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	idle := c.watch
	if idle == nil {
		return c.Conn.Read(p)
	}
	c.watch = nil
	<-idle.done
	if idle.n == 0 && E.IsTimeout(idle.err) {
		return c.Conn.Read(p)
	}
	return copy(p, idle.data[:idle.n]), idle.err
}

func (c *Conn) Upstream() any {
	return c.Conn
}

func (c *Conn) WriterReplaceable() bool {
	return true
}

var (
	_ common.WithUpstream  = (*Conn)(nil)
	_ N.WriterWithUpstream = (*Conn)(nil)
)
