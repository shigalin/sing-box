package snell

import (
	"io"
	"net"
	"sync"
)

type pskReadResult struct {
	data []byte
	err  error
}

// pskReadAhead owns at most one read while lookup waits for CPU capacity.
// A successful short-header lookup can hand that read to the protocol instead
// of waiting for it or changing deadlines to cancel it. No bytes are discarded.
// Lookup owns these fields until handoff; afterwards Read serializes consumers.
type pskReadAhead struct {
	terminalErr error
	net.Conn
	pending chan pskReadResult
	ready   []byte
	access  sync.Mutex
}

func (c *pskReadAhead) start(limit int) {
	if c.pending != nil || c.terminalErr != nil {
		return
	}
	result := make(chan pskReadResult, 1)
	c.pending = result
	go func() {
		data := make([]byte, limit)
		n, err := io.ReadAtLeast(c.Conn, data, 1)
		result <- pskReadResult{data[:n], err}
	}()
}

func (c *pskReadAhead) Read(p []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.pending != nil {
		result := <-c.pending
		c.pending = nil
		if result.err != nil {
			c.terminalErr = result.err
			return 0, result.err
		}
		c.ready = result.data
	}
	if len(c.ready) > 0 {
		n := copy(p, c.ready)
		c.ready = c.ready[n:]
		return n, nil
	}
	if c.terminalErr != nil {
		return 0, c.terminalErr
	}
	return c.Conn.Read(p)
}

func (c *pskReadAhead) handoff() net.Conn {
	if c.pending == nil && len(c.ready) == 0 && c.terminalErr == nil {
		return c.Conn
	}
	return c
}

func (c *pskReadAhead) Upstream() any           { return c.Conn }
func (c *pskReadAhead) ReaderReplaceable() bool { return false }
func (c *pskReadAhead) WriterReplaceable() bool { return true }
