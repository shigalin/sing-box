// Package prefixconn keeps preread bytes private to the reader. Closing the
// transport never releases or mutates bytes a concurrent read may still use.
package prefixconn

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common/bufio"
)

type Conn struct {
	net.Conn
	reader     io.Reader
	readAccess sync.Mutex
	closed     atomic.Bool
	closeOnce  sync.Once
	closeErr   error
}

// New copies the prefix into Go-owned storage. Close only closes the transport;
// it never waits for a blocked read or returns a live buffer to a pool.
func New(conn net.Conn, prefix []byte) net.Conn {
	data := append([]byte(nil), prefix...)
	return &Conn{Conn: conn, reader: io.MultiReader(bytes.NewReader(data), conn)}
}

// TakeCached must run before handing the connection to readers or close hooks.
// ShadowTLS supplies a pooled CachedConn whose Read and Close are not concurrent-safe.
func TakeCached(conn net.Conn) net.Conn {
	cached, ok := conn.(*bufio.CachedConn)
	if !ok {
		return conn
	}
	buffer := cached.ReadCached()
	if buffer == nil {
		return cached.Conn
	}
	safe := New(cached.Conn, buffer.Bytes())
	buffer.Release()
	return safe
}

func (c *Conn) Read(p []byte) (int, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.reader.Read(p)
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() { c.closed.Store(true); c.closeErr = c.Conn.Close() })
	return c.closeErr
}

func (c *Conn) Upstream() any { return c.Conn }

// A reader must not bypass an unconsumed prefix. This value is immutable so
// capability checks are also safe while another goroutine reads or closes.
func (c *Conn) ReaderReplaceable() bool { return false }
func (c *Conn) WriterReplaceable() bool { return true }
