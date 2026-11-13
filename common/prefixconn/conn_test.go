package prefixconn

import (
	"bytes"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/stretchr/testify/require"
)

func TestPrefixThenTransport(t *testing.T) {
	for _, cached := range []bool{false, true} {
		raw, peer := net.Pipe()
		var conn net.Conn
		if cached {
			conn = TakeCached(bufio.NewCachedConn(raw, buf.As([]byte("prefix"))))
		} else {
			conn = New(raw, []byte("prefix"))
		}
		go func() { defer peer.Close(); peer.Write([]byte("tail")) }()
		data, err := io.ReadAll(conn)
		require.NoError(t, err)
		require.Equal(t, "prefixtail", string(data))
		conn.Close()
	}
}

func TestConcurrentReadClose(t *testing.T) {
	for _, cached := range []bool{false, true} {
		for iteration := 0; iteration < 64; iteration++ {
			raw, peer := net.Pipe()
			prefix := bytes.Repeat([]byte{0x5a}, 64*1024)
			var conn net.Conn
			if cached {
				conn = TakeCached(bufio.NewCachedConn(raw, buf.As(prefix)))
			} else {
				conn = New(raw, prefix)
			}
			started := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				b := make([]byte, 1)
				conn.Read(b)
				close(started)
				for {
					if _, err := conn.Read(b); err != nil {
						return
					}
					runtime.Gosched()
				}
			}()
			<-started
			conn.Close()
			peer.Close()
			wg.Wait()
		}
	}
}

func TestCloseInterruptsTransportRead(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	conn := New(raw, []byte("x"))
	done := make(chan struct{})
	go func() { defer close(done); io.Copy(io.Discard, conn) }()
	require.NoError(t, conn.Close())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close blocked behind Read")
	}
}
