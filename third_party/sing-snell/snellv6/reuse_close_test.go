package snellv6

import (
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"

	"github.com/sagernet/sing-snell/internal/eof"
	"github.com/sagernet/sing-snell/internal/reuse"
)

// onClose wakes Serve before the handler calls Close. Serve may still be
// finishing the response EOF when that second Close arrives.
func TestServerReuseCloseAfterCompletion(t *testing.T) { //nolint:paralleltest // Controls scheduling of the two close callers.
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)

	tunnel := &reuseCloseTunnel{closed: make(chan struct{})}
	writer := &reuseCloseWriter{entered: make(chan struct{}), resume: make(chan struct{})}
	conn := &serverReuseConn[struct{}]{
		Conn:         tunnel,
		session:      &serverReuseSession[struct{}]{Conn: tunnel, writer: writer, transport: &eof.TrackingReader{}},
		replyWritten: true,
		completion:   make(chan struct{}),
	}
	conn.completeLogicalConnection(nil)
	writeDone := make(chan error, 1)
	go func() { writeDone <- conn.CloseWrite() }()
	<-writer.entered
	closeDone := make(chan error, 2)
	go func() { closeDone <- conn.Close() }()
	go func() { closeDone <- conn.Close() }()
	runtime.Gosched()
	select {
	case <-tunnel.closed:
		t.Error("normal completion closed the reusable tunnel while CloseWrite held the lock")
	default:
	}
	close(writer.resume)
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := <-closeDone; err != nil {
			t.Fatal(err)
		}
	}
	if conn.aborted.Load() {
		t.Fatal("normal completion was marked aborted")
	}
	if writer.count != 1 {
		t.Fatalf("wrote %d EOF records, want one", writer.count)
	}
}

// The first Close, not a separate CloseWrite, owns final EOF emission.
func TestServerReuseConcurrentCloseAfterCompletion(t *testing.T) { //nolint:paralleltest // Controls scheduling of close callers.
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	for _, writeErr := range []error{nil, errors.New("EOF write failed")} {
		tunnel := &reuseCloseTunnel{closed: make(chan struct{})}
		writer := &reuseCloseWriter{entered: make(chan struct{}), resume: make(chan struct{}), err: writeErr}
		conn := &serverReuseConn[struct{}]{
			Conn:         tunnel,
			session:      &serverReuseSession[struct{}]{Conn: tunnel, writer: writer, transport: &eof.TrackingReader{}},
			replyWritten: true,
			completion:   make(chan struct{}),
		}
		conn.completeLogicalConnection(nil)
		done := make(chan error, 2)
		go func() { done <- conn.Close() }()
		<-writer.entered
		go func() { done <- conn.Close() }()
		runtime.Gosched()
		select {
		case <-tunnel.closed:
			t.Error("second Close interrupted the final EOF")
		default:
		}
		close(writer.resume)
		for i := 0; i < 2; i++ {
			if err := <-done; err != writeErr {
				t.Fatalf("Close returned %v, want %v", err, writeErr)
			}
		}
		if writer.count != 1 || conn.aborted.Load() {
			t.Fatalf("final EOF count=%d aborted=%v", writer.count, conn.aborted.Load())
		}
	}
}

// Without completion, Close must still interrupt a blocked write rather than
// wait forever for the write mutex.
func TestServerReuseCloseInterruptsBlockedWrite(t *testing.T) {
	for _, failed := range []bool{false, true} {
		tunnel := &reuseCloseTunnel{closed: make(chan struct{})}
		writer := &reuseCloseWriter{entered: make(chan struct{}), closed: tunnel.closed}
		conn := &serverReuseConn[struct{}]{
			Conn:         tunnel,
			session:      &serverReuseSession[struct{}]{Conn: tunnel, writer: writer, transport: &eof.TrackingReader{}},
			replyWritten: true,
			completion:   make(chan struct{}),
		}
		writeDone := make(chan error, 1)
		go func() { _, err := conn.Write([]byte("blocked")); writeDone <- err }()
		<-writer.entered
		if failed {
			conn.completeLogicalConnection(net.ErrClosed)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-writeDone; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked write returned %v, want closed", err)
		}
		if !conn.aborted.Load() {
			t.Fatal("interrupted session was not marked aborted")
		}
	}
}

type reuseCloseTunnel struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *reuseCloseTunnel) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

type reuseCloseWriter struct {
	reuse.RecordWriter
	entered chan struct{}
	resume  chan struct{}
	closed  <-chan struct{}
	count   int
	err     error
}

func (w *reuseCloseWriter) WriteZeroChunk() error {
	w.count++
	close(w.entered)
	<-w.resume
	return w.err
}

func (w *reuseCloseWriter) Write([]byte) (int, error) {
	close(w.entered)
	<-w.closed
	return 0, net.ErrClosed
}
