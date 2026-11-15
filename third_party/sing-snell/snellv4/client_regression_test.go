package snellv4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/internal/reuse"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestEmptyWriteDoesNotEndStream(t *testing.T) {
	var wire bytes.Buffer
	w := &writer{upstream: &wire, psk: []byte("empty-write-key")}
	if n, err := w.Write(nil); n != 0 || err != nil || wire.Len() != 0 {
		t.Fatalf("empty write emitted %d bytes: n=%d err=%v", wire.Len(), n, err)
	}
	if _, err := w.Write([]byte("still open")); err != nil {
		t.Fatal(err)
	}
	r := &reader{upstream: &wire, psk: w.psk}
	record, err := r.ReadRecord()
	if err != nil {
		t.Fatal(err)
	}
	defer record.Release()
	if string(record.Bytes()) != "still open" {
		t.Fatalf("payload: %q", record.Bytes())
	}
}

type regressionConn struct {
	net.Conn
	input    io.Reader
	output   bytes.Buffer
	deadline time.Time
}

func (c *regressionConn) Read(p []byte) (int, error) { return c.input.Read(p) }
func (c *regressionConn) Write(p []byte) (int, error) {
	if !c.deadline.IsZero() && !time.Now().Before(c.deadline) {
		return 0, &net.OpError{Op: "write", Err: deadlineError{}}
	}
	return c.output.Write(p)
}
func (*regressionConn) Close() error                         { return nil }
func (*regressionConn) SetReadDeadline(time.Time) error      { return nil }
func (c *regressionConn) SetWriteDeadline(d time.Time) error { c.deadline = d; return nil }

type deadlineError struct{}

func (deadlineError) Error() string   { return "deadline exceeded" }
func (deadlineError) Timeout() bool   { return true }
func (deadlineError) Temporary() bool { return true }

func TestClientTransportEOFAfterPayloadIsUnexpected(t *testing.T) {
	for _, reused := range []bool{false, true} {
		var wire bytes.Buffer
		psk := []byte("reply-without-zero-chunk")
		writer := &writer{upstream: &wire, psk: psk}
		if _, err := writer.Write(append([]byte{snell.ReplyTunnel}, []byte("body")...)); err != nil {
			t.Fatal(err)
		}
		client, err := NewClient(ClientOptions{PSK: psk, Reuse: reused})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		transport := &regressionConn{input: bytes.NewReader(wire.Bytes())}
		destination := M.ParseSocksaddr("example.com:443")
		var conn net.Conn = client.DialEarlyConn(transport, destination)
		if reused {
			session := client.newReuseSession(transport)
			session.state.Store(uint32(reuse.StateActive))
			conn, err = session.DialConn(destination)
			if err != nil {
				t.Fatal(err)
			}
		}
		payload := make([]byte, 4)
		if _, err := io.ReadFull(conn, payload); err != nil || string(payload) != "body" {
			t.Fatalf("reused=%v: payload %q, error %v", reused, payload, err)
		}
		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			t.Fatalf("reused=%v: transport EOF after payload was treated as %v", reused, err)
		}
	}
}

func TestClientTruncatedReplyIsUnexpectedEOF(t *testing.T) {
	client, err := NewClient(ClientOptions{PSK: []byte("truncated-reply-key")})
	if err != nil {
		t.Fatal(err)
	}
	conn := client.DialEarlyConn(&regressionConn{input: bytes.NewReader(nil)}, M.ParseSocksaddr("example.com:443"))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v, want unexpected EOF", err)
	}
}

type closeNotifyingConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *closeNotifyingConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func TestReuseSkipsDeadIdleSession(t *testing.T) {
	client, _ := NewClient(ClientOptions{PSK: []byte("idle-probe-key"), Reuse: true})
	defer client.Close()
	local, peer := net.Pipe()
	transport := &closeNotifyingConn{Conn: local, closed: make(chan struct{})}
	session := client.newReuseSession(transport)
	session.state.Store(uint32(reuse.StateActive))
	session.Release(true)
	peer.Close()
	select {
	case <-transport.closed:
	case <-time.After(time.Second):
		t.Fatal("idle peer EOF did not evict and close the session")
	}
	if _, found, _ := client.pool.Take(); found {
		t.Fatal("pool returned dead idle session")
	}
}

func TestReuseRejectsWritesAfterCloseWrite(t *testing.T) {
	client, _ := NewClient(ClientOptions{PSK: []byte("closed-write-key"), Reuse: true})
	defer client.Close()
	transport := &regressionConn{input: bytes.NewReader(nil)}
	session := client.newReuseSession(transport)
	session.state.Store(1)
	connection, err := session.DialConn(M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	conn := connection.(*reuseConn)
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	before := transport.output.Len()
	if n, err := conn.Write([]byte("late")); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Errorf("Write after EOF: %d, %v", n, err)
	}
	options := N.NewReadWaitOptions(nil, conn)
	buffer := options.NewBufferSize(4)
	buffer.WriteString("late")
	options.PostReturn(buffer)
	if err := conn.WriteBuffer(buffer); !errors.Is(err, net.ErrClosed) {
		t.Errorf("WriteBuffer after EOF: %v", err)
	}
	buffer = options.NewBufferSize(4)
	buffer.WriteString("late")
	options.PostReturn(buffer)
	if err := (&reuseVectorisedWriter{conn: conn, upstream: bufio.NewVectorisedWriter(transport)}).WriteVectorised([]*buf.Buffer{buffer}); !errors.Is(err, net.ErrClosed) {
		t.Errorf("vector write after EOF: %v", err)
	}
	if transport.output.Len() != before {
		t.Errorf("late writes emitted %d bytes", transport.output.Len()-before)
	}
}

func TestReuseServerEOFIsSticky(t *testing.T) {
	for _, method := range []string{"read", "buffer", "waiter"} {
		t.Run(method, func(t *testing.T) {
			var wire bytes.Buffer
			psk := []byte("sticky-eof-key")
			w := &writer{upstream: &wire, psk: psk}
			if _, err := w.Write([]byte{snell.ReplyTunnel}); err != nil {
				t.Fatal(err)
			}
			client, _ := NewClient(ClientOptions{PSK: psk, Reuse: true})
			defer client.Close()
			reply := bytes.Clone(wire.Bytes())
			wire.Reset()
			if err := w.WriteZeroChunk(); err != nil {
				t.Fatal(err)
			}
			zero := bytes.Clone(wire.Bytes())
			wire.Reset()
			if _, err := w.Write([]byte("next")); err != nil {
				t.Fatal(err)
			}
			transport := &regressionConn{input: io.MultiReader(bytes.NewReader(reply), bytes.NewReader(zero), bytes.NewReader(wire.Bytes()))}
			session := client.newReuseSession(transport)
			session.state.Store(1)
			connection, err := session.DialConn(M.ParseSocksaddr("example.com:443"))
			if err != nil {
				t.Fatal(err)
			}
			conn := connection.(*reuseConn)
			if _, err := conn.Read(make([]byte, 4)); !errors.Is(err, io.EOF) {
				t.Fatalf("first EOF: %v", err)
			}
			switch method {
			case "read":
				n, err := conn.Read(make([]byte, 4))
				if n != 0 || !errors.Is(err, io.EOF) {
					t.Fatalf("read crossed EOF: n=%d err=%v", n, err)
				}
			case "buffer":
				b := buf.New()
				defer b.Release()
				if err := conn.ReadBuffer(b); !errors.Is(err, io.EOF) || b.Len() != 0 {
					t.Fatalf("buffer crossed EOF: len=%d err=%v", b.Len(), err)
				}
			case "waiter":
				waiter, _ := conn.CreateReadWaiter()
				b, err := waiter.WaitReadBuffer()
				if b != nil {
					b.Release()
				}
				if b != nil || !errors.Is(err, io.EOF) {
					t.Fatalf("waiter crossed EOF: buffer=%v err=%v", b, err)
				}
			}
		})
	}
}

func TestReuseCloseClearsExpiredWriteDeadline(t *testing.T) {
	var wire bytes.Buffer
	psk := []byte("closing-deadline-key")
	w := &writer{upstream: &wire, psk: psk}
	if _, err := w.Write([]byte{snell.ReplyTunnel}); err != nil {
		t.Fatal(err)
	}
	client, _ := NewClient(ClientOptions{PSK: psk, Reuse: true})
	defer client.Close()
	reply := bytes.Clone(wire.Bytes())
	wire.Reset()
	if err := w.WriteZeroChunk(); err != nil {
		t.Fatal(err)
	}
	transport := &regressionConn{input: io.MultiReader(bytes.NewReader(reply), bytes.NewReader(wire.Bytes()))}
	session := client.newReuseSession(transport)
	session.state.Store(uint32(reuse.StateActive))
	connection, err := session.DialConn(M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	conn := connection.(*reuseConn)
	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("reply EOF: %v", err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("closing zero chunk used stale deadline: %v", err)
	}
}

func TestReuseCloseInterruptsBlockedWrite(t *testing.T) {
	client, _ := NewClient(ClientOptions{PSK: []byte("blocked-write-key"), Reuse: true})
	defer client.Close()
	local, peer := net.Pipe()
	defer peer.Close()
	session := client.newReuseSession(local)
	session.state.Store(uint32(reuse.StateActive))
	connection, err := session.DialConn(M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	conn := connection.(*reuseConn)
	writeDone := make(chan error, 1)
	go func() { _, err := conn.Write([]byte("blocked")); writeDone <- err }()
	// Reading one wire byte proves the write is inside the transport, not
	// merely racing to acquire the logical connection lock.
	if _, err := peer.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- conn.Close() }()
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Close waited for blocked write")
	}
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("blocked write succeeded on aborted session")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked write was not interrupted")
	}
	if _, err := conn.Write([]byte("late")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after Close: %v", err)
	}
}

type singleConnDialer struct {
	N.Dialer
	conn  net.Conn
	calls atomic.Int32
}

func (d *singleConnDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	if d.calls.Add(1) != 1 {
		return nil, errors.New("unexpected fresh transport instead of reuse")
	}
	return d.conn, nil
}

func TestReuseKeepSessionIsOneLogicalConnection(t *testing.T) {
	for _, closeIdleInitially := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear-inherited-flag", true: "keep-while-draining"}[closeIdleInitially], func(t *testing.T) {
			local, peer := net.Pipe()
			defer peer.Close()
			dialer := &singleConnDialer{conn: local}
			client, _ := NewClient(ClientOptions{PSK: []byte("keep-session-key"), Reuse: true, Dialer: dialer})
			defer client.Close()
			client.SetKeepIdleConnections(!closeIdleInitially)
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				r := &reader{upstream: peer, psk: client.psk}
				w := &writer{upstream: peer, psk: client.psk}
				for i := 0; i < 2; i++ {
					record, err := r.ReadRecord()
					if err != nil {
						return
					}
					record.Release()
					_, err = w.Write([]byte{snell.ReplyTunnel, 'x'})
					if err != nil {
						return
					}
					for {
						record, err = r.NextRecord()
						if record != nil {
							record.Release()
						}
						if err != nil {
							break
						}
					}
					if !errors.Is(err, io.EOF) {
						return
					}
					if err := w.WriteZeroChunk(); err != nil {
						return
					}
				}
			}()
			destination := M.ParseSocksaddr("example.com:443")
			connection, err := client.DialContext(snell.ContextWithKeepSession(context.Background()), destination)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := connection.Write([]byte("first")); err != nil {
				t.Fatal(err)
			}
			if _, err := connection.Read(make([]byte, 1)); err != nil {
				t.Fatal(err)
			}
			if err := connection.Close(); err != nil {
				t.Fatal(err)
			}
			session := connection.(*reuseConn).session
			deadline := time.Now().Add(time.Second)
			for reuse.State(session.state.Load()) != reuse.StateReady {
				if reuse.State(session.state.Load()) == reuse.StateClosed {
					t.Fatal("KeepSession was consumed twice while draining")
				}
				if time.Now().After(deadline) {
					t.Fatal("session never returned to ready")
				}
				runtime.Gosched()
			}
			connection, err = client.DialContext(context.Background(), destination)
			if err != nil {
				t.Fatal(err)
			}
			client.SetKeepIdleConnections(false)
			if _, err := connection.Write([]byte("second")); err != nil {
				t.Fatal(err)
			}
			if _, err := connection.Read(make([]byte, 1)); err != nil {
				t.Fatal(err)
			}
			if err := connection.Close(); err != nil {
				t.Fatal(err)
			}
			if reuse.State(session.state.Load()) != reuse.StateClosed {
				t.Fatal("second logical connection inherited KeepSession")
			}
			select {
			case <-serverDone:
			case <-time.After(time.Second):
				t.Fatal("server did not exit after transport close")
			}
		})
	}
}

func TestReuseConcurrentFirstWriteMetadata(t *testing.T) {
	client, _ := NewClient(ClientOptions{PSK: []byte("concurrent-metadata-key"), Reuse: true})
	defer client.Close()
	transport := &regressionConn{input: bytes.NewReader(nil)}
	session := client.newReuseSession(transport)
	session.state.Store(uint32(reuse.StateActive))
	connection, err := session.DialConn(M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	conn := connection.(*reuseConn)
	var workers sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for j := 0; j < 100; j++ {
				conn.FrontHeadroom()
				conn.RearHeadroom()
				conn.WriterMTU()
				conn.NeedHandshakeForWrite()
			}
		}()
	}
	close(start)
	if _, err := conn.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
}

func TestRecordTruncatedPaddingAndBodyAreUnexpectedEOF(t *testing.T) {
	var wire bytes.Buffer
	psk := []byte("truncated-record-key")
	payload := []byte{snell.ReplyTunnel, 'x'}
	w := &writer{upstream: &wire, psk: psk}
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	encoded := wire.Bytes()
	for _, end := range []int{snell.SaltLen + snell.HeaderCipherLen, len(encoded) - len(payload) - snell.AEADTagLen} {
		r := &reader{upstream: bytes.NewReader(encoded[:end]), psk: psk}
		if record, err := r.ReadRecord(); !errors.Is(err, io.ErrUnexpectedEOF) {
			if record != nil {
				record.Release()
			}
			t.Fatalf("truncated at %d: %v", end, err)
		}
	}
}

// Block errors.Is exactly after the old implementation's closed check.
// Close must not lose this EOF while deciding who owns the next read.
type handoffEOF struct {
	entered, resume chan struct{}
	once            sync.Once
}

func (*handoffEOF) Error() string { return "gated EOF" }
func (e *handoffEOF) Is(target error) bool {
	if target != io.EOF {
		return false
	}
	e.once.Do(func() { close(e.entered); <-e.resume })
	return true
}

type handoffReader struct{ err error }

func (r handoffReader) Read([]byte) (int, error) { return 0, r.err }

type handoffTransport struct {
	net.Conn
	closed      chan struct{}
	closing     chan struct{}
	once        sync.Once
	closingOnce sync.Once
}

func (c *handoffTransport) Read([]byte) (int, error)      { <-c.closed; return 0, net.ErrClosed }
func (c *handoffTransport) Close() error                  { c.once.Do(func() { close(c.closed) }); return nil }
func (*handoffTransport) SetReadDeadline(time.Time) error { return nil }
func (c *handoffTransport) SetWriteDeadline(time.Time) error {
	c.closingOnce.Do(func() { close(c.closing) })
	return nil
}

func TestReuseEOFConcurrentCloseHandoff(t *testing.T) {
	for _, method := range []string{"Read", "ReadBuffer", "WaitReadBuffer"} {
		t.Run(method, func(t *testing.T) {
			client, _ := NewClient(ClientOptions{PSK: []byte("eof-handoff"), Reuse: true})
			defer client.Close()
			transport := &handoffTransport{closed: make(chan struct{}), closing: make(chan struct{})}
			defer transport.Close()
			session := client.newReuseSession(transport)
			session.state.Store(uint32(reuse.StateActive))
			gate := &handoffEOF{entered: make(chan struct{}), resume: make(chan struct{})}
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(gate.resume) }) }
			defer release()
			waitSignal := func(signal <-chan struct{}, label string) {
				t.Helper()
				select {
				case <-signal:
				case <-time.After(time.Second):
					t.Fatalf("timed out waiting for %s", label)
				}
			}
			waitResult := func(result <-chan error, label string) error {
				t.Helper()
				select {
				case err := <-result:
					return err
				case <-time.After(time.Second):
					t.Fatalf("timed out waiting for %s", label)
					return nil
				}
			}
			session.reader = &reader{upstream: handoffReader{err: gate}, psk: client.psk}
			conn := &reuseConn{session: session, writeClosed: true}
			conn.replyRead.Store(true)
			readDone := make(chan error, 1)
			go func() {
				var err error
				switch method {
				case "Read":
					_, err = conn.Read(make([]byte, 1))
				case "ReadBuffer":
					b := buf.New()
					defer b.Release()
					err = conn.ReadBuffer(b)
				case "WaitReadBuffer":
					_, err = (&reuseReadWaiter{conn: conn}).WaitReadBuffer()
				}
				readDone <- err
			}()
			waitSignal(gate.entered, "reader EOF")
			closeDone := make(chan error, 1)
			go func() { closeDone <- conn.Close() }()
			waitSignal(transport.closing, "Close deadline reset")
			// In the broken implementation Close completes while EOF is undecided.
			// A synchronized Close waits until the read result has been committed.
			timer := time.NewTimer(50 * time.Millisecond)
			var closed bool
			select {
			case err := <-closeDone:
				if err != nil {
					t.Error(err)
				}
				closed = true
			case <-timer.C:
			}
			timer.Stop()
			release()
			if err := waitResult(readDone, "reader completion"); !errors.Is(err, io.EOF) {
				t.Fatalf("read = %v", err)
			}
			if !closed {
				if err := waitResult(closeDone, "Close completion"); err != nil {
					t.Fatal(err)
				}
			}
			pooled, found, _ := client.pool.Take()
			if !found || pooled != session {
				t.Fatalf("EOF left session unavailable, state=%v", reuse.State(session.state.Load()))
			}
			pooled.Close()
		})
	}
}

func TestClientConcurrentFirstWritesAndMetadata(t *testing.T) {
	client, _ := NewClient(ClientOptions{PSK: []byte("nonreuse-concurrent")})
	defer client.Close()
	conn := client.DialEarlyConn(&regressionConn{input: bytes.NewReader(nil)}, M.ParseSocksaddr("example.com:443")).(*clientConn)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for j := 0; j < 100; j++ {
				conn.FrontHeadroom()
				conn.RearHeadroom()
				conn.WriterMTU()
				conn.NeedHandshakeForWrite()
				if _, err := conn.Write([]byte("data")); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	close(start)
	workers.Wait()
}
