package snellv5

import (
	"bytes"
	"context"
	"errors"
	snell "github.com/sagernet/sing-snell"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/sagernet/sing-snell/internal/eof"
	"github.com/sagernet/sing-snell/internal/reuse"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type boundaryTunnel struct{ reuseCloseTunnel }

func (*boundaryTunnel) Write(p []byte) (int, error) { return len(p), nil }

type failedRecordReader struct {
	reuse.RecordReader
	err error
}

func (r failedRecordReader) Read([]byte) (int, error)             { return 0, r.err }
func (r failedRecordReader) ReadBuffer(*buf.Buffer) error         { return r.err }
func (r failedRecordReader) WaitReadBuffer() (*buf.Buffer, error) { return nil, r.err }

func TestServerReuseCloseAfterReadFailure(t *testing.T) {
	for _, failure := range []error{io.ErrUnexpectedEOF, errors.New("invalid record authentication")} {
		for _, method := range []string{"Read", "ReadBuffer", "WaitReadBuffer"} {
			t.Run(failure.Error()+"/"+method, func(t *testing.T) {
				tunnel := &boundaryTunnel{reuseCloseTunnel: reuseCloseTunnel{closed: make(chan struct{})}}
				conn := &serverReuseConn[struct{}]{Conn: tunnel, session: &serverReuseSession[struct{}]{Conn: tunnel, transport: &eof.TrackingReader{}, reader: failedRecordReader{err: failure}}, replyWritten: true, writeClosed: true, completion: make(chan struct{})}
				var err error
				switch method {
				case "Read":
					_, err = conn.Read(make([]byte, 1))
				case "ReadBuffer":
					b := buf.New()
					defer b.Release()
					err = conn.ReadBuffer(b)
				case "WaitReadBuffer":
					_, err = conn.WaitReadBuffer()
				}
				if err != failure {
					t.Fatalf("read error = %v", err)
				}
				conn.completeLogicalConnection(err)
				if err := conn.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-tunnel.closed:
				default:
					t.Fatal("failed read after response EOF left tunnel open for drain")
				}
				if !conn.aborted.Load() {
					t.Fatal("failed stream remains reusable")
				}
			})
		}
	}
}

func TestServerReuseConcurrentMetadata(t *testing.T) {
	for _, action := range []string{"Write", "Close"} {
		t.Run(action, func(t *testing.T) {
			service := &Service{psk: []byte("metadata-regression")}
			tunnel := &boundaryTunnel{reuseCloseTunnel: reuseCloseTunnel{closed: make(chan struct{})}}
			conn := &serverReuseConn[struct{}]{Conn: tunnel, session: &serverReuseSession[struct{}]{Conn: tunnel, service: service, transport: &eof.TrackingReader{}}, completion: make(chan struct{})}
			start := make(chan struct{})
			var workers sync.WaitGroup
			for i := 0; i < 4; i++ {
				workers.Add(1)
				go func() {
					defer workers.Done()
					<-start
					for j := 0; j < 1000; j++ {
						conn.FrontHeadroom()
						conn.RearHeadroom()
						conn.WriterMTU()
					}
				}()
			}
			close(start)
			var err error
			if action == "Write" {
				_, err = conn.Write([]byte("reply"))
			} else {
				err = conn.Close()
			}
			workers.Wait()
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
		})
	}
}

type finalRecordReader struct{ data []byte }

func (r *finalRecordReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}
func TestServerReuseFinalZeroChunk(t *testing.T) {
	var wire bytes.Buffer
	aead, err := snell.NewAEAD(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	writer, err := newWriter(&wire, aead, make([]byte, snell.NonceLen))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write([]byte{snell.CommandConnectV2}); err != nil {
		t.Fatal(err)
	}
	if err = writer.WriteZeroChunk(); err != nil {
		t.Fatal(err)
	}
	tracker := &eof.TrackingReader{Reader: &finalRecordReader{data: wire.Bytes()}}
	reader := newReader(tracker, aead, make([]byte, snell.NonceLen))
	record, err := reader.ReadRecord()

	if err != nil {
		t.Fatal(err)
	}
	record.Release()
	conn := &serverReuseConn[struct{}]{session: &serverReuseSession[struct{}]{reader: reader, transport: tracker}}
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("valid final zero chunk: %v", err)
	}
	if !conn.readClosed.Load() || tracker.Reached() {
		t.Fatal("protocol EOF was mistaken for transport truncation")
	}
}

func TestServerConcurrentFirstWritesAndMetadata(t *testing.T) {
	service := &Service{psk: []byte("nonreuse-concurrent")}
	conn := &serverConn{Conn: &boundaryTunnel{reuseCloseTunnel: reuseCloseTunnel{closed: make(chan struct{})}}, service: service}
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

// A downstream write failure can leave a healthy upload to drain. Its protocol
// zero chunk permits reuse; a transport EOF must instead reject that stream.
type drainHandler struct {
	snell.Handler
	t *testing.T
}

func (h drainHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	if _, err := conn.Write([]byte("response")); err != nil {
		h.t.Fatal(err)
	}
	if err := conn.(N.WriteCloser).CloseWrite(); err != nil {
		h.t.Fatal(err)
	}
	onClose(io.ErrClosedPipe)
}

type drainRecordReader struct {
	reuse.RecordReader
	tracker           *eof.TrackingReader
	transportEOF      bool
	drained, requests int
}

func (r *drainRecordReader) NextRecord() (*buf.Buffer, error) {
	r.drained++
	if r.drained == 1 {
		return buf.As([]byte("remaining upload")), nil
	}
	if r.transportEOF {
		_, err := r.tracker.Read(make([]byte, 1))
		return nil, err
	}
	return nil, io.EOF
}
func (r *drainRecordReader) ReadRecord() (*buf.Buffer, error) {
	r.requests++
	if r.transportEOF {
		return nil, io.EOF
	}
	return buf.As([]byte{snell.RequestVersion, snell.CommandPing, 0}), nil
}
func TestServerReuseDrainDistinguishesTransportEOF(t *testing.T) {
	for _, transportEOF := range []bool{false, true} {
		name := "protocol EOF permits next request"
		if transportEOF {
			name = "transport EOF rejects drain"
		}
		t.Run(name, func(t *testing.T) {
			service := &Service{psk: []byte("drain-regression"), handler: drainHandler{t: t}}
			tunnel := &boundaryTunnel{reuseCloseTunnel: reuseCloseTunnel{closed: make(chan struct{})}}
			tracker := &eof.TrackingReader{Reader: bytes.NewReader(nil)}
			reader := &drainRecordReader{tracker: tracker, transportEOF: transportEOF}
			session := &serverReuseSession[struct{}]{Conn: tunnel, service: service, transport: tracker, reader: reader}
			err := session.Serve(context.Background(), M.Socksaddr{}, nil, buf.New(), snell.Request{Command: snell.CommandConnectV2})
			if transportEOF {
				if !errors.Is(err, io.ErrUnexpectedEOF) || reader.requests != 0 {
					t.Fatalf("truncated drain: err=%v next requests=%d", err, reader.requests)
				}
			} else if err != nil || reader.requests != 1 {
				t.Fatalf("healthy drain: err=%v next requests=%d", err, reader.requests)
			}
			if reader.drained != 2 {
				t.Fatalf("remaining upload was not drained: %d reads", reader.drained)
			}
			select {
			case <-tunnel.closed:
			default:
				t.Fatal("terminal tunnel was not closed")
			}
		})
	}
}
