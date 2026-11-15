package hysteria

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestXPlusPacketConnWriteToLength(t *testing.T) {
	t.Parallel()
	peer, sender := newXPlusPacketTestPair(t)
	// Hide the syscall/vector writer to exercise the ordinary PacketConn path.
	plain := struct{ net.PacketConn }{sender}
	wrapped := NewXPlusPacketConn(plain, []byte("test-password"))
	receiver := NewXPlusPacketConn(peer, []byte("test-password"))
	for _, want := range [][]byte{nil, []byte("packet payload")} {
		payload := bytes.Clone(want)
		n, err := wrapped.WriteTo(payload, peer.LocalAddr())
		if n != len(want) || err != nil {
			t.Errorf("WriteTo = (%d, %v), want (%d, nil)", n, err, len(want))
		}
		if !bytes.Equal(payload, want) {
			t.Error("WriteTo modified the slice passed by the caller")
		}
		buffer := make([]byte, 256)
		n, _, err = receiver.ReadFrom(buffer)
		if err != nil || !bytes.Equal(buffer[:n], want) {
			t.Fatalf("ReadFrom = (%q, %v), want (%q, nil)", buffer[:n], err, want)
		}
	}
}

func TestXPlusVectorPacketConnWriteToPreservesPayload(t *testing.T) {
	t.Parallel()
	for _, closed := range []bool{false, true} {
		name := "success"
		if closed {
			name = "closed"
		}
		t.Run(name, func(t *testing.T) {
			peer, sender := newXPlusPacketTestPair(t)
			wrapped := NewXPlusPacketConn(sender, []byte("test-password"))
			receiver := NewXPlusPacketConn(peer, []byte("test-password"))
			if closed {
				if err := sender.Close(); err != nil {
					t.Fatal(err)
				}
			}
			want := bytes.Repeat([]byte("packet payload"), 6)
			payload := bytes.Clone(want)
			for range 2 {
				n, err := wrapped.WriteTo(payload, peer.LocalAddr())
				if !bytes.Equal(payload, want) {
					t.Error("WriteTo modified the slice passed by the caller")
				}
				if closed {
					if n != 0 || err == nil {
						t.Fatalf("closed WriteTo = (%d, %v), want (0, error)", n, err)
					}
					continue
				}
				if n != len(want) || err != nil {
					t.Errorf("WriteTo = (%d, %v), want (%d, nil)", n, err, len(want))
				}
				buffer := make([]byte, 256)
				n, _, err = receiver.ReadFrom(buffer)
				if err != nil || !bytes.Equal(buffer[:n], want) {
					t.Fatalf("ReadFrom = (%q, %v), want (%q, nil)", buffer[:n], err, want)
				}
			}
		})
	}
}

func TestXPlusClientConnWritePreservesPayload(t *testing.T) {
	t.Parallel()
	for _, closed := range []bool{false, true} {
		name := "success"
		if closed {
			name = "closed"
		}
		t.Run(name, func(t *testing.T) {
			peer, client := newXPlusClientTestPair(t)
			wrapped := NewXPlusClientConn(client, []byte("test-password"))
			receiver := NewXPlusPacketConn(peer, []byte("test-password"))
			if closed {
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
			}
			want := bytes.Repeat([]byte("client payload"), 6)
			payload := bytes.Clone(want)
			for range 2 {
				n, err := wrapped.Write(payload)
				if !bytes.Equal(payload, want) {
					t.Error("Write modified the slice passed by the caller")
				}
				if closed {
					if n != 0 || err == nil {
						t.Fatalf("closed Write = (%d, %v), want (0, error)", n, err)
					}
					continue
				}
				if n != len(want) || err != nil {
					t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(want))
				}
				buffer := make([]byte, 256)
				n, _, err = receiver.ReadFrom(buffer)
				if err != nil || !bytes.Equal(buffer[:n], want) {
					t.Fatalf("ReadFrom = (%q, %v), want (%q, nil)", buffer[:n], err, want)
				}
			}
		})
	}
}

func TestXPlusVectorPacketOwnership(t *testing.T) {
	t.Parallel()
	for _, writeErr := range []error{nil, errors.New("write failed")} {
		name := "success"
		if writeErr != nil {
			name = "error"
		}
		t.Run(name, func(t *testing.T) {
			peer, sender := newXPlusPacketTestPair(t)
			downstream := &xplusRetainedPacketConn{PacketConn: sender, err: writeErr}
			t.Cleanup(func() { buf.ReleaseMulti(downstream.buffers) })
			wrapped := NewXPlusPacketConn(downstream, []byte("test-password"))
			writer, ok := wrapped.(N.VectorisedPacketWriter)
			if !ok {
				t.Fatal("vector packet writer unavailable")
			}
			parts := [][]byte{[]byte("prefix-"), nil, bytes.Repeat([]byte("data"), 20)}
			buffers := make([]*buf.Buffer, len(parts))
			for i, part := range parts {
				buffers[i] = buf.NewSize(len(part))
				_, _ = buffers[i].Write(part)
			}
			destination := M.SocksaddrFromNet(peer.LocalAddr())
			if err := writer.WriteVectorisedPacket(buffers, destination); err != writeErr {
				t.Fatalf("WriteVectorisedPacket error = %v, want %v", err, writeErr)
			}
			// Ownership belongs to the downstream writer, including on error.
			// It may finish consuming and release the buffers after returning.
			if len(downstream.buffers) != len(parts)+1 || downstream.buffers[0].Len() != xplusSaltLen {
				t.Fatal("salt buffer released before its downstream owner finished")
			}
			if downstream.destination != destination {
				t.Fatalf("destination = %v, want %v", downstream.destination, destination)
			}
			var wire []byte
			for i, buffer := range downstream.buffers {
				if i > 0 && buffer.Len() != len(parts[i-1]) {
					t.Fatal("payload buffer released before its downstream owner finished")
				}
				wire = append(wire, buffer.Bytes()...)
			}
			if _, err := sender.WriteTo(wire, peer.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			receiver := NewXPlusPacketConn(peer, []byte("test-password"))
			buffer := make([]byte, 256)
			n, _, err := receiver.ReadFrom(buffer)
			want := bytes.Join(parts, nil)
			if err != nil || !bytes.Equal(buffer[:n], want) {
				t.Fatalf("ReadFrom = (%q, %v), want (%q, nil)", buffer[:n], err, want)
			}
		})
	}
}

type xplusRetainedPacketConn struct {
	net.PacketConn
	buffers     []*buf.Buffer
	destination M.Socksaddr
	err         error
}

func (c *xplusRetainedPacketConn) WriteVectorisedPacket(buffers []*buf.Buffer, destination M.Socksaddr) error {
	c.buffers = buffers
	c.destination = destination
	return c.err
}

func newXPlusPacketTestPair(t *testing.T) (net.PacketConn, net.PacketConn) {
	t.Helper()
	conns := make([]net.PacketConn, 2)
	for i := range conns {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if err = conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		conns[i] = conn
	}
	return conns[0], conns[1]
}

func newXPlusClientTestPair(t *testing.T) (net.PacketConn, net.Conn) {
	t.Helper()
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	client, err := net.Dial("udp4", peer.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err = client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	return peer, client
}
