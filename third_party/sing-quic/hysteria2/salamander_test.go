package hysteria2

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

func TestSalamanderClientConnShortRead(t *testing.T) {
	t.Parallel()

	peer, client := newSalamanderClientTestPair(t)
	wrapped := NewSalamanderClientConn(client, []byte("test-password"))
	buffer := make([]byte, 256)
	for _, length := range []int{0, 1, salamanderSaltLen - 1, salamanderSaltLen} {
		if _, err := peer.WriteTo(make([]byte, length), client.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		if n, err := wrapped.Read(buffer); n != 0 || err != nil {
			t.Errorf("%d-byte packet: Read = (%d, %v), want (0, nil)", length, n, err)
		}
	}
}

func TestSalamanderClientConnWritePreservesPayload(t *testing.T) {
	t.Parallel()
	for _, closed := range []bool{false, true} {
		name := "success"
		if closed {
			name = "closed"
		}
		t.Run(name, func(t *testing.T) {
			peer, client := newSalamanderClientTestPair(t)
			wrapped := NewSalamanderClientConn(client, []byte("test-password"))
			receiver := NewSalamanderConn(peer, []byte("test-password"))
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

func TestSalamanderVectorPacketOwnership(t *testing.T) {
	t.Parallel()
	for _, writeErr := range []error{nil, errors.New("write failed")} {
		name := "success"
		if writeErr != nil {
			name = "error"
		}
		t.Run(name, func(t *testing.T) {
			peer, client := newSalamanderClientTestPair(t)
			downstream := &salamanderRetainedPacketConn{PacketConn: peer, err: writeErr}
			t.Cleanup(func() { buf.ReleaseMulti(downstream.buffers) })
			wrapped := NewSalamanderConn(downstream, []byte("test-password"))
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
			destination := M.SocksaddrFromNet(client.LocalAddr())
			if err := writer.WriteVectorisedPacket(buffers, destination); err != writeErr {
				t.Fatalf("WriteVectorisedPacket error = %v, want %v", err, writeErr)
			}
			// Ownership belongs to the downstream writer, including on error.
			// It may finish consuming and release the buffers after returning.
			if len(downstream.buffers) != len(parts)+1 || downstream.buffers[0].Len() != salamanderSaltLen {
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
			if _, err := peer.WriteTo(wire, client.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			receiver := NewSalamanderClientConn(client, []byte("test-password"))
			buffer := make([]byte, 256)
			n, err := receiver.Read(buffer)
			want := bytes.Join(parts, nil)
			if err != nil || !bytes.Equal(buffer[:n], want) {
				t.Fatalf("Read = (%q, %v), want (%q, nil)", buffer[:n], err, want)
			}
		})
	}
}

type salamanderRetainedPacketConn struct {
	net.PacketConn
	buffers     []*buf.Buffer
	destination M.Socksaddr
	err         error
}

func (c *salamanderRetainedPacketConn) WriteVectorisedPacket(buffers []*buf.Buffer, destination M.Socksaddr) error {
	c.buffers = buffers
	c.destination = destination
	return c.err
}

func newSalamanderClientTestPair(t *testing.T) (net.PacketConn, net.Conn) {
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

func TestSalamanderPacketConn(t *testing.T) {
	t.Parallel()

	sender, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	if err = receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	password := []byte("test-password")
	wrappedSender := NewSalamanderConn(sender, password)
	wrappedReceiver := NewSalamanderConn(receiver, password)
	want := []byte("connection close")
	payload := bytes.Clone(want)
	buffer := make([]byte, 256)
	for range 2 {
		n, writeErr := wrappedSender.WriteTo(payload, receiver.LocalAddr())
		if writeErr != nil || n != len(want) {
			t.Fatalf("write got %d bytes and error %v", n, writeErr)
		}
		if !bytes.Equal(payload, want) {
			t.Fatal("WriteTo modified the packet passed by the caller")
		}
		n, _, readErr := wrappedReceiver.ReadFrom(buffer)
		if readErr != nil || !bytes.Equal(buffer[:n], want) {
			t.Fatalf("read got %q and error %v", buffer[:n], readErr)
		}
	}

	for _, length := range []int{0, 1, salamanderSaltLen - 1, salamanderSaltLen} {
		if _, err = sender.WriteTo(make([]byte, length), receiver.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		if n, addr, readErr := wrappedReceiver.ReadFrom(buffer); readErr != nil || n != 0 || addr == nil || addr.String() != sender.LocalAddr().String() {
			t.Fatalf("%d-byte packet got (%d, %v, %v), want (0, %v, nil)", length, n, addr, readErr, sender.LocalAddr())
		}
	}
}
