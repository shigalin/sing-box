package snellv4

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestPacketReceiveBufferPreservesDatagram(t *testing.T) {
	t.Parallel()

	c := &clientPacketConn{}
	options := N.NewReadWaitOptions(nil, c)
	b := options.NewPacketBuffer()
	defer b.Release()
	payload := bytes.Repeat([]byte{0x73}, 65507)
	n, err := bytes.NewReader(payload).Read(b.FreeBytes())
	if err != nil || n != len(payload) {
		t.Fatalf("receive buffer truncated datagram: got %d want %d: %v", n, len(payload), err)
	}
}

func TestPacketAddressPayloadBoundary(t *testing.T) {
	t.Parallel()

	for _, destination := range []string{"127.0.0.1:53", "[::1]:53", "example.com:53"} {
		for _, batch := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/batch=%v", destination, batch), func(t *testing.T) {
				t.Parallel()

				var wire bytes.Buffer
				w := &writer{upstream: &wire, psk: []byte("udp-boundary-test-key")}
				r := &reader{upstream: &wire, psk: []byte("udp-boundary-test-key")}
				c := &clientPacketConn{writer: w, reader: &reader{}}
				// Packet connections have exchanged the tunnel request/reply first.
				_, warmErr := w.Write([]byte{1})
				if warmErr != nil {
					t.Fatal(warmErr)
				}
				warmRecord, warmErr := r.ReadRecord()
				if warmErr != nil {
					t.Fatal(warmErr)
				}
				warmRecord.Release()
				addr := M.ParseSocksaddr(destination)
				payloadLimit := maxPayload - (1 + c.udpRequestAddrLen(addr))
				makePacket := func(size int) *buf.Buffer {
					b := buf.NewSize(c.FrontHeadroom() + size + c.RearHeadroom())
					b.Resize(c.FrontHeadroom(), 0)
					b.Write(bytes.Repeat([]byte{0x73}, size))
					return b
				}
				write := func(buffers []*buf.Buffer) error {
					if batch {
						destinations := make([]M.Socksaddr, len(buffers))
						for i := range destinations {
							destinations[i] = addr
						}
						bw := &clientPacketBatchWriter{conn: c, writer: w.CreatePacketVectorisedWriterFor(packetTestVectorWriter{&wire})}
						return bw.WritePacketBatch(buffers, destinations)
					}
					return c.WritePacket(buffers[0], addr)
				}
				// Drop only the oversized datagram; preserve the valid batch prefix.
				invalid := []*buf.Buffer{makePacket(payloadLimit + 1)}
				if batch {
					invalid = append([]*buf.Buffer{makePacket(37)}, invalid...)
				}
				errResult := write(invalid)
				if !errors.Is(errResult, snell.ErrPayloadTooLarge) {
					t.Fatalf("oversized datagram: %v", errResult)
				}
				if batch {
					record, err := r.ReadRecord()
					if err != nil {
						t.Fatalf("valid batch prefix dropped: %v", err)
					}
					wantLen := 37 + 1 + c.udpRequestAddrLen(addr)
					valid := record.Len() == wantLen && bytes.Equal(record.Bytes()[wantLen-37:], bytes.Repeat([]byte{0x73}, 37))
					record.Release()
					if !valid {
						t.Fatal("valid batch prefix changed")
					}
				}
				if wire.Len() != 0 {
					t.Fatalf("oversized datagram emitted %d extra bytes", wire.Len())
				}
				// Dropping one datagram must not break later cipher nonces or writes.
				for _, size := range []int{payloadLimit, 37} {
					if err := write([]*buf.Buffer{makePacket(size)}); err != nil {
						t.Fatal(err)
					}
					record, err := r.ReadRecord()
					if err != nil {
						t.Fatalf("decode after rejection: %v", err)
					}
					wantLen := size + (1 + c.udpRequestAddrLen(addr))
					valid := record.Len() == wantLen && bytes.Equal(record.Bytes()[wantLen-size:], bytes.Repeat([]byte{0x73}, size))
					record.Release()
					if !valid {
						t.Fatalf("datagram boundary/content changed for %d bytes", size)
					}
				}
			})
		}
	}
}
