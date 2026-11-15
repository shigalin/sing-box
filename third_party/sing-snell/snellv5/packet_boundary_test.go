package snellv5

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

func TestPacketReceiveBufferCapacity(t *testing.T) {
	t.Parallel()

	c := &serverPacketConn{}
	options := N.NewReadWaitOptions(nil, c)
	b := options.NewPacketBuffer()
	defer b.Release()
	// Fit the largest IPv4 response and one byte to detect an oversized packet.
	if b.FreeLen() != 16377 || cap(b.FreeBytes()) > 32*1024 {
		t.Fatalf("receive buffer capacity %d, backing capacity %d", b.FreeLen(), cap(b.FreeBytes()))
	}
}

func TestPacketAddressPayloadBoundary(t *testing.T) {
	t.Parallel()

	for _, destination := range []string{"127.0.0.1:53", "[::1]:53"} {
		for _, batch := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/batch=%v", destination, batch), func(t *testing.T) {
				t.Parallel()

				var wire bytes.Buffer
				aead, err := snell.NewAEAD(make([]byte, 32))
				if err != nil {
					t.Fatal(err)
				}
				w, err := newWriter(&wire, aead, make([]byte, snell.NonceLen))
				if err != nil {
					t.Fatal(err)
				}
				r := newReader(&wire, aead, make([]byte, snell.NonceLen))
				c := &serverPacketConn{writer: w}
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
				payloadLimit := maxPayload - c.responseAddrLen(addr)
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
						bw := &serverPacketBatchWriter{conn: c, writer: w.CreatePacketVectorisedWriterFor(packetTestVectorWriter{&wire})}
						return bw.WritePacketBatch(buffers, destinations)
					}
					return c.WritePacket(buffers[0], addr)
				}
				checkRecord := func(size int) {
					t.Helper()
					record, err := r.ReadRecord()
					if err != nil {
						t.Fatalf("decode datagram: %v", err)
					}
					wantLen := size + c.responseAddrLen(addr)
					valid := record.Len() == wantLen && bytes.Equal(record.Bytes()[wantLen-size:], bytes.Repeat([]byte{0x73}, size))
					record.Release()
					if !valid {
						t.Fatalf("datagram boundary/content changed for %d bytes", size)
					}
				}

				// Discard only the oversized datagram, without advancing its cipher nonce.
				invalid := []*buf.Buffer{makePacket(payloadLimit + 1)}
				if batch {
					invalid = []*buf.Buffer{makePacket(37), invalid[0], makePacket(41)}
				}
				errResult := write(invalid)
				if !errors.Is(errResult, snell.ErrPayloadTooLarge) {
					t.Fatalf("oversized datagram: %v", errResult)
				}
				if batch {
					checkRecord(37)
					checkRecord(41)
				}
				if wire.Len() != 0 {
					t.Fatalf("oversized datagram emitted %d extra bytes", wire.Len())
				}
				for _, size := range []int{payloadLimit, 37} {
					if err := write([]*buf.Buffer{makePacket(size)}); err != nil {
						t.Fatal(err)
					}
					checkRecord(size)
				}
			})
		}
	}
}
