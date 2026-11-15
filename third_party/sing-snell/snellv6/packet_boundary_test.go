package snellv6

import (
	"bytes"
	"errors"
	"testing"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestPacketReceiveBufferPreservesDatagram(t *testing.T) {
	t.Parallel()

	for _, writer := range []N.PacketWriter{
		&clientPacketConn{client: &Client{mode: ModeUnshaped}},
		&serverPacketConn{service: &Service{mode: ModeUnshaped}},
	} {
		buffer := N.NewReadWaitOptions(nil, writer).NewPacketBuffer()
		capacity := buffer.FreeLen()
		buffer.Release()
		if capacity < 65527 {
			t.Errorf("%T receive capacity is %d, want at least 65527", writer, capacity)
		}
	}
}

func TestPacketAddressPayloadBoundary(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		address   string
		headerLen int
		request   bool
	}{
		{"ipv4-request", "127.0.0.1:53", 9, true},
		{"ipv6-request", "[::1]:53", 21, true},
		{"domain-request", "example.com:53", 15, true},
		{"ipv4-response", "127.0.0.1:53", 7, false},
		{"ipv6-response", "[::1]:53", 19, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var wire bytes.Buffer
			writer := newRawWriter(&wire)
			reader := newRawReader(&wire)
			client := &clientPacketConn{client: &Client{mode: ModeUnsafeRaw}, writer: writer, reader: reader}
			server := &serverPacketConn{service: &Service{mode: ModeUnsafeRaw}, writer: writer, reader: reader}
			var sender N.PacketWriter = server
			var receiver N.PacketReadWaiter = client
			if test.request {
				sender, receiver = client, server
			}
			address := M.ParseSocksaddr(test.address)
			limit := 65535 - test.headerLen
			options := N.NewReadWaitOptions(nil, sender)
			for _, size := range []int{limit + 1, limit} {
				payload := bytes.Repeat([]byte{0x73}, size)
				buffer := options.NewBufferSize(size)
				copy(buffer.Extend(size), payload)
				options.PostReturn(buffer)
				err := sender.WritePacket(buffer, address)
				if size > limit {
					if !errors.Is(err, snell.ErrPayloadTooLarge) || wire.Len() != 0 {
						t.Fatalf("oversized packet: wrote %d bytes, error %v", wire.Len(), err)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				packet, gotAddress, err := receiver.WaitReadPacket()
				if err != nil {
					t.Fatal(err)
				}
				matches := bytes.Equal(packet.Bytes(), payload)
				packet.Release()
				if !matches || gotAddress != address || wire.Len() != 0 {
					t.Fatalf("boundary packet changed: address %v, payload matches %v, %d bytes left", gotAddress, matches, wire.Len())
				}
			}
		})
	}
}

func TestServerPacketBatchResponseBoundary(t *testing.T) {
	t.Parallel()
	for _, mode := range []Mode{ModeDefault, ModeUnshaped, ModeUnsafeRaw} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			for _, address := range []string{"127.0.0.1:53", "[::1]:53"} {
				t.Run(address, func(t *testing.T) {
					t.Parallel()
					var wire bytes.Buffer
					psk := []byte("server-batch-boundary")
					profile := NewProfile(psk)
					writer, err := writeFirstRecord(&wire, mode, psk, profile, []byte{snell.ReplyTunnel})
					if err != nil {
						t.Fatal(err)
					}
					reader, reply, err := readFirstRecord(&wire, mode, psk, profile, N.ReadWaitOptions{})
					if err != nil {
						t.Fatal(err)
					}
					reply.Release()
					server := &serverPacketConn{service: &Service{mode: mode, profile: profile}, writer: writer}
					client := &clientPacketConn{reader: reader}
					batch := &serverPacketBatchWriter{conn: server, upstream: bufio.NewVectorisedWriter(&wire)}
					addr := M.ParseSocksaddr(address)
					limit := maxPayload - server.responseAddrLen(addr)
					options := N.NewReadWaitOptions(nil, server)
					makePacket := func(size int) *buf.Buffer {
						packet := options.NewBufferSize(size)
						copy(packet.Extend(size), bytes.Repeat([]byte{0x73}, size))
						options.PostReturn(packet)
						return packet
					}
					checkPacket := func(size int) {
						t.Helper()
						packet, source, err := client.WaitReadPacket()
						if err != nil {
							t.Fatal(err)
						}
						matches := bytes.Equal(packet.Bytes(), bytes.Repeat([]byte{0x73}, size))
						packet.Release()
						if source != addr || !matches {
							t.Fatalf("response changed: source %v, payload matches %v", source, matches)
						}
					}
					packets := []*buf.Buffer{makePacket(37), makePacket(limit + 1), makePacket(11), makePacket(41)}
					destinations := []M.Socksaddr{addr, addr, M.ParseSocksaddr("example.org:53"), addr}
					if err := batch.WritePacketBatch(packets, destinations); !errors.Is(err, snell.ErrPayloadTooLarge) {
						t.Fatalf("oversized batch error: %v", err)
					}
					checkPacket(37)
					checkPacket(41)
					if wire.Len() != 0 {
						t.Fatalf("invalid responses emitted %d extra bytes", wire.Len())
					}
					if err := batch.WritePacketBatch([]*buf.Buffer{makePacket(limit)}, []M.Socksaddr{addr}); err != nil {
						t.Fatal(err)
					}
					checkPacket(limit)
					if wire.Len() != 0 {
						t.Fatalf("boundary response left %d bytes", wire.Len())
					}
				})
			}
		})
	}
}
