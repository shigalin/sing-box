package snellv6

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

func TestPacketRecordsPreserveLargeDatagrams(t *testing.T) {
	t.Parallel()

	for _, mode := range []Mode{ModeDefault, ModeUnshaped, ModeUnsafeRaw} {
		for _, batch := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/batch=%v", mode, batch), func(t *testing.T) {
				t.Parallel()

				var wire bytes.Buffer
				psk := []byte("udp-record-test-key")
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
				options := N.NewReadWaitOptions(nil, writer)
				makePacket := func(size int) *buf.Buffer {
					buffer := options.NewBufferSize(size)
					copy(buffer.Extend(size), bytes.Repeat([]byte{0x73}, size))
					options.PostReturn(buffer)
					return buffer
				}
				write := func(buffers ...*buf.Buffer) error {
					if batch {
						return writer.CreatePacketVectorisedWriterFor(bufio.NewVectorisedWriter(&wire)).WriteVectorised(buffers)
					}
					return writer.WritePacketBuffer(buffers[0])
				}
				invalid := []*buf.Buffer{makePacket(65536)}
				if batch {
					invalid = append([]*buf.Buffer{makePacket(37)}, invalid...)
				}
				if err := write(invalid...); !errors.Is(err, snell.ErrPayloadTooLarge) || wire.Len() != 0 {
					t.Fatalf("oversized packet: wrote %d bytes, error %v", wire.Len(), err)
				}
				for _, idle := range []bool{false, true} {
					if shaped, ok := writer.(*shapedWriter); idle && ok {
						shaped.lastWriteUnix = time.Now().Unix() - int64(shaped.profile.idleResetSec) - 1
					}
					if err := write(makePacket(65535)); err != nil {
						t.Fatal(err)
					}
					record, err := reader.NextRecord()
					if err != nil {
						t.Fatal(err)
					}
					matches := bytes.Equal(record.Bytes(), bytes.Repeat([]byte{0x73}, 65535))
					record.Release()
					if !matches || wire.Len() != 0 {
						t.Fatalf("datagram did not occupy one intact record, %d bytes left", wire.Len())
					}
				}
			})
		}
	}
}
