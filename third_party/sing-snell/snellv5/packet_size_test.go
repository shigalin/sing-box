package snellv5

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
)

// UDP boundaries must survive even the first record and an idle-window reset.
func TestPacketRecordsPreserveLargeDatagrams(t *testing.T) {
	t.Parallel()

	for _, vector := range []bool{false, true} {
		for _, idle := range []bool{false, true} {
			t.Run(fmt.Sprintf("vector=%v/idle=%v", vector, idle), func(t *testing.T) {
				t.Parallel()

				var wire bytes.Buffer
				aead, initErr := snell.NewAEAD(make([]byte, 32))
				if initErr != nil {
					t.Fatal(initErr)
				}
				w, initErr := newWriter(&wire, aead, make([]byte, snell.NonceLen))
				if initErr != nil {
					t.Fatal(initErr)
				}
				r := newReader(&wire, aead, make([]byte, snell.NonceLen))
				for _, size := range []int{4096, 1, 8192, maxPayload} {
					if idle {
						w.lastFrameUnix = time.Now().Unix() - framePayloadResetInterval - 1
					}

					payload := make([]byte, size)
					for i := range payload {
						payload[i] = byte(i*31 + size)
					}
					b := buf.NewSize(w.FrontHeadroom() + len(payload) + w.RearHeadroom())
					b.Resize(w.FrontHeadroom(), 0)
					b.Write(payload)
					var err error
					if vector {
						err = w.CreatePacketVectorisedWriterFor(packetTestVectorWriter{&wire}).WriteVectorised([]*buf.Buffer{b})
					} else {
						err = w.WritePacketBuffer(b)
					}
					if err != nil {
						t.Fatalf("write %d bytes: %v", size, err)
					}
					record, err := r.ReadRecord()
					if err != nil {
						t.Fatal(err)
					}
					same := bytes.Equal(record.Bytes(), payload)
					record.Release()
					if !same {
						t.Fatalf("%d-byte datagram changed", size)
					}
				}
				b := buf.NewSize(maxPayload + 1)
				b.Extend(maxPayload + 1)
				var err error
				if vector {
					err = w.CreatePacketVectorisedWriterFor(packetTestVectorWriter{&wire}).WriteVectorised([]*buf.Buffer{b})
				} else {
					err = w.WritePacketBuffer(b)
				}
				if !errors.Is(err, snell.ErrPayloadTooLarge) {
					t.Fatalf("oversized record: %v", err)
				}
			})
		}
	}
}

type packetTestVectorWriter struct{ *bytes.Buffer }

func (w packetTestVectorWriter) WriteVectorised(buffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(buffers)
	for _, b := range buffers {
		if _, err := w.Write(b.Bytes()); err != nil {
			return err
		}
	}
	return nil
}
