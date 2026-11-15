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

// An oversized datagram must not discard the valid datagrams in its batch.
func TestPacketVectorKeepsValidDatagramsAroundOversized(t *testing.T) {
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
	newPacket := func(payload []byte) *buf.Buffer {
		b := buf.NewSize(w.FrontHeadroom() + len(payload) + w.RearHeadroom())
		b.Resize(w.FrontHeadroom(), 0)
		b.Write(payload)
		return b
	}
	first, last := []byte("before oversized"), []byte("after oversized")
	batch := []*buf.Buffer{newPacket(first), newPacket(make([]byte, maxPayload+1)), newPacket(last)}
	err = w.CreatePacketVectorisedWriterFor(packetTestVectorWriter{&wire}).WriteVectorised(batch)
	if !errors.Is(err, snell.ErrPayloadTooLarge) {
		t.Fatalf("mixed batch: %v", err)
	}
	for _, want := range [][]byte{first, last} {
		record, err := r.ReadRecord()
		if err != nil {
			t.Fatalf("read %q: %v", want, err)
		}
		same := bytes.Equal(record.Bytes(), want)
		record.Release()
		if !same {
			t.Fatalf("datagram %q changed", want)
		}
	}
	if wire.Len() != 0 {
		t.Fatalf("%d unexpected bytes after valid datagrams", wire.Len())
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
