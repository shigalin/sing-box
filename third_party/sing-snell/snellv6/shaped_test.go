package snellv6

import (
	"bytes"
	"errors"
	"io"
	"testing"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
)

func TestShapedWriterWritePacketBufferFallsBackForInsufficientHeadroom(t *testing.T) {
	const inputHeadroom = 1024
	psk := []byte("snell-v6-packet-headroom-regression")
	profile := NewProfile(psk)
	payload := bytes.Repeat([]byte{0x42}, 64)
	sequence, _ := findShapedRecordRequiringHeadroom(t, profile, len(payload), inputHeadroom)

	salt := bytes.Repeat([]byte{0x24}, saltLen)
	writerCipher, err := snell.NewAEAD(snell.DeriveKey(psk, salt))
	if err != nil {
		t.Fatal(err)
	}
	var upstream bytes.Buffer
	writer := newShapedWriter(
		&upstream,
		profile,
		salt,
		writerCipher,
		make([]byte, snell.NonceLen),
	)
	writer.saltSent = true
	writer.seq = sequence

	packet := buf.NewSize(inputHeadroom + len(payload) + snell.AEADTagLen)
	packet.Resize(inputHeadroom, 0)
	if _, err = packet.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = writer.WritePacketBuffer(packet); err != nil {
		t.Fatal(err)
	}
	if packet.RawCap() != 0 {
		t.Fatal("input packet was not released after the fallback write")
	}

	readerCipher, err := snell.NewAEAD(snell.DeriveKey(psk, salt))
	if err != nil {
		t.Fatal(err)
	}
	reader := newShapedReader(bytes.NewReader(upstream.Bytes()), psk, profile)
	reader.cipher = readerCipher
	reader.seq = sequence
	record, err := reader.ReadRecord()
	if err != nil {
		t.Fatal(err)
	}
	defer record.Release()
	if !bytes.Equal(payload, record.Bytes()) {
		t.Fatalf("payload mismatch after fallback: got %d bytes, want %d", record.Len(), len(payload))
	}
}

func TestShapedWriterMakeBufferRecordUsesSufficientInputSpace(t *testing.T) {
	const inputHeadroom = 1024
	psk := []byte("snell-v6-packet-headroom-regression")
	profile := NewProfile(psk)
	payload := bytes.Repeat([]byte{0x24}, 64)
	sequence, requiredHeadroom := findShapedRecordRequiringHeadroom(t, profile, len(payload), inputHeadroom)

	salt := bytes.Repeat([]byte{0x42}, saltLen)
	writerCipher, err := snell.NewAEAD(snell.DeriveKey(psk, salt))
	if err != nil {
		t.Fatal(err)
	}
	writer := newShapedWriter(
		io.Discard,
		profile,
		salt,
		writerCipher,
		make([]byte, snell.NonceLen),
	)
	writer.saltSent = true
	writer.seq = sequence

	packet := buf.NewSize(requiredHeadroom + len(payload) + snell.AEADTagLen)
	packet.Resize(requiredHeadroom, 0)
	if _, err = packet.Write(payload); err != nil {
		t.Fatal(err)
	}
	record := writer.makeBufferRecord(packet)
	if record != packet {
		record.Release()
		packet.Release()
		t.Fatal("sufficient input buffer unexpectedly used the allocating fallback")
	}
	record.Release()
}

func findShapedRecordRequiringHeadroom(t *testing.T, profile *Profile, payloadLen int, available int) (uint32, int) {
	t.Helper()
	for candidate := uint32(1); candidate < 10000; candidate++ {
		prefixLen := profile.recordPrefixLen(candidate)
		paddingLen := profile.paddingLen(candidate, payloadLen, prefixLen, 0, 0)
		frontLen := prefixLen + snell.HeaderCipherLen + paddingLen
		if frontLen > available {
			return candidate, frontLen
		}
	}
	t.Fatal("test profile did not produce a shaped record larger than the input headroom")
	return 0, 0
}

// Record the bytes before returning an injected error, so both error propagation
// and record validity can be checked. Vectorised writers own their input buffers.
type shapedTestUpstream struct {
	bytes.Buffer
	err     error
	records []*buf.Buffer
}

func (w *shapedTestUpstream) Write(p []byte) (int, error) {
	n, _ := w.Buffer.Write(p)
	return n, w.err
}

func (w *shapedTestUpstream) WriteVectorised(buffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(buffers)
	w.records = append(w.records, buffers...)
	for _, buffer := range buffers {
		_, _ = w.Buffer.Write(buffer.Bytes())
	}
	return w.err
}

func TestShapedWriterBufferSpaceFallbacks(t *testing.T) {
	writeFailure := errors.New("injected shaped write failure")
	for _, method := range []string{"buffer", "packet", "vector", "packet-vector"} {
		for _, space := range []string{"headroom", "tailroom", "sufficient"} {
			for _, outcome := range []string{"success", "error"} {
				t.Run(method+"/"+space+"/"+outcome, func(t *testing.T) {
					psk := []byte("snell-v6-buffer-space-regression")
					profile := NewProfile(psk)
					salt := bytes.Repeat([]byte{0x42}, saltLen)
					aead, err := snell.NewAEAD(snell.DeriveKey(psk, salt))
					if err != nil {
						t.Fatal(err)
					}
					upstream := &shapedTestUpstream{}
					if outcome == "error" {
						upstream.err = writeFailure
					}
					writer := newShapedWriter(upstream, profile, salt, aead, make([]byte, snell.NonceLen))
					// One-byte payloads fit every stream chunk limit. Exercise the
					// initial salt-bearing record and subsequent records in one batch.
					payloads := [][]byte{{0x11}, {0x22}, {0x33}}
					var inputs []*buf.Buffer
					for i, payload := range payloads {
						headroom := writer.FrontHeadroom()
						tailroom := snell.AEADTagLen
						// Keep the middle record in place, checking mixed ownership
						// alongside both first-record and later-record fallbacks.
						if i != 1 {
							switch space {
							case "headroom":
								headroom = 0
							case "tailroom":
								tailroom--
							}
						}
						input := buf.NewSize(headroom + len(payload) + tailroom)
						input.Resize(headroom, 0)
						_, _ = input.Write(payload)
						if input.Start() != headroom || input.FreeLen() != tailroom {
							t.Fatal("input does not have the requested buffer space")
						}
						inputs = append(inputs, input)
					}
					defer buf.ReleaseMulti(inputs)
					switch method {
					case "buffer", "packet":
						for _, input := range inputs {
							if method == "buffer" {
								err = writer.WriteBuffer(input)
							} else {
								err = writer.WritePacketBuffer(input)
							}
							if !errors.Is(err, upstream.err) {
								t.Fatalf("write error = %v, want %v", err, upstream.err)
							}
						}
					case "vector":
						err = writer.CreateVectorisedWriterFor(upstream).WriteVectorised(inputs)
					case "packet-vector":
						err = writer.CreatePacketVectorisedWriterFor(upstream).WriteVectorised(inputs)
					}
					if !errors.Is(err, upstream.err) {
						t.Fatalf("write error = %v, want %v", err, upstream.err)
					}
					for i, input := range inputs {
						if input.RawCap() != 0 {
							t.Errorf("input %d was not released", i)
						}
					}
					if method == "vector" || method == "packet-vector" {
						if len(upstream.records) != len(inputs) {
							t.Fatalf("got %d records, want %d", len(upstream.records), len(inputs))
						}
						for i, record := range upstream.records {
							wantInPlace := space == "sufficient" || i == 1
							if (record == inputs[i]) != wantInPlace {
								t.Errorf("record %d: in-place = %v, want %v", i, record == inputs[i], wantInPlace)
							}
							if record.RawCap() != 0 {
								t.Errorf("output record %d was not released", i)
							}
						}
					}
					reader := newShapedReader(&upstream.Buffer, psk, profile)
					for i, payload := range payloads {
						record, err := reader.ReadRecord()
						if err != nil {
							t.Fatalf("read record %d: %v", i, err)
						}
						matches := bytes.Equal(record.Bytes(), payload)
						record.Release()
						if !matches {
							t.Fatalf("record %d payload mismatch", i)
						}
					}
					if upstream.Len() != 0 {
						t.Fatalf("%d unexpected bytes after records", upstream.Len())
					}
				})
			}
		}
	}
}
