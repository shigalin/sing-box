package eof

import (
	"io"
	"testing"
)

type finalDataReader struct {
	data  []byte
	calls int
}

func (r *finalDataReader) Read(p []byte) (int, error) {
	r.calls++
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func TestTrackingReaderFinalData(t *testing.T) {
	source := &finalDataReader{data: []byte("record")}
	r := &TrackingReader{Reader: source}
	p := make([]byte, 6)
	if n, err := io.ReadFull(r, p); n != 6 || err != nil {
		t.Fatalf("complete record: %d %v", n, err)
	}
	if r.Reached() {
		t.Fatal("complete final record was marked as transport EOF")
	}
	if n, err := r.Read(nil); n != 0 || err != nil || r.Reached() {
		t.Fatalf("empty read consumed pending EOF: %d %v", n, err)
	}
	if n, err := r.Read(p); n != 0 || err != io.EOF || !r.Reached() {
		t.Fatalf("pending EOF: %d %v", n, err)
	}
	if source.calls != 1 {
		t.Fatalf("read past terminal EOF: %d calls", source.calls)
	}
}

func TestTrackingReaderTruncatedData(t *testing.T) {
	r := &TrackingReader{Reader: &finalDataReader{data: []byte("short")}}
	if _, err := io.ReadFull(r, make([]byte, 6)); err != io.ErrUnexpectedEOF || !r.Reached() {
		t.Fatalf("truncated record: %v reached=%v", err, r.Reached())
	}
}
