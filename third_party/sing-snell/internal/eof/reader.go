package eof

import (
	"errors"
	"io"
	"sync/atomic"
)

type UnexpectedReader struct {
	io.Reader
}

func (r UnexpectedReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	return n, Unexpected(err)
}

func (r UnexpectedReader) Upstream() any {
	return r.Reader
}

type TrackingReader struct {
	io.Reader
	reached    atomic.Bool
	pendingEOF bool
}

func (r *TrackingReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.pendingEOF {
		r.reached.Store(true)
		return 0, io.EOF
	}
	n, err := r.Reader.Read(p)
	if errors.Is(err, io.EOF) {
		// io.ReadFull may accept these bytes as a complete protocol record.
		// Expose transport EOF only when a later read needs more data.
		r.pendingEOF = true
		if n > 0 {
			return n, nil
		}
		r.reached.Store(true)
	}
	return n, err
}

func (r *TrackingReader) Reached() bool {
	return r.reached.Load()
}

func (r *TrackingReader) Upstream() any {
	return r.Reader
}

func Unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
