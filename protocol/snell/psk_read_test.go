package snell

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPSKReadAheadHandoffClose(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	reader := &pskReadAhead{Conn: raw}
	reader.start(32)
	conn := reader.handoff()
	done := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); done <- err }()
	require.NoError(t, conn.Close())
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt handed-off read")
	}
}

func TestPSKReadAheadPreservesEOF(t *testing.T) {
	raw, peer := net.Pipe()
	defer raw.Close()
	reader := &pskReadAhead{Conn: raw}
	reader.start(32)
	peer.Close()
	result := <-reader.pending
	reader.pending = nil
	reader.terminalErr = result.err
	require.ErrorIs(t, result.err, io.EOF)
	_, err := reader.handoff().Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
}
