package reuse

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestIdleProbePreservesFirstReplyByte(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	conn := &Conn{Conn: local}
	var state atomic.Uint32
	state.Store(uint32(StateActive))
	if !conn.Ready(&state, StateActive) {
		t.Fatal("session was not made ready")
	}
	if !state.CompareAndSwap(uint32(StateReady), uint32(StateActive)) {
		t.Fatal("session was not reusable")
	}
	local.SetReadDeadline(time.Now().Add(time.Second))
	// A zero-length read must neither wait for nor consume the pending probe.
	if n, err := conn.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read: %d, %v", n, err)
	}
	writeDone := make(chan error, 1)
	go func() { _, err := peer.Write([]byte("reply")); writeDone <- err }()
	local.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "reply" {
		t.Fatalf("probe changed reply: %q", got)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if State(state.Load()) != StateActive {
		t.Fatal("old idle probe closed an active session")
	}
}
