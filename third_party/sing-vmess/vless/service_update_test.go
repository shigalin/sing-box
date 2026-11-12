package vless

import (
	"bytes"
	"context"
	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing/common/auth"
	N "github.com/sagernet/sing/common/network"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// Exercise the actual request reader while UpdateUsers publishes maps.
func TestConcurrentUserUpdateAndHandshake(t *testing.T) {
	s := NewService[int](nil, nil)
	update := func(i int) {
		s.UpdateUsers([]int{i % 2}, []string{"11111111-1111-4111-8111-111111111111"}, []string{""})
	}
	update(0)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			update(i)
		}
	}()
	// Version 0, zero UUID, no addons, TCP, port 80, IPv4 0.0.0.0.
	request := make([]byte, 26)
	request[18] = 1
	request[20] = 80
	request[21] = 1
	for i := 0; i < 100; i++ {
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() { defer close(done); defer client.Close(); _, _ = client.Write(request) }()
		err := s.NewConnection(context.Background(), server, M.Socksaddr{}, nil)
		server.Close()
		<-done
		if err == nil {
			t.Fatal("unknown user accepted")
		}
	}
	wg.Wait()
}

type authenticatedHandler struct{ users chan int }

func (h *authenticatedHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	user, ok := auth.UserFromContext[int](ctx)
	if !ok {
		user = -1
	}
	h.users <- user
	conn.Close()
}
func (h *authenticatedHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
	panic("unexpected UDP")
}

func TestConcurrentAuthenticationFlowPairing(t *testing.T) {
	const first = "11111111-1111-4111-8111-111111111111"
	const second = "22222222-2222-4222-8222-222222222222"
	h := &authenticatedHandler{users: make(chan int, 1)}
	s := NewService[int](nil, h)
	update := func(i int) { s.UpdateUsers([]int{i % 2, 1 - i%2}, []string{first, second}, []string{"", FlowVision}) }
	update(0)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				update(i)
			}
		}
	}()
	defer func() { close(stop); <-done }()
	handshake := func(flow string) error {
		var request bytes.Buffer
		if err := WriteRequest(&request, Request{UUID: uuid.Must(uuid.FromString(first)), Command: 1, Destination: M.ParseSocksaddr("127.0.0.1:80"), Flow: flow}, nil); err != nil {
			t.Fatal(err)
		}
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()
		server.SetDeadline(time.Now().Add(5 * time.Second))
		sent := make(chan struct{})
		go func() { defer close(sent); defer client.Close(); client.Write(request.Bytes()) }()
		err := s.NewConnection(context.Background(), server, M.Socksaddr{}, nil)
		server.Close()
		<-sent
		return err
	}
	for i := 0; i < 200; i++ {
		if err := handshake(""); err != nil {
			t.Fatalf("consistent UUID/flow must authenticate: %v", err)
		}
		select {
		case user := <-h.users:
			if user != 0 && user != 1 {
				t.Fatalf("missing identity: %d", user)
			}
		default:
			t.Fatal("successful authentication did not reach handler")
		}
		if err := handshake(FlowVision); err == nil || !strings.Contains(err.Error(), "flow mismatch") {
			t.Fatalf("wrong flow must be rejected: %v", err)
		}
	}
}
