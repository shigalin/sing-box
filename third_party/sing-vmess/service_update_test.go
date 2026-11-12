package vmess

import (
	"context"
	"net"
	"sync"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

// Exercise the actual handshake reader while both update paths publish maps.
func TestConcurrentUserUpdateAndHandshake(t *testing.T) {
	s := NewService[int](nil)
	update := func(i int) {
		t.Helper()
		if err := s.UpdateUsers([]int{i % 2}, []string{"11111111-1111-4111-8111-111111111111"}, []int{i % 2}); err != nil {
			t.Error(err)
		}
	}
	update(0)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			update(i)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			s.generateLegacyKeys()
		}
	}()
	for i := 0; i < 100; i++ {
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() { defer close(done); defer client.Close(); _, _ = client.Write(make([]byte, 128)) }()
		err := s.NewConnection(context.Background(), server, M.Socksaddr{}, nil)
		server.Close()
		<-done
		if err == nil {
			t.Fatal("invalid handshake accepted")
		}
	}
	wg.Wait()
}
