package reuse

import (
	"sync/atomic"
	"testing"
)

type testSession struct{ state atomic.Uint32 }

func (s *testSession) ReuseState() *atomic.Uint32 { return &s.state }
func (s *testSession) Close() error               { s.state.Store(uint32(StateClosed)); return nil }

func TestPoolTakesMostRecentlyReadySession(t *testing.T) {
	var pool Pool[*testSession]
	pool.Init()
	defer pool.Close()
	first, second, waiting := &testSession{}, &testSession{}, &testSession{}
	waiting.state.Store(uint32(StateWaiting))
	for _, session := range []*testSession{first, second, waiting} {
		if !pool.MoveToPool(session, State(session.state.Load()), false) {
			t.Fatal("pool rejected session")
		}
	}
	got, found, closed := pool.Take()
	if got != second || !found || closed {
		t.Fatalf("Take() = %p, %v, %v; want most recently ready %p", got, found, closed, second)
	}
}
