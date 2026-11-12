package snellv5

import (
	"context"
	"sync"
	"testing"

	snell "github.com/sagernet/sing-snell"
)

// Authentication reads the user map while UpdateUsers replaces it.
func TestConcurrentUserUpdateAndAuthenticate(t *testing.T) {
	service := &MultiService[int]{users: make(map[string]int)}
	update := func(keys ...string) {
		t.Helper()
		userList := make([]int, len(keys))
		keyList := make([][]byte, len(keys))
		for index, key := range keys {
			userList[index] = index
			keyList[index] = []byte(key)
		}
		if err := service.UpdateUsers(userList, keyList); err != nil {
			t.Error(err)
		}
	}
	update("alice")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			update("alice", "bob")
			update("alice")
		}
	}()
	for i := 0; i < 1000; i++ {
		if _, err := service.authenticate(context.Background(), snell.Request{ClientID: []byte("alice")}); err != nil {
			t.Fatal("a user present in every update was rejected: ", err)
		}
	}
	wg.Wait()

	// An empty update keeps authentication on and rejects every user.
	update()
	if _, err := service.authenticate(context.Background(), snell.Request{ClientID: []byte("alice")}); err == nil {
		t.Fatal("removed user accepted")
	}
}
