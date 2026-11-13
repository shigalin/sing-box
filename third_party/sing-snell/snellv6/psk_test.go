package snellv6

import (
	"bytes"
	"testing"
)

func TestPSKProbeAuthenticatesHeader(t *testing.T) {
	for _, mode := range []Mode{ModeDefault, ModeUnshaped} {
		key := []byte("per-user-key-test")
		service, err := NewService(ServerOptions{PSK: key, Mode: mode})
		if err != nil {
			t.Fatal(err)
		}
		var wire bytes.Buffer
		if _, err = writeFirstRecord(&wire, mode, key, service.profile, []byte("test request")); err != nil {
			t.Fatal(err)
		}
		before := append([]byte(nil), wire.Bytes()...)
		if service.PSKHeaderSize() > 4096 {
			t.Fatal("header exceeds probe bound")
		}
		if service.MatchPSKHeader(before[:service.PSKHeaderSize()-1]) {
			t.Fatal("short header accepted")
		}
		if !service.MatchPSKHeader(before) {
			t.Fatal("valid PSK rejected")
		}
		if !bytes.Equal(before, wire.Bytes()) {
			t.Fatal("probe mutated wire bytes")
		}
		other, _ := NewService(ServerOptions{PSK: []byte("different-user-psk"), Mode: mode})
		if other.MatchPSKHeader(before) {
			t.Fatal("another user's key accepted")
		}
	}
}
