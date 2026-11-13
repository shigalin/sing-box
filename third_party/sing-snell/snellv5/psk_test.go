package snellv5

import (
	"bytes"
	snell "github.com/sagernet/sing-snell"
	"testing"
)

func TestPSKProbeAndSharedReplayCache(t *testing.T) {
	cache := &ReplayCache{}
	first, err := NewService(ServiceOptions{PSK: []byte("first-user-key"), ReplayCache: cache})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewService(ServiceOptions{PSK: []byte("second-user-key"), ReplayCache: cache})
	if err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, snell.SaltLen)
	key := snell.DeriveKey(first.psk, salt)
	aead, err := snell.NewAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	writer, err := newWriter(&wire, aead, make([]byte, snell.NonceLen))
	if err != nil {
		t.Fatal(err)
	}
	if err = writer.WriteFirst(salt, []byte("request")); err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), wire.Bytes()...)
	if !first.MatchPSKHeader(original) || second.MatchPSKHeader(original) {
		t.Fatal("PSK selection failed")
	}
	if !bytes.Equal(original, wire.Bytes()) {
		t.Fatal("probe modified request")
	}
	if cache.CheckAndAdd(key) {
		t.Fatal("new salt rejected")
	}
	if !cache.CheckAndAdd(key) {
		t.Fatal("replay accepted")
	}
	if cache.CheckAndAdd(snell.DeriveKey(second.psk, salt)) {
		t.Fatal("equal salt under a different PSK rejected")
	}
	if first.saltCache != second.saltCache {
		t.Fatal("per-user services did not share replay-cache storage")
	}
}
