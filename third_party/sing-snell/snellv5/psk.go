package snellv5

import snell "github.com/sagernet/sing-snell"

// PSKHeaderSize is the bounded prefix needed to authenticate the first record.
func (s *Service) PSKHeaderSize() int { return snell.SaltLen + snell.HeaderCipherLen }

// MatchPSKHeader verifies a copy: the original prefix is replayed to NewConnection,
// which still performs the full request, payload and replay validation.
func (s *Service) MatchPSKHeader(prefix []byte) bool {
	if len(prefix) < s.PSKHeaderSize() {
		return false
	}
	aead, err := snell.NewAEAD(snell.DeriveKey(s.psk, prefix[:snell.SaltLen]))
	if err != nil {
		return false
	}
	_, err = aead.Open(nil, make([]byte, snell.NonceLen), prefix[snell.SaltLen:s.PSKHeaderSize()], nil)
	return err == nil
}
