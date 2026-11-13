package snellv6

import snell "github.com/sagernet/sing-snell"

func (s *Service) PSKHeaderSize() int {
	switch s.mode {
	case ModeUnshaped:
		return snell.SaltLen + snell.HeaderCipherLen
	case ModeDefault:
		return s.profile.saltBlockLen + s.profile.recordPrefixLen(0) + snell.HeaderCipherLen
	default:
		return 0 // unsafe-raw cannot authenticate a PSK
	}
}

func (s *Service) MatchPSKHeader(prefix []byte) bool {
	size := s.PSKHeaderSize()
	if size == 0 || len(prefix) < size {
		return false
	}
	var salt []byte
	var aad []byte
	switch s.mode {
	case ModeUnshaped:
		salt = prefix[:snell.SaltLen]
	case ModeDefault:
		extracted := s.profile.extractSalt(prefix[:s.profile.saltBlockLen])
		salt = extracted[:]
		aad = prefix[s.profile.saltBlockLen : size-snell.HeaderCipherLen]
	}
	aead, err := snell.NewAEAD(snell.DeriveKey(s.psk, salt))
	if err != nil {
		return false
	}
	_, err = aead.Open(nil, make([]byte, snell.NonceLen), prefix[size-snell.HeaderCipherLen:size], aad)
	return err == nil
}
