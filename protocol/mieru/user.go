package mieru

import (
	"github.com/sagernet/sing-box/option"
)

// UpdateUsers replaces the user set on the running server. New handshakes
// authenticate against the new set, and connections of removed users are
// rejected even on underlays that authenticated before the update. An empty
// list removes every user.
func (h *Inbound) UpdateUsers(users []option.MieruUser) error {
	if err := validateMieruUsers(users); err != nil {
		return err
	}
	h.setUsers(users)
	h.mux.SetServerUsers(buildMieruUsers(users))
	return nil
}
