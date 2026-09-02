package mieru

import (
	"github.com/sagernet/sing-box/option"
)

// UpdateUsers replaces the user set on the running server. New connections
// authenticate against the new set; established sessions keep their identity
// until they end, as mieru only re-checks credentials at handshake. An empty
// list removes every user, so all new handshakes are rejected.
func (h *Inbound) UpdateUsers(users []option.MieruUser) error {
	if err := validateMieruUsers(users); err != nil {
		return err
	}
	h.mux.SetServerUsers(buildMieruUsers(users))
	return nil
}
