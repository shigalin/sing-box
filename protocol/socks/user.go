package socks

import (
	"github.com/sagernet/sing/common/auth"
)

// UpdateUsers replaces the user set. Unlike an inbound created without users,
// which does not authenticate at all, an empty update keeps authentication on
// and rejects every user.
func (h *Inbound) UpdateUsers(users []auth.User) error {
	authenticator := auth.NewAuthenticator(users)
	if authenticator == nil {
		authenticator = &auth.Authenticator{}
	}
	h.authenticator.Store(authenticator)
	return nil
}
