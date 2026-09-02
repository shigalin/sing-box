package naive

import (
	"github.com/sagernet/sing/common/auth"
)

// UpdateUsers replaces the user set. Unlike an inbound created without users,
// which does not authenticate at all, an empty update keeps authentication on
// and rejects every user.
func (n *Inbound) UpdateUsers(users []auth.User) error {
	authenticator := auth.NewAuthenticator(users)
	if authenticator == nil {
		authenticator = &auth.Authenticator{}
	}
	n.authenticator.Store(authenticator)
	return nil
}
