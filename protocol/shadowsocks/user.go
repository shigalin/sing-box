package shadowsocks

import (
	"github.com/sagernet/sing-box/option"
)

// UpdateUsersByOptions replaces the user set. Users keep their ID across
// updates, so a connection is attributed to the user that authenticated it
// even after other users were added or removed; connections of removed users
// are rejected.
func (h *MultiInbound) UpdateUsersByOptions(users []option.ShadowsocksUser) error {
	userNameList := make([]string, 0, len(users))
	userPasswordList := make([]string, 0, len(users))
	for _, user := range users {
		userNameList = append(userNameList, user.Name)
		userPasswordList = append(userPasswordList, user.Password)
	}
	return h.UpdateUsers(userNameList, userPasswordList)
}
