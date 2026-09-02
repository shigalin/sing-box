package trojan

import (
	"github.com/sagernet/sing-box/common/usertable"
	"github.com/sagernet/sing-box/option"
)

// UpdateUsers replaces the user set. Users keep their ID across updates, so a
// connection is attributed to the user that authenticated it even after other
// users were added or removed; connections of removed users are rejected.
func (h *Inbound) UpdateUsers(users []option.TrojanUser) error {
	userEntryList := make([]usertable.User, 0, len(users))
	userPasswordList := make([]string, 0, len(users))
	for _, user := range users {
		userEntryList = append(userEntryList, usertable.User{Key: usertable.Key(user.Name, user.Password), Name: user.Name})
		userPasswordList = append(userPasswordList, user.Password)
	}
	state := h.users.Save()
	err := h.service.UpdateUsers(h.users.Update(userEntryList), userPasswordList)
	if err != nil {
		// The service keeps its current users, so the table must too.
		h.users.Restore(state)
	}
	return err
}
