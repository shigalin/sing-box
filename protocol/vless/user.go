package vless

import (
	"github.com/sagernet/sing-box/common/usertable"
	"github.com/sagernet/sing-box/option"
)

// UpdateUsers replaces the user set. Users keep their ID across updates, so a
// connection is attributed to the user that authenticated it even after other
// users were added or removed; connections of removed users are rejected.
func (h *Inbound) UpdateUsers(users []option.VLESSUser) error {
	userEntryList := make([]usertable.User, 0, len(users))
	userUUIDList := make([]string, 0, len(users))
	userFlowList := make([]string, 0, len(users))
	for _, user := range users {
		userEntryList = append(userEntryList, usertable.User{Key: usertable.Key(user.Name, user.UUID, user.Flow), Name: user.Name})
		userUUIDList = append(userUUIDList, user.UUID)
		userFlowList = append(userFlowList, user.Flow)
	}
	h.service.UpdateUsers(h.users.Update(userEntryList), userUUIDList, userFlowList)
	return nil
}
