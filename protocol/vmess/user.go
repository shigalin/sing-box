package vmess

import (
	"github.com/sagernet/sing-box/common/usertable"
	"github.com/sagernet/sing-box/option"
	F "github.com/sagernet/sing/common/format"
)

// UpdateUsers replaces the user set. Users keep their ID across updates, so a
// connection is attributed to the user that authenticated it even after other
// users were added or removed; connections of removed users are rejected.
func (h *Inbound) UpdateUsers(users []option.VMessUser) error {
	h.updateAccess.Lock()
	defer h.updateAccess.Unlock()
	return h.updateUsers(users)
}

// DelUsers removes the users with the given UUIDs from the current user set.
func (h *Inbound) DelUsers(uuids []string) error {
	h.updateAccess.Lock()
	defer h.updateAccess.Unlock()
	toDelete := make(map[string]struct{}, len(uuids))
	for _, uuid := range uuids {
		toDelete[uuid] = struct{}{}
	}
	remaining := make([]option.VMessUser, 0, len(h.userOptions))
	for _, user := range h.userOptions {
		if _, found := toDelete[user.UUID]; !found {
			remaining = append(remaining, user)
		}
	}
	return h.updateUsers(remaining)
}

func (h *Inbound) updateUsers(users []option.VMessUser) error {
	userEntryList := make([]usertable.User, 0, len(users))
	userUUIDList := make([]string, 0, len(users))
	userAlterIDList := make([]int, 0, len(users))
	for _, user := range users {
		userEntryList = append(userEntryList, usertable.User{Key: usertable.Key(user.Name, user.UUID, F.ToString(user.AlterId)), Name: user.Name})
		userUUIDList = append(userUUIDList, user.UUID)
		userAlterIDList = append(userAlterIDList, user.AlterId)
	}
	state := h.users.Save()
	err := h.service.UpdateUsers(h.users.Update(userEntryList), userUUIDList, userAlterIDList)
	if err != nil {
		// The service keeps its current users, so the table must too.
		h.users.Restore(state)
		return err
	}
	h.userOptions = users
	return nil
}
