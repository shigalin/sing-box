package snell

import (
	"github.com/sagernet/sing-box/common/usertable"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type userService interface {
	UpdateUsers(userList []int, userKeyList [][]byte) error
}

// UpdateUsers replaces the user set. Users keep their ID across updates, so a
// connection is attributed to the user that authenticated it even after other
// users were added or removed; requests of removed users are rejected, also
// on reused connections. Whether the inbound authenticates users at all is
// fixed at creation: one created without users accepts the PSK alone and
// cannot take users, while an empty update of one created with users keeps
// authentication on and rejects every user.
func (h *Inbound) UpdateUsers(users []option.SnellUser) error {
	if h.userService == nil {
		return E.New("snell: inbound was created without users")
	}
	userEntryList := make([]usertable.User, 0, len(users))
	userKeyList := make([][]byte, 0, len(users))
	for _, user := range users {
		userEntryList = append(userEntryList, usertable.User{Key: usertable.Key(user.Name, user.UserKey), Name: user.Name})
		userKeyList = append(userKeyList, []byte(user.UserKey))
	}
	// The table and the service must end up with the same user set, also
	// when two updates overlap or one of them is rolled back.
	h.updateAccess.Lock()
	defer h.updateAccess.Unlock()
	state := h.users.Save()
	err := h.userService.UpdateUsers(h.users.Update(userEntryList), userKeyList)
	if err != nil {
		// The service keeps its current users, so the table must too.
		h.users.Restore(state)
	}
	return err
}
