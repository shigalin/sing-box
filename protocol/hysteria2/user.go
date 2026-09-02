package hysteria2

import (
	"github.com/sagernet/sing-box/common/usertable"
	"github.com/sagernet/sing-box/option"
)

func (h *Inbound) UpdateUsers(users []option.Hysteria2User) error {
	userEntryList := make([]usertable.User, 0, len(users))
	userPasswordList := make([]string, 0, len(users))
	for _, user := range users {
		userEntryList = append(userEntryList, usertable.User{Key: usertable.Key(user.Name, user.Password), Name: user.Name})
		userPasswordList = append(userPasswordList, user.Password)
	}
	userList := h.users.Update(userEntryList)
	h.service.UpdateUsers(userList, userPasswordList)
	return nil
}
