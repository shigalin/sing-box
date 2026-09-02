package hysteria2

import (
	"github.com/sagernet/sing-box/option"
)

func (h *Inbound) UpdateUsers(users []option.Hysteria2User) error {
	userNameList := make([]string, 0, len(users))
	userPasswordList := make([]string, 0, len(users))
	for _, user := range users {
		userNameList = append(userNameList, user.Name)
		userPasswordList = append(userPasswordList, user.Password)
	}
	userList := h.users.Update(userNameList)
	h.service.UpdateUsers(userList, userPasswordList)
	return nil
}
