package anytls

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

func (h *Inbound) UpdateUsers(users []option.AnyTLSUser) error {
	return h.service.UpdateUsers(
		common.Map(users, func(it option.AnyTLSUser) string { return it.Name }),
		common.Map(users, func(it option.AnyTLSUser) string { return it.Password }),
	)
}
