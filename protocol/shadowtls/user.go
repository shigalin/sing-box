package shadowtls

import (
	"crypto/rand"
	"net"
	"strconv"

	"github.com/sagernet/sing-box/common/usertable"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowtls"
	E "github.com/sagernet/sing/common/exceptions"
)

// UpdateUsers replaces the user set of a version 3 inbound. Users keep their
// ID across updates, so a connection is attributed to the user that
// authenticated it even after other users were added or removed; connections
// of removed users are closed, so they cannot keep using a protocol that
// reuses the connection behind this inbound. Whether the inbound has users at
// all is fixed at creation: only a version 3 inbound created with users can
// take them, and an empty update of one rejects every user.
func (h *Inbound) UpdateUsers(users []option.ShadowTLSUser) error {
	if h.serviceConfig == nil {
		return E.New("shadowtls: inbound was created without users")
	}
	userEntryList := make([]usertable.User, 0, len(users))
	for _, user := range users {
		userEntryList = append(userEntryList, usertable.User{Key: usertable.Key(user.Name, user.Password), Name: user.Name})
	}
	// The table and the service must end up with the same user set, also
	// when two updates overlap or one of them is rolled back.
	h.updateAccess.Lock()
	defer h.updateAccess.Unlock()
	state := h.users.Save()
	userIDList := h.users.Update(userEntryList)
	// The service only reports the name of the user it authenticated, so it
	// is given the ID as the name: names need not be unique, IDs are.
	serviceConfig := *h.serviceConfig
	serviceConfig.Users = make([]shadowtls.User, 0, len(users)+1)
	for index, user := range users {
		serviceConfig.Users = append(serviceConfig.Users, shadowtls.User{Name: strconv.Itoa(userIDList[index]), Password: user.Password})
	}
	if len(serviceConfig.Users) == 0 {
		// The service needs a user. Nobody knows this password, so every
		// client is handled as an unauthenticated one.
		serviceConfig.Users = append(serviceConfig.Users, shadowtls.User{Password: rand.Text()})
	}
	service, err := shadowtls.NewService(serviceConfig)
	if err != nil {
		// The inbound keeps its current service, so the table must too.
		h.users.Restore(state)
		return err
	}
	h.service.Store(service)
	h.closeRemovedUsers()
	return nil
}

// trackConn registers an authenticated connection and returns the name of
// its user. It reports false if the user is not in the current user set.
func (h *Inbound) trackConn(conn net.Conn, userID int) (net.Conn, string, bool) {
	h.connAccess.Lock()
	defer h.connAccess.Unlock()
	// Looked up under the lock: an update that removes the user has either
	// already made this lookup fail or will find the connection registered.
	userName, loaded := h.users.Name(userID)
	if !loaded {
		return conn, "", false
	}
	tracked := &userConn{Conn: conn, inbound: h, userID: userID}
	h.conns[tracked] = struct{}{}
	return tracked, userName, true
}

func (h *Inbound) closeRemovedUsers() {
	var removed []*userConn
	h.connAccess.Lock()
	for conn := range h.conns {
		_, loaded := h.users.Name(conn.userID)
		if !loaded {
			removed = append(removed, conn)
		}
	}
	h.connAccess.Unlock()
	for _, conn := range removed {
		conn.Close()
	}
}

// userConn is an authenticated connection, registered until it is closed.
type userConn struct {
	net.Conn
	inbound *Inbound
	userID  int
}

func (c *userConn) Close() error {
	c.inbound.connAccess.Lock()
	delete(c.inbound.conns, c)
	c.inbound.connAccess.Unlock()
	return c.Conn.Close()
}

func (c *userConn) Upstream() any {
	return c.Conn
}

func (c *userConn) ReaderReplaceable() bool {
	return true
}

func (c *userConn) WriterReplaceable() bool {
	return true
}
