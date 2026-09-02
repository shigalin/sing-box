package usertable

import (
	"strings"
	"sync"
)

// Table assigns stable integer IDs to users.
//
// QUIC based inbounds store the authenticated user ID per session, so the ID
// must not change while the user set is updated: sessions of users that are
// still present keep resolving to the same user, and sessions of users that
// are gone no longer resolve at all, so the inbound can reject their new
// streams instead of routing them under a stale or empty identity.
//
// Users are identified by Key, not by position: removing one user never
// changes the ID of any other user, even among users sharing a name.
type Table struct {
	access sync.RWMutex
	ids    map[string]int
	names  map[int]string
	nextID int
}

// User is one entry of the user set.
type User struct {
	// Key is the stable identity of the user, see Key. Entries with equal keys
	// are the same user and share one ID; protocol services key per-user state
	// by ID, so two different users must never share one.
	Key string
	// Name is the display name used for logging and routing.
	Name string
}

// Key builds a user key from the name and the credentials of a user. Users
// with the same name but different credentials are different users, so
// rotating a credential is a removal plus an addition: sessions authenticated
// with the old credential are rejected from then on.
func Key(name string, credentials ...string) string {
	return name + "\x00" + strings.Join(credentials, "\x00")
}

// Update replaces the user set and returns the ID assigned to each user, in
// input order. Keys already present keep their ID; new keys get a fresh one.
func (t *Table) Update(users []User) []int {
	t.access.Lock()
	defer t.access.Unlock()
	newIDs := make(map[string]int, len(users))
	newNames := make(map[int]string, len(users))
	idList := make([]int, 0, len(users))
	for _, user := range users {
		id, loaded := newIDs[user.Key]
		if !loaded {
			id, loaded = t.ids[user.Key]
			if !loaded {
				id = t.nextID
				t.nextID++
			}
			newIDs[user.Key] = id
			newNames[id] = user.Name
		}
		idList = append(idList, id)
	}
	t.ids = newIDs
	t.names = newNames
	return idList
}

// Name returns the name of the user with the given ID. The second result is
// false if no current user has this ID, i.e. the user was removed or its
// credentials were changed.
func (t *Table) Name(id int) (string, bool) {
	t.access.RLock()
	defer t.access.RUnlock()
	name, loaded := t.names[id]
	return name, loaded
}
