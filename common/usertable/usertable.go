package usertable

import "sync"

// Table assigns stable integer IDs to users keyed by user name.
//
// QUIC based inbounds store the authenticated user ID per session, so the ID
// must not change while the user set is updated: sessions of users that are
// still present keep resolving to the same user even if their credential was
// rotated, and sessions of removed (or renamed) users no longer resolve at
// all, so the inbound can reject their new streams instead of routing them
// under a stale or empty identity.
type Table struct {
	access sync.RWMutex
	ids    map[string]int
	names  map[int]string
	nextID int
}

// Update replaces the user set and returns the ID assigned to each name, in
// input order. Names already present keep their ID; new names get a fresh one.
// Users sharing a name share an ID, as they are indistinguishable downstream.
func (t *Table) Update(names []string) []int {
	t.access.Lock()
	defer t.access.Unlock()
	newIDs := make(map[string]int, len(names))
	newNames := make(map[int]string, len(names))
	idList := make([]int, 0, len(names))
	for _, name := range names {
		id, loaded := newIDs[name]
		if !loaded {
			id, loaded = t.ids[name]
			if !loaded {
				id = t.nextID
				t.nextID++
			}
			newIDs[name] = id
			newNames[id] = name
		}
		idList = append(idList, id)
	}
	t.ids = newIDs
	t.names = newNames
	return idList
}

// Name returns the name of the user with the given ID. The second result is
// false if no current user has this ID, i.e. the user was removed or renamed.
func (t *Table) Name(id int) (string, bool) {
	t.access.RLock()
	defer t.access.RUnlock()
	name, loaded := t.names[id]
	return name, loaded
}
