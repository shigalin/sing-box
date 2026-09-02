package usertable

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func users(names ...string) []User {
	list := make([]User, 0, len(names))
	for _, name := range names {
		list = append(list, User{Key: Key(name, "pw"), Name: name})
	}
	return list
}

func TestTableKeepsIDsAcrossUpdates(t *testing.T) {
	t.Parallel()
	var table Table
	require.Equal(t, []int{0, 1, 2}, table.Update(users("a", "b", "c")))

	// Same users: same IDs.
	require.Equal(t, []int{0, 1, 2}, table.Update(users("a", "b", "c")))

	// Shrink and reorder: surviving users keep their IDs, removed user is gone.
	require.Equal(t, []int{2, 0}, table.Update(users("c", "a")))
	name, loaded := table.Name(2)
	require.True(t, loaded)
	require.Equal(t, "c", name)
	_, loaded = table.Name(1)
	require.False(t, loaded)
	_, loaded = table.Name(99)
	require.False(t, loaded)

	// New users get fresh IDs; a removed user that comes back is a new user.
	require.Equal(t, []int{2, 0, 3, 4}, table.Update(users("c", "a", "d", "b")))
}

func TestTableCredentialRotationIsNewUser(t *testing.T) {
	t.Parallel()
	var table Table
	require.Equal(t, []int{0}, table.Update([]User{{Key: Key("a", "old"), Name: "a"}}))
	require.Equal(t, []int{1}, table.Update([]User{{Key: Key("a", "new"), Name: "a"}}))
	// Sessions authenticated with the old credential must not resolve anymore.
	_, loaded := table.Name(0)
	require.False(t, loaded)
	name, loaded := table.Name(1)
	require.True(t, loaded)
	require.Equal(t, "a", name)
}

func TestTableDuplicateNames(t *testing.T) {
	t.Parallel()
	var table Table
	// Unnamed users are the common duplicate case (TUIC users only need a
	// UUID). Different credentials mean different users with distinct IDs.
	first := User{Key: Key("", "uuid-1"), Name: ""}
	second := User{Key: Key("", "uuid-2"), Name: ""}
	other := User{Key: Key("b", "uuid-3"), Name: "b"}
	require.Equal(t, []int{0, 1, 2}, table.Update([]User{first, second, other}))
	for _, id := range []int{0, 1} {
		name, loaded := table.Name(id)
		require.True(t, loaded, "an empty name is a valid user and must stay resolvable")
		require.Equal(t, "", name)
	}

	// Removing the first unnamed user must not shift the second one onto its
	// ID: sessions of the second user still carry ID 1.
	require.Equal(t, []int{1, 2}, table.Update([]User{second, other}))
	_, loaded := table.Name(0)
	require.False(t, loaded)
	name, loaded := table.Name(1)
	require.True(t, loaded)
	require.Equal(t, "", name)

	// A user listed twice is one user with one ID.
	require.Equal(t, []int{1, 1, 2}, table.Update([]User{second, second, other}))
	require.Equal(t, []int{3, 1, 2}, table.Update([]User{first, second, other}))
}
