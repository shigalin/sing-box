package usertable

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTableKeepsIDsAcrossUpdates(t *testing.T) {
	t.Parallel()
	var table Table
	require.Equal(t, []int{0, 1, 2}, table.Update([]string{"a", "b", "c"}))

	// Credential rotation is a no-op for the table: same names, same IDs.
	require.Equal(t, []int{0, 1, 2}, table.Update([]string{"a", "b", "c"}))

	// Shrink and reorder: surviving users keep their IDs, removed user is gone.
	require.Equal(t, []int{2, 0}, table.Update([]string{"c", "a"}))
	name, loaded := table.Name(2)
	require.True(t, loaded)
	require.Equal(t, "c", name)
	_, loaded = table.Name(1)
	require.False(t, loaded)
	_, loaded = table.Name(99)
	require.False(t, loaded)

	// New users get fresh IDs; a removed name that comes back is a new user.
	require.Equal(t, []int{2, 0, 3, 4}, table.Update([]string{"c", "a", "d", "b"}))
}

func TestTableEmptyAndDuplicateNames(t *testing.T) {
	t.Parallel()
	var table Table
	require.Equal(t, []int{0, 0, 1}, table.Update([]string{"", "", "b"}))
	name, loaded := table.Name(0)
	require.True(t, loaded, "an empty name is a valid user and must stay resolvable")
	require.Equal(t, "", name)
}
