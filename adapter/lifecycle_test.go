package adapter

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

type testLifecycle struct {
	closed int
}

func (l *testLifecycle) Start(stage StartStage, scope *Scope) error {
	scope.Add(func() error {
		l.closed++
		return nil
	})
	return nil
}

// CloseChild closes one component and leaves nothing of it in the parent, so
// that components which come and go do not accumulate there.
func TestScopeCloseChild(t *testing.T) {
	scope := NewScope(context.Background(), log.NewNOPFactory().Logger())
	kept := &testLifecycle{}
	require.NoError(t, scope.Start("kept", kept, StartStateStart))
	for range 3 {
		removed := &testLifecycle{}
		require.NoError(t, scope.Start("removed", removed, StartStateStart))
		require.NoError(t, scope.CloseChild(removed))
		require.Equal(t, 1, removed.closed)
		require.NoError(t, scope.CloseChild(removed))
		require.Equal(t, 1, removed.closed)
	}
	require.Len(t, scope.cleanups, 1)
	require.Len(t, scope.children, 1)
	require.Zero(t, kept.closed)
	require.NoError(t, scope.Close())
	require.Equal(t, 1, kept.closed)
}
