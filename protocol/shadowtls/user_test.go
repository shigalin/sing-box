package shadowtls

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/usertable"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type completionRouter struct {
	adapter.Router
	conn    net.Conn
	onClose N.CloseHandlerFunc
}

func (r *completionRouter) RouteConnectionEx(_ context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.conn, r.onClose = conn, onClose
}

// Some downstream protocols finish through onClose after closing or unwrapping
// the transport. Registration must not depend on calling the outer Conn.Close.
func TestUserConnectionCompletionCleansRegistration(t *testing.T) {
	for _, completionErr := range []error{nil, errors.New("downstream failed")} {
		name := "success"
		if completionErr != nil {
			name = "failure"
		}
		t.Run(name, func(t *testing.T) {
			router := &completionRouter{}
			h := &Inbound{
				Adapter:       inbound.NewAdapter(C.TypeShadowTLS, "shadowtls-in"),
				router:        router,
				logger:        log.NewNOPFactory().NewLogger("test"),
				listener:      listener.New(listener.Options{Listen: option.ListenOptions{Detour: "snell-in"}}),
				serviceConfig: &shadowtls.ServiceConfig{},
				conns:         make(map[*userConn]struct{}),
			}
			id := h.users.Update([]usertable.User{{Key: "alice", Name: "alice"}})[0]
			for i := 0; i < 3; i++ {
				local, peer := net.Pipe()
				t.Cleanup(func() { local.Close(); peer.Close() })
				called := 0
				ctx := auth.ContextWithUser(context.Background(), strconv.Itoa(id))
				(*inboundHandler)(h).NewConnectionEx(ctx, local, M.Socksaddr{}, M.Socksaddr{}, func(err error) {
					called++
					require.Equal(t, completionErr, err)
					h.connAccess.Lock()
					remaining := len(h.conns)
					h.connAccess.Unlock()
					require.Zero(t, remaining, "cleanup must precede the parent callback")
				})
				require.NotNil(t, router.onClose)
				h.connAccess.Lock()
				registered := len(h.conns)
				h.connAccess.Unlock()
				require.Equal(t, 1, registered)
				router.onClose(completionErr)
				require.Equal(t, 1, called)
				peer.SetReadDeadline(time.Now().Add(time.Second))
				_, err := peer.Read(make([]byte, 1))
				require.ErrorIs(t, err, io.EOF)
			}
		})
	}
}

func TestUserConnectionCompletionRacesWithRevocation(t *testing.T) {
	router := &completionRouter{}
	h := &Inbound{
		Adapter:       inbound.NewAdapter(C.TypeShadowTLS, "shadowtls-in"),
		router:        router,
		logger:        log.NewNOPFactory().NewLogger("test"),
		listener:      listener.New(listener.Options{}),
		serviceConfig: &shadowtls.ServiceConfig{},
		conns:         make(map[*userConn]struct{}),
	}
	id := h.users.Update([]usertable.User{{Key: "alice", Name: "alice"}})[0]
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	(*inboundHandler)(h).NewConnectionEx(auth.ContextWithUser(context.Background(), strconv.Itoa(id)), local, M.Socksaddr{}, M.Socksaddr{}, nil)
	require.NotNil(t, router.onClose, "a nil parent must still install cleanup")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		h.users.Update(nil)
		h.closeRemovedUsers()
	}()
	go func() {
		defer wg.Done()
		router.onClose(nil)
		router.conn.Close()
	}()
	wg.Wait()
	h.connAccess.Lock()
	remaining := len(h.conns)
	h.connAccess.Unlock()
	require.Zero(t, remaining)
}
