package shadowsocks

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/uot"
	"github.com/sagernet/sing-box/common/usertable"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

var (
	_ adapter.TCPInjectableInbound = (*MultiInbound)(nil)
	_ adapter.ManagedSSMServer     = (*MultiInbound)(nil)
)

type MultiInbound struct {
	inbound.Adapter
	ctx      context.Context
	router   adapter.ConnectionRouterEx
	logger   logger.ContextLogger
	listener *listener.Listener
	service  shadowsocks.MultiService[int]
	users    usertable.Table
	// updateAccess serializes UpdateUsers, which must roll the service back
	// to the last accepted user set (userIDs, userPSKs) if an update fails.
	updateAccess sync.Mutex
	userIDs      []int
	userPSKs     []string
	tracker      adapter.SSMTracker
}

func newMultiInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowsocksInboundOptions) (*MultiInbound, error) {
	inbound := &MultiInbound{
		Adapter: inbound.NewAdapter(C.TypeShadowsocks, tag),
		ctx:     ctx,
		router:  uot.NewRouter(router, logger),
		logger:  logger,
	}
	var err error
	inbound.router, err = mux.NewRouterWithOptions(inbound.router, logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	var service shadowsocks.MultiService[int]
	if common.Contains(shadowaead_2022.List, options.Method) {
		service, err = shadowaead_2022.NewMultiServiceWithPassword[int](
			options.Method,
			options.Password,
			int64(udpTimeout.Seconds()),
			adapter.NewLegacyUpstreamHandler(adapter.InboundContext{}, inbound.newConnection, inbound.newPacketConnection, inbound),
			ntp.TimeFuncFromContext(ctx),
		)
	} else if common.Contains(shadowaead.List, options.Method) {
		service, err = shadowaead.NewMultiService[int](
			options.Method,
			int64(udpTimeout.Seconds()),
			adapter.NewLegacyUpstreamHandler(adapter.InboundContext{}, inbound.newConnection, inbound.newPacketConnection, inbound),
		)
	} else {
		return nil, E.New("unsupported method: " + options.Method)
	}
	if err != nil {
		return nil, err
	}
	inbound.service = service
	if len(options.Users) > 0 {
		err = inbound.UpdateUsersByOptions(options.Users)
		if err != nil {
			return nil, err
		}
	}
	inbound.listener = listener.New(listener.Options{
		Context:                  ctx,
		Logger:                   logger,
		Network:                  options.Network.Build(),
		Listen:                   options.ListenOptions,
		ConnectionHandler:        inbound,
		PacketHandler:            inbound,
		ThreadUnsafePacketWriter: true,
	})
	return inbound, err
}

func (h *MultiInbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return h.listener.Start()
}

func (h *MultiInbound) Close() error {
	return h.listener.Close()
}

func (h *MultiInbound) SetTracker(tracker adapter.SSMTracker) {
	h.tracker = tracker
}

func (h *MultiInbound) UpdateUsers(users []string, uPSKs []string) error {
	if len(users) != len(uPSKs) {
		return E.New("user and password count mismatch")
	}
	userEntryList := make([]usertable.User, 0, len(users))
	for i, user := range users {
		userEntryList = append(userEntryList, usertable.User{Key: usertable.Key(user, uPSKs[i]), Name: user})
	}
	h.updateAccess.Lock()
	defer h.updateAccess.Unlock()
	state := h.users.Save()
	userIDs := h.users.Update(userEntryList)
	err := h.service.UpdateUsersWithPasswords(userIDs, uPSKs)
	if err != nil {
		// The service may have applied part of the new set before it
		// rejected a password: put the last accepted set back, together with
		// the user table that matches it.
		h.users.Restore(state)
		if rollbackErr := h.service.UpdateUsersWithPasswords(h.userIDs, h.userPSKs); rollbackErr != nil {
			h.logger.Error(E.Cause(rollbackErr, "restore users after failed update"))
		}
		return err
	}
	h.userIDs = userIDs
	h.userPSKs = uPSKs
	return nil
}

//nolint:staticcheck
func (h *MultiInbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	err := h.service.NewConnection(ctx, conn, adapter.UpstreamMetadata(metadata))
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil {
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
		}
	}
}

//nolint:staticcheck
func (h *MultiInbound) NewPacket(buffer *buf.Buffer, source M.Socksaddr) {
	err := h.service.NewPacket(h.ctx, &stubPacketConn{h.listener.PacketWriter()}, buffer, M.Metadata{Source: source})
	if err != nil {
		h.logger.Error(E.Cause(err, "process packet from ", source))
	}
}

func (h *MultiInbound) newConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	userID, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		return os.ErrInvalid
	}
	user, loaded := h.users.Name(userID)
	if !loaded {
		return E.New("user removed")
	}
	if user == "" {
		user = F.ToString(userID)
	} else {
		metadata.User = user
	}
	h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	if h.tracker != nil {
		conn = h.tracker.TrackConnection(conn, metadata)
	}
	return h.router.RouteConnection(ctx, conn, metadata)
}

func (h *MultiInbound) newPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	userID, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		return os.ErrInvalid
	}
	user, loaded := h.users.Name(userID)
	if !loaded {
		return E.New("user removed")
	}
	if user == "" {
		user = F.ToString(userID)
	} else {
		metadata.User = user
	}
	ctx = log.ContextWithNewID(ctx)
	h.logger.InfoContext(ctx, "[", user, "] inbound packet connection from ", metadata.Source)
	h.logger.InfoContext(ctx, "[", user, "] inbound packet connection to ", metadata.Destination)
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	if h.tracker != nil {
		conn = h.tracker.TrackPacketConnection(conn, metadata)
	}
	return h.router.RoutePacketConnection(ctx, conn, metadata)
}

//nolint:staticcheck
func (h *MultiInbound) NewError(ctx context.Context, err error) {
	NewError(h.logger, ctx, err)
}
