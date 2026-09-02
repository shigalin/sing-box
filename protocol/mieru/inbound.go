package mieru

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mierucommon "github.com/enfein/mieru/v3/apis/common"
	mieruconstant "github.com/enfein/mieru/v3/apis/constant"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
	mierutp "github.com/enfein/mieru/v3/apis/trafficpattern"
	mieruappctl "github.com/enfein/mieru/v3/pkg/appctl/appctlcommon"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	mierunet "github.com/enfein/mieru/v3/pkg/common"
	mierulog "github.com/enfein/mieru/v3/pkg/log"
	mieruprotocol "github.com/enfein/mieru/v3/pkg/protocol"
	"google.golang.org/protobuf/proto"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.MieruInboundOptions](registry, C.TypeMieru, NewInbound)
}

// disableMieruLog mirrors what mieru's own server API does on construction:
// mieru logs through its global logger, which would otherwise print to stderr.
var disableMieruLog = sync.OnceFunc(func() {
	mierulog.SetFormatter(&mierulog.NilFormatter{})
})

// Inbound drives mieru's server multiplexer directly instead of going through
// the apis/server wrapper: the wrapper only applies users at Start, while the
// multiplexer can take a new user set at runtime, which UpdateUsers needs.
type Inbound struct {
	inbound.Adapter
	ctx      context.Context
	router   adapter.ConnectionRouterEx
	logger   log.ContextLogger
	listener *listener.Listener
	mux      *mieruprotocol.Mux
	users    atomic.Pointer[map[string]bool]
	running  atomic.Bool

	mu sync.Mutex
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MieruInboundOptions) (adapter.Inbound, error) {
	mux, err := buildMieruMux(options)
	if err != nil {
		return nil, fmt.Errorf("failed to build mieru server: %w", err)
	}

	inboundInstance := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeMieru, tag),
		ctx:     ctx,
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		mux:     mux,
	}
	inboundInstance.setUsers(options.Users)
	inboundInstance.listener = listener.New(listener.Options{
		Context: ctx,
		Logger:  logger,
		Network: []string{N.NetworkTCP, N.NetworkUDP},
		Listen:  options.ListenOptions,
	})

	return inboundInstance, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if err := h.mux.Start(); err != nil {
		return fmt.Errorf("failed to start mieru server: %w", err)
	}
	h.running.Store(true)

	h.logger.Info("mieru server is started")
	go h.acceptLoop()
	return nil
}

func (h *Inbound) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.running.Store(false)
	// Close is idempotent and also stops the multiplexer's background cleaner,
	// which runs from construction, so close even if Start was never reached.
	return h.mux.Close()
}

func (h *Inbound) setUsers(users []option.MieruUser) {
	userSet := make(map[string]bool, len(users))
	for _, user := range users {
		userSet[user.Name] = true
	}
	h.users.Store(&userSet)
}

func (h *Inbound) hasUser(name string) bool {
	return (*h.users.Load())[name]
}

func (h *Inbound) acceptLoop() {
	for {
		conn, request, err := h.accept()
		if err != nil {
			if !h.running.Load() {
				return
			}
			h.logger.Debug("failed to accept mieru connection: ", err)
			continue
		}
		go h.handleConnection(conn, request)
	}
}

// accept waits for a proxy connection and reads its SOCKS5 request, the same
// way mieru's server API does before handing the connection to the caller.
func (h *Inbound) accept() (net.Conn, *mierumodel.Request, error) {
	conn, err := h.mux.Accept()
	if err != nil {
		return nil, nil, err
	}
	if _, ok := conn.(mierucommon.UserContext); !ok {
		conn.Close()
		return nil, nil, E.New("connection doesn't implement UserContext interface")
	}

	mierunet.SetReadTimeout(conn, 10*time.Second)
	request := &mierumodel.Request{}
	if err := request.ReadFromSocks5(conn); err != nil {
		conn.Close()
		return nil, nil, err
	}
	mierunet.SetReadTimeout(conn, 0)
	return conn, request, nil
}

func (h *Inbound) handleConnection(conn net.Conn, request *mierumodel.Request) {
	ctx := log.ContextWithNewID(h.ctx)

	// mieru authenticates a client once per underlay and keeps accepting
	// sessions on it after the user was removed, so every connection is
	// checked against the current user set.
	var userName string
	if userCtx, ok := conn.(mierucommon.UserContext); ok {
		userName = userCtx.UserName()
	}
	if !h.hasUser(userName) {
		conn.Close()
		h.logger.WarnContext(ctx, "reject connection from removed user")
		return
	}

	// Send fake SOCKS5 response back to proxy client.
	resp := &mierumodel.Response{
		Reply: mieruconstant.Socks5ReplySuccess,
		BindAddr: mierumodel.AddrSpec{
			IP:   net.IPv4zero,
			Port: 0,
		},
	}
	if err := resp.WriteToSocks5(conn); err != nil {
		conn.Close()
		h.logger.DebugContext(ctx, "failed to write mieru response: ", err)
		return
	}

	// Build metadata.
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	metadata.UDPDisableDomainUnmapping = h.listener.ListenOptions().UDPDisableDomainUnmapping

	// Parse source address.
	if remoteAddr := conn.RemoteAddr(); remoteAddr != nil {
		metadata.Source = M.SocksaddrFromNet(remoteAddr)
	}

	// Parse destination from request.
	if request.DstAddr.FQDN != "" {
		metadata.Destination = M.Socksaddr{
			Fqdn: request.DstAddr.FQDN,
			Port: uint16(request.DstAddr.Port),
		}
	} else if request.DstAddr.IP != nil {
		addr, _ := netip.AddrFromSlice(request.DstAddr.IP)
		metadata.Destination = M.Socksaddr{
			Addr: addr.Unmap(),
			Port: uint16(request.DstAddr.Port),
		}
	}

	metadata.User = userName

	// Handle request.
	switch request.Command {
	case mieruconstant.Socks5ConnectCmd:
		h.logger.InfoContext(ctx, "inbound TCP connection from ", metadata.Source, " to ", metadata.Destination)
		if metadata.User != "" {
			h.logger.InfoContext(ctx, "[", metadata.User, "] inbound TCP connection")
		}
		h.router.RouteConnectionEx(ctx, conn, metadata, nil)
	case mieruconstant.Socks5UDPAssociateCmd:
		h.logger.InfoContext(ctx, "inbound UDP connection from ", metadata.Source, " to ", metadata.Destination)
		if metadata.User != "" {
			h.logger.InfoContext(ctx, "[", metadata.User, "] inbound UDP connection")
		}
		h.handleUDP(ctx, conn, metadata)
	default:
		conn.Close()
		h.logger.WarnContext(ctx, "unsupported mieru command: ", request.Command)
	}
}

func (h *Inbound) handleUDP(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) {
	pc := mierucommon.NewPacketOverStreamTunnel(conn)
	packetConn := &mieruPacketConn{
		PacketConn:  pc,
		destination: metadata.Destination,
	}
	h.router.RoutePacketConnectionEx(ctx, packetConn, metadata, nil)
}

// mieruPacketConn wraps mieru's PacketConn to implement N.PacketConn
type mieruPacketConn struct {
	net.PacketConn
	destination M.Socksaddr
}

var _ N.PacketConn = (*mieruPacketConn)(nil)

// ReadPacket parses the SOCKS5 UDP header and returns the destination address.
func (c *mieruPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	n, _, err := c.PacketConn.ReadFrom(buffer.FreeBytes())
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	if buffer.Len() < 3 {
		return M.Socksaddr{}, io.ErrShortBuffer
	}

	// Skip RSV (2 bytes) and FRAG (1 byte).
	buffer.Advance(3)

	var addr mierumodel.AddrSpec
	if err := addr.ReadFromSocks5(buffer); err != nil {
		return M.Socksaddr{}, err
	}
	if addr.FQDN != "" {
		destination = M.Socksaddr{
			Fqdn: addr.FQDN,
			Port: uint16(addr.Port),
		}
	} else if addr.IP != nil {
		netAddr, _ := netip.AddrFromSlice(addr.IP)
		destination = M.Socksaddr{
			Addr: netAddr.Unmap(),
			Port: uint16(addr.Port),
		}
	}
	return destination, nil
}

// WritePacket writes the SOCKS5 UDP header and the payload.
func (c *mieruPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	header := buf.NewSize(3 + M.MaxSocksaddrLength)
	defer header.Release()

	// RSV (2 bytes) + FRAG (1 byte)
	common.Must(header.WriteZeroN(3))

	var addr mierumodel.AddrSpec
	if destination.IsFqdn() {
		addr.FQDN = destination.Fqdn
	} else {
		addr.IP = destination.Addr.AsSlice()
	}
	addr.Port = int(destination.Port)
	if err := addr.WriteToSocks5(header); err != nil {
		return err
	}

	packet := buf.NewSize(header.Len() + buffer.Len())
	defer packet.Release()
	common.Must1(packet.Write(header.Bytes()))
	common.Must1(packet.Write(buffer.Bytes()))
	_, err := c.PacketConn.WriteTo(packet.Bytes(), nil)
	return err
}

func buildMieruMux(options option.MieruInboundOptions) (*mieruprotocol.Mux, error) {
	if err := validateMieruInboundOptions(options); err != nil {
		return nil, fmt.Errorf("failed to validate mieru options: %w", err)
	}

	var transportProtocol *mierupb.TransportProtocol
	switch options.Transport {
	case "TCP":
		transportProtocol = mierupb.TransportProtocol_TCP.Enum()
	case "UDP":
		transportProtocol = mierupb.TransportProtocol_UDP.Enum()
	}

	if options.ListenOptions.ListenPort == 0 {
		return nil, E.New("listen_port must be set")
	}
	portBindings := []*mierupb.PortBinding{
		{
			Port:     proto.Int32(int32(options.ListenOptions.ListenPort)),
			Protocol: transportProtocol,
		},
	}
	endpoints, err := mieruappctl.PortBindingsToUnderlayProperties(portBindings, mierunet.DefaultMTU)
	if err != nil {
		return nil, err
	}

	// Already validated above; Decode of an empty pattern yields nil, which
	// NewConfig treats as the default pattern.
	trafficPatternPB, _ := mierutp.Decode(options.TrafficPattern)
	trafficPattern, err := mierutp.NewConfig(trafficPatternPB)
	if err != nil {
		return nil, fmt.Errorf("invalid traffic pattern: %w", err)
	}

	disableMieruLog()
	mux := mieruprotocol.NewMux(false)
	mux.SetTrafficPattern(trafficPattern)
	mux.SetServerUsers(buildMieruUsers(options.Users))
	mux.SetEndpoints(endpoints)
	return mux, nil
}

func buildMieruUsers(users []option.MieruUser) map[string]*mierupb.User {
	userMap := make(map[string]*mierupb.User, len(users))
	for _, user := range users {
		userMap[user.Name] = &mierupb.User{
			Name:     proto.String(user.Name),
			Password: proto.String(user.Password),
		}
	}
	return userMap
}

func validateMieruInboundOptions(options option.MieruInboundOptions) error {
	if options.Transport != "TCP" && options.Transport != "UDP" {
		return E.New("transport must be TCP or UDP")
	}
	if len(options.Users) == 0 {
		return E.New("users is empty")
	}
	if err := validateMieruUsers(options.Users); err != nil {
		return err
	}
	if options.TrafficPattern != "" {
		trafficPattern, err := mierutp.Decode(options.TrafficPattern)
		if err != nil {
			return fmt.Errorf("failed to decode traffic pattern %q: %w", options.TrafficPattern, err)
		}
		if err := mierutp.Validate(trafficPattern); err != nil {
			return fmt.Errorf("invalid traffic pattern %q: %w", options.TrafficPattern, err)
		}
	}
	return nil
}

func validateMieruUsers(users []option.MieruUser) error {
	for _, user := range users {
		if user.Name == "" {
			return E.New("username is empty")
		}
		if user.Password == "" {
			return E.New("password is empty")
		}
	}
	return nil
}
