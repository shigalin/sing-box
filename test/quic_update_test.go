//go:build with_quic

package main

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type quicAuthHandler struct{ users chan int }

func (h *quicAuthHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	user, ok := auth.UserFromContext[int](ctx)
	if !ok {
		user = -1
	}
	h.users <- user
	var b [1]byte
	if _, err := io.ReadFull(conn, b[:]); err == nil {
		conn.Write(b[:])
	}
}
func (h *quicAuthHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
	panic("unexpected UDP")
}

type quicUpdateClient interface {
	DialConn(context.Context, M.Socksaddr) (net.Conn, error)
	CloseWithError(error) error
}

func TestQUICConcurrentUserUpdate(t *testing.T) {
	for _, protocol := range []string{"hysteria", "hysteria2", "tuic"} {
		t.Run(protocol, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			logger := log.NewNOPFactory().Logger()
			_, cert, key := createSelfSignedCertificate(t, "example.org")
			serverTLS, err := tls.NewServer(ctx, logger, option.InboundTLSOptions{Enabled: true, CertificatePath: cert, KeyPath: key})
			require.NoError(t, err)
			require.NoError(t, serverTLS.Start())
			defer serverTLS.Close()
			clientTLS, err := tls.NewClient(ctx, logger, "example.org", option.OutboundTLSOptions{Enabled: true, ServerName: "example.org", CertificatePath: cert})
			require.NoError(t, err)
			socket, err := net.ListenPacket("udp", "127.0.0.1:0")
			require.NoError(t, err)
			defer socket.Close()
			addr := M.SocksaddrFromNet(socket.LocalAddr())
			handler := &quicAuthHandler{users: make(chan int, 1)}
			ids := [][16]byte{{1}, {2}}
			var update func(bool)
			var newClient func() (quicUpdateClient, error)
			switch protocol {
			case "hysteria":
				s, e := hysteria.NewService[int](hysteria.ServiceOptions{Context: ctx, Logger: logger, TLSConfig: serverTLS, Handler: handler, SendBPS: 10000000, ReceiveBPS: 10000000, UDPDisabled: true})
				require.NoError(t, e)
				update = func(keep bool) {
					if keep {
						s.UpdateUsers([]int{1, 2}, []string{"alice", "bob"})
					} else {
						s.UpdateUsers([]int{2}, []string{"bob"})
					}
				}
				update(true)
				require.NoError(t, s.Start(socket))
				defer s.Close()
				newClient = func() (quicUpdateClient, error) {
					return hysteria.NewClient(hysteria.ClientOptions{Context: ctx, Logger: logger, Dialer: N.SystemDialer, ServerAddress: addr, TLSConfig: clientTLS, Password: "alice", SendBPS: 10000000, ReceiveBPS: 10000000, UDPDisabled: true})
				}
			case "hysteria2":
				s, e := hysteria2.NewService[int](hysteria2.ServiceOptions{Context: ctx, Logger: logger, TLSConfig: serverTLS, Handler: handler, UDPDisabled: true})
				require.NoError(t, e)
				update = func(keep bool) {
					if keep {
						s.UpdateUsers([]int{1, 2}, []string{"alice", "bob"})
					} else {
						s.UpdateUsers([]int{2}, []string{"bob"})
					}
				}
				update(true)
				require.NoError(t, s.Start(socket))
				defer s.Close()
				newClient = func() (quicUpdateClient, error) {
					return hysteria2.NewClient(hysteria2.ClientOptions{Context: ctx, Logger: logger, Dialer: N.SystemDialer, ServerAddress: addr, TLSConfig: clientTLS, Password: "alice", UDPDisabled: true})
				}
			case "tuic":
				s, e := tuic.NewService[int](tuic.ServiceOptions{Context: ctx, Logger: logger, TLSConfig: serverTLS, Handler: handler, AuthTimeout: time.Second * 5})
				require.NoError(t, e)
				update = func(keep bool) {
					if keep {
						s.UpdateUsers([]int{1, 2}, ids, []string{"alice", "bob"})
					} else {
						s.UpdateUsers([]int{2}, ids[1:], []string{"bob"})
					}
				}
				update(true)
				require.NoError(t, s.Start(socket))
				defer s.Close()
				newClient = func() (quicUpdateClient, error) {
					return tuic.NewClient(tuic.ClientOptions{Context: ctx, Dialer: N.SystemDialer, ServerAddress: addr, TLSConfig: clientTLS, UUID: ids[0], Password: "alice"})
				}
			}
			exchange := func() error {
				client, e := newClient()
				if e != nil {
					return e
				}
				defer client.CloseWithError(net.ErrClosed)
				dialCtx, stop := context.WithTimeout(ctx, 5*time.Second)
				defer stop()
				conn, e := client.DialConn(dialCtx, M.ParseSocksaddr("127.0.0.1:80"))
				if e != nil {
					return e
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				if _, e = conn.Write([]byte{42}); e != nil {
					return e
				}
				var reply [1]byte
				_, e = io.ReadFull(conn, reply[:])
				if e == nil && reply[0] != 42 {
					return io.ErrUnexpectedEOF
				}
				return e
			}
			stop, done := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(done)
				for {
					select {
					case <-stop:
						return
					default:
						update(true)
					}
				}
			}()
			// Join even when an assertion fails; the updater must never outlive the service.
			stopped := false
			defer func() {
				if !stopped {
					close(stop)
					<-done
				}
			}()
			for i := 0; i < 20; i++ {
				require.NoError(t, exchange())
				select {
				case user := <-handler.users:
					require.Equal(t, 1, user)
				default:
					t.Fatal("authenticated connection was not routed")
				}
			}
			close(stop)
			<-done
			stopped = true
			update(false)
			require.Error(t, exchange(), "removed user must fail on a fresh QUIC connection")
			select {
			case <-handler.users:
				t.Fatal("removed user reached handler")
			default:
			}
		})
	}
}
