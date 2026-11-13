package snell

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
)

type probeBufferConn struct {
	net.Conn
	buffer *bytes.Buffer
}

func (c *probeBufferConn) Read(p []byte) (int, error)    { return c.buffer.Read(p) }
func (c *probeBufferConn) Write(p []byte) (int, error)   { return c.buffer.Write(p) }
func (*probeBufferConn) SetReadDeadline(time.Time) error { return nil }

// Last-candidate lookup measures the linear worst case, without socket or
// client-handshake setup in the timed section.
func BenchmarkPSKLookup(b *testing.B) {
	for _, version := range []int{5, 6} {
		for _, count := range []int{1, 100, 1000} {
			b.Run(fmt.Sprintf("v%d/users%d", version, count), func(b *testing.B) {
				users := make([]option.SnellUser, count)
				for i := range users {
					users[i] = option.SnellUser{Name: fmt.Sprintf("user-%d", i), PSK: fmt.Sprintf("independent-psk-%d", i)}
				}
				in, err := NewInbound(context.Background(), nil, log.NewNOPFactory().NewLogger("bench"), "snell", option.SnellInboundOptions{Version: version, AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{UserPSK: true, Users: users}})
				if err != nil {
					b.Fatal(err)
				}
				h := in.(*Inbound)
				last := h.psk.ordered[count-1]
				var client snellprotocol.Method
				if version == 5 {
					client, err = snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(last.key)})
				} else {
					client, err = snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(last.key)})
				}
				if err != nil {
					b.Fatal(err)
				}
				wire := &probeBufferConn{buffer: new(bytes.Buffer)}
				if _, err = client.DialConn(wire, M.ParseSocksaddr("127.0.0.1:80")); err != nil {
					b.Fatal(err)
				}
				data := append([]byte(nil), wire.buffer.Bytes()...)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					entry, _, err := h.selectPSK(&probeBufferConn{buffer: bytes.NewBuffer(data)}, adapter.InboundContext{})
					if err != nil || entry != last {
						b.Fatal("PSK probe failed", err)
					}
				}
			})
		}
	}
}
