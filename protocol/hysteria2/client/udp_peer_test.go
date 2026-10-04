package client

import (
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

func TestUDPConnPeerSurvivesNATIdentity(t *testing.T) {
	for _, push := range []bool{false, true} {
		for _, fragmented := range []bool{false, true} {
			m := &udpSessionManager{io: noopUDPTestIO{}, m: make(map[uint32]*udpConn), done: make(chan struct{})}
			hint := netip.MustParseAddrPort("28.0.0.1:27015")
			conn, err := m.openUDP("192.0.2.1:27015", hint)
			if err != nil {
				t.Fatal(err)
			}
			u := conn.(*udpConn)
			var released atomic.Int32
			var gotFrom, gotPeer netip.AddrPort
			var gotData string
			if push {
				stop, ok := u.RegisterPacketReceiver(func(p *netproxy.ReceivedPacket) bool {
					gotFrom, gotPeer, gotData = p.From, p.Peer, string(p.Data)
					p.Release()
					return true
				})
				if !ok {
					t.Fatal("receiver registration")
				}
				defer stop()
			}
			for i, target := range []string{"192.0.2.1:27015", "192.0.2.2:27015", "relay.example:27015"} {
				count := 1
				if fragmented {
					count = 2
				}
				for part := 0; part < count; part++ {
					msg := &protocol.UDPMessage{PacketID: uint16(i), FragID: uint8(part), FragCount: uint8(count), Addr: []byte(target), Data: []byte("x"), Release: func() { released.Add(1) }}
					if push {
						u.deliverMessage(msg)
					} else {
						u.ReceiveCh <- msg
					}
				}
				if !push {
					buf := make([]byte, 8)
					n, from, peer, err := u.ReadFromWithPeer(buf)
					if err != nil {
						t.Fatal(err)
					}
					gotFrom, gotPeer, gotData = from, peer, string(buf[:n])
				}
				want, _ := netip.ParseAddrPort(target)
				if gotFrom != hint || gotPeer != want || len(gotData) != count {
					t.Fatalf("push=%v fragments=%v target=%s: from=%s peer=%s data=%q", push, fragmented, target, gotFrom, gotPeer, gotData)
				}
			}
			wantRelease := int32(3)
			if fragmented {
				wantRelease *= 2
			}
			if released.Load() != wantRelease {
				t.Fatalf("releases=%d want=%d", released.Load(), wantRelease)
			}
			m.close(u)
		}
	}
}
