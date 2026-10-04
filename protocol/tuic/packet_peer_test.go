package tuic

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

func TestQUICPacketPeerSurvivesNATIdentity(t *testing.T) {
	for _, push := range []bool{false, true} {
		for _, fragmented := range []bool{false, true} {
			packets := NewPackets()
			hint := netip.MustParseAddrPort("28.0.0.1:27015")
			q := &quicStreamPacketConn{incomingPackets: packets, natIdentity: hint}
			var gotFrom, gotPeer netip.AddrPort
			var gotData string
			if push {
				stop, ok := q.RegisterPacketReceiver(func(p *netproxy.ReceivedPacket) bool {
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
				peer, _ := netip.ParseAddrPort(target)
				addr := NewAddressAddrPort(peer)
				if !peer.IsValid() {
					addr = &Address{TYPE: AtypDomainName, ADDR: append([]byte{13}, []byte("relay.example")...), PORT: 27015}
				}
				count := 1
				if fragmented {
					count = 2
				}
				for part := 0; part < count; part++ {
					partAddr := addr
					if part > 0 {
						partAddr = &Address{TYPE: AtypNone}
					}
					packets.PushBack(&Packet{PKT_ID: uint16(i), FRAG_TOTAL: uint8(count), FRAG_ID: uint8(part), ADDR: partAddr, DATA: []byte("x")})
				}
				if !push {
					buf := make([]byte, 8)
					n, from, actual, err := q.ReadFromWithPeer(buf)
					if err != nil {
						t.Fatal(err)
					}
					gotFrom, gotPeer, gotData = from, actual, string(buf[:n])
				}
				if gotFrom != hint || gotPeer != peer || len(gotData) != count {
					t.Fatalf("push=%v fragments=%v target=%s: from=%s peer=%s data=%q", push, fragmented, target, gotFrom, gotPeer, gotData)
				}
			}
			_ = q.Close()
		}
	}
}
