package shadowsocks_2022

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
)

// recoveryUnderlay is both a net.Conn (what UdpConn embeds) and a packet
// transport with a declared promise, like the direct UDP socket.
type recoveryUnderlay struct {
	net.Conn
	caps netproxy.PacketRecoveryCapabilities
}

func (c *recoveryUnderlay) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, nil
}
func (c *recoveryUnderlay) WriteTo(p []byte, addr string) (int, error) { return len(p), nil }

func (c *recoveryUnderlay) PacketRecoveryCapabilities() netproxy.PacketRecoveryCapabilities {
	return c.caps
}

func TestPacketRecoveryDoesNotPromoteQueueOrSharedUnderlay(t *testing.T) {
	for _, caps := range []netproxy.PacketRecoveryCapabilities{{}, {LocalWriteCompleted: true}, {IndependentAssociation: true}, {LocalWriteCompleted: true, IndependentAssociation: true}} {
		c := &UdpConn{Conn: &recoveryUnderlay{caps: caps}}
		for name, conn := range map[string]netproxy.PacketConn{"udp_conn": c, "dial_wrapper": &FakeNetPacketConn{PacketConn: c}} {
			got := netproxy.RecoveryCapabilities(conn)
			if got.LocalWriteCompleted != caps.LocalWriteCompleted || got.IndependentAssociation != caps.IndependentAssociation || !got.ApplicationPeer || !got.AddressedWrites {
				t.Fatalf("%s expanded or dropped underlay promise %+v: %+v", name, caps, got)
			}
		}
	}
}

// A net.Conn underlay that is not a packet transport makes no recovery
// promise; the session layer alone must not create one.
func TestPacketRecoveryNonPacketUnderlay(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	got := netproxy.RecoveryCapabilities(&UdpConn{Conn: a})
	if got.LocalWriteCompleted || got.IndependentAssociation {
		t.Fatalf("non-packet underlay promised recovery: %+v", got)
	}
}

// The dialer path used by dae: a direct UDP underlay through the SS2022
// dialer's FakeNetPacketConn must carry the direct socket's promise.
func TestPacketRecoveryThroughDialer(t *testing.T) {
	for _, cipher := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		keyLen := 32
		if cipher == "2022-blake3-aes-128-gcm" {
			keyLen = 16
		}
		d, err := NewDialer(direct.FullconeDirect, protocol.Header{IsClient: true, ProxyAddress: "127.0.0.1:9", Cipher: cipher, Password: pskBase64(keyLen, 0x22)})
		if err != nil {
			t.Fatal(err)
		}
		conn, err := d.DialContext(context.Background(), "udp", "192.0.2.1:27015")
		if err != nil {
			t.Fatal(err)
		}
		got := netproxy.RecoveryCapabilities(conn.(netproxy.PacketConn))
		_ = conn.Close()
		if !got.LocalWriteCompleted || !got.IndependentAssociation || !got.AddressedWrites || !got.ApplicationPeer {
			t.Fatalf("%s dial lost the direct UDP promise: %+v", cipher, got)
		}
	}
}
