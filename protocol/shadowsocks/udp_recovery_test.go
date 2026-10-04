package shadowsocks

import (
	"github.com/daeuniverse/outbound/netproxy"
	"testing"
)

type recoveryUnderlay struct {
	netproxy.PacketConn
	caps netproxy.PacketRecoveryCapabilities
}

func (c *recoveryUnderlay) PacketRecoveryCapabilities() netproxy.PacketRecoveryCapabilities {
	return c.caps
}

func TestPacketRecoveryDoesNotPromoteQueueOrSharedUnderlay(t *testing.T) {
	for _, caps := range []netproxy.PacketRecoveryCapabilities{{}, {LocalWriteCompleted: true}, {IndependentAssociation: true}, {LocalWriteCompleted: true, IndependentAssociation: true}} {
		c := &UdpConn{PacketConn: &recoveryUnderlay{caps: caps}}
		got := netproxy.RecoveryCapabilities(c)
		if got.LocalWriteCompleted != caps.LocalWriteCompleted || got.IndependentAssociation != caps.IndependentAssociation || !got.ApplicationPeer || !got.AddressedWrites {
			t.Fatalf("wrapper expanded underlay promise: %+v", got)
		}
	}
}
