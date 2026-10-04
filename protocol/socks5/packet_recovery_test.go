package socks5

import (
	"github.com/daeuniverse/outbound/netproxy"
	"testing"
)

type recoveryTestUnderlay struct {
	netproxy.PacketConn
	caps netproxy.PacketRecoveryCapabilities
}

func (c *recoveryTestUnderlay) PacketRecoveryCapabilities() netproxy.PacketRecoveryCapabilities {
	return c.caps
}
func TestPacketRecoveryRequiresLocalCompletionAndFreshControl(t *testing.T) {
	for _, local := range []bool{false, true} {
		for _, independent := range []bool{false, true} {
			for _, control := range []bool{false, true} {
				underlay := &recoveryTestUnderlay{caps: netproxy.PacketRecoveryCapabilities{LocalWriteCompleted: local, IndependentAssociation: independent}}
				c := &PktConn{PacketConn: underlay}
				if control {
					c.ctrlConn = underlay
				}
				caps := netproxy.RecoveryCapabilities(c)
				if caps.LocalWriteCompleted != local || caps.IndependentAssociation != (independent && control) || !caps.AddressedWrites || !caps.ApplicationPeer {
					t.Fatalf("expanded recovery promise: %+v", caps)
				}
			}
		}
	}
}
