package netproxy

import "testing"

func TestPacketRecoveryMissingDeclarationFailsClosed(t *testing.T) {
	if got := RecoveryCapabilities(&fakePacketConnForLifecycle{}); got != (PacketRecoveryCapabilities{}) {
		t.Fatalf("invented capability: %+v", got)
	}
}
