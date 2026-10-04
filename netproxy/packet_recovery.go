package netproxy

// PacketRecoveryCapabilities describes the actual connection, including its
// wrapping transports. A missing declaration is deliberately unsupported.
// IndependentAssociation promises a fresh association on a new DialContext;
// it does not promise a different externally visible NAT port.
type PacketRecoveryCapabilities struct {
	LocalWriteCompleted    bool
	IndependentAssociation bool
	AddressedWrites        bool
	ApplicationPeer        bool
}

type PacketRecoveryProvider interface {
	PacketRecoveryCapabilities() PacketRecoveryCapabilities
}

func RecoveryCapabilities(conn PacketConn) PacketRecoveryCapabilities {
	if provider, ok := conn.(PacketRecoveryProvider); ok {
		return provider.PacketRecoveryCapabilities()
	}
	return PacketRecoveryCapabilities{}
}
