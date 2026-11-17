package anytls

import (
	"net"
	"syscall"
)

const defaultTCPNotSentLowat = 16384

type underlyingConnProvider interface {
	UnderlyingConn() net.Conn
}

type netConnProvider interface {
	NetConn() net.Conn
}

type unwrapConnProvider interface {
	Unwrap() net.Conn
}

func extractSyscallConn(conn net.Conn) syscall.Conn {
	for depth := 0; depth < 8 && conn != nil; depth++ {
		if sc, ok := conn.(syscall.Conn); ok {
			return sc
		}
		switch wrapped := conn.(type) {
		case underlyingConnProvider:
			conn = wrapped.UnderlyingConn()
		case netConnProvider:
			conn = wrapped.NetConn()
		case unwrapConnProvider:
			conn = wrapped.Unwrap()
		default:
			return nil
		}
	}
	return nil
}

// tuneTCPCarrierConn configures TCP_NOTSENT_LOWAT on the underlying carrier
// TCP socket (best effort on Linux; no-op elsewhere) so buffered slow streams
// cannot bloat the kernel send queue ahead of faster multiplexed streams.
func tuneTCPCarrierConn(conn net.Conn) {
	sc := extractSyscallConn(conn)
	if sc == nil {
		return
	}
	raw, err := sc.SyscallConn()
	if err != nil || raw == nil {
		return
	}
	_ = setTCPNotSentLowat(raw, defaultTCPNotSentLowat)
}
