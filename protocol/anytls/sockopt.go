package anytls

import (
	"net"
	"syscall"
	"time"
)

const (
	defaultTCPNotSentLowat  = 16384
	defaultTCPUserTimeoutMs = 15000
	defaultTCPKeepAlive     = 15 * time.Second
)

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

// tuneTCPCarrierConn configures low-latency and fast-blackhole-detection socket
// options on the underlying carrier TCP socket (best effort on Linux;
// TCP_NOTSENT_LOWAT and TCP_USER_TIMEOUT are no-ops elsewhere):
//   - TCP_NOTSENT_LOWAT=16KiB prevents slow streams from bloating the kernel
//     send queue ahead of faster multiplexed streams.
//   - TCP_USER_TIMEOUT=15s bounds unacknowledged retransmission hangs on
//     silently blackholed WAN/NAT paths instead of waiting ~15m (tcp_retries2).
//   - TCP keepalive=15s helps surface dead idle carriers promptly.
func tuneTCPCarrierConn(conn net.Conn) {
	if tc := extractTCPConn(conn); tc != nil {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(defaultTCPKeepAlive)
	}
	sc := extractSyscallConn(conn)
	if sc == nil {
		return
	}
	raw, err := sc.SyscallConn()
	if err != nil || raw == nil {
		return
	}
	_ = setTCPNotSentLowat(raw, defaultTCPNotSentLowat)
	_ = setTCPUserTimeout(raw, defaultTCPUserTimeoutMs)
}

func extractTCPConn(conn net.Conn) *net.TCPConn {
	for depth := 0; depth < 8 && conn != nil; depth++ {
		if tc, ok := conn.(*net.TCPConn); ok {
			return tc
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
