package coalesce

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// nopParityConn is the minimal base Conn the capability sentinel embeds.
type nopParityConn struct{}

func (nopParityConn) Read([]byte) (int, error)         { return 0, nil }
func (nopParityConn) Write([]byte) (int, error)        { return 0, nil }
func (nopParityConn) Close() error                     { return nil }
func (nopParityConn) SetDeadline(time.Time) error      { return nil }
func (nopParityConn) SetReadDeadline(time.Time) error  { return nil }
func (nopParityConn) SetWriteDeadline(time.Time) error { return nil }

// paritySentinelConn implements every optional capability FlushConn may be
// asked to forward; the gate only inspects method sets and the peel
// convention, so the methods never run.
type paritySentinelConn struct{ netproxy.Conn }

func (paritySentinelConn) IntrinsicConn() netproxy.Conn     { return nil }
func (paritySentinelConn) UnderlyingConn() net.Conn         { return nil }
func (paritySentinelConn) CloseWrite() error                { return nil }
func (paritySentinelConn) WriteDeadlineClosesSession() bool { return true }
func (paritySentinelConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, nil
}
func (paritySentinelConn) WriteTo([]byte, string) (int, error) { return 0, nil }
func (paritySentinelConn) WriteBatch([]netproxy.BatchItem) (int, error) {
	return 0, nil
}
func (paritySentinelConn) RegisterPacketReceiver(netproxy.PacketReceiveHandler) (func(), bool) {
	return nil, false
}
func (paritySentinelConn) LocalAddr() net.Addr  { return nil }
func (paritySentinelConn) RemoteAddr() net.Addr { return nil }

// TestFlushConnCapabilityParity gates the bug class where FlushConn (or any
// future wrapper installed by this package) hides an optional capability the
// concrete TLS conn carried: embedding the Conn interface only promotes the
// base method set, and a missing forward is not a compile error.
func TestFlushConnCapabilityParity(t *testing.T) {
	inner := paritySentinelConn{Conn: nopParityConn{}}
	wrapped := NewFlushConn(inner, nil)
	if got := netproxy.MissingCapabilities(wrapped, inner); len(got) != 0 {
		t.Fatalf("FlushConn hides capabilities %v; forward them or implement IntrinsicConnProvider", got)
	}
}
