package netproxy

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// nopParityConn is the minimal base Conn the capability sentinel embeds.
type nopParityConn struct{}

func (nopParityConn) Read([]byte) (int, error)         { return 0, nil }
func (nopParityConn) Write([]byte) (int, error)        { return 0, nil }
func (nopParityConn) Close() error                     { return nil }
func (nopParityConn) SetDeadline(time.Time) error      { return nil }
func (nopParityConn) SetReadDeadline(time.Time) error  { return nil }
func (nopParityConn) SetWriteDeadline(time.Time) error { return nil }

// paritySentinelConn implements every optional capability a wrapper may be
// asked to forward. Its methods never run: the gate only inspects method sets
// and the peel convention.
type paritySentinelConn struct{ Conn }

func (paritySentinelConn) IntrinsicConn() Conn              { return nil }
func (paritySentinelConn) UnderlyingConn() net.Conn         { return nil }
func (paritySentinelConn) CloseWrite() error                { return nil }
func (paritySentinelConn) WriteDeadlineClosesSession() bool { return true }
func (paritySentinelConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, nil
}
func (paritySentinelConn) WriteTo([]byte, string) (int, error) { return 0, nil }
func (paritySentinelConn) WriteBatch([]BatchItem) (int, error) { return 0, nil }
func (paritySentinelConn) RegisterPacketReceiver(PacketReceiveHandler) (func(), bool) {
	return nil, false
}
func (paritySentinelConn) LocalAddr() net.Addr  { return nil }
func (paritySentinelConn) RemoteAddr() net.Addr { return nil }

// TestWrapperCapabilityParity is the regression gate for the bug class where
// a wrapper embeds the Conn interface and thereby hides optional capabilities
// the concrete inner conn carried (a missing forward is not a compile error).
// Every wrapper this package installs must be registered here; new wrappers
// fail this test until they forward the capabilities or expose
// IntrinsicConnProvider.
func TestWrapperCapabilityParity(t *testing.T) {
	inner := paritySentinelConn{Conn: nopParityConn{}}
	wrappers := []struct {
		name string
		wrap func(Conn) Conn
	}{
		{"ForceBufferedReaderConn", func(c Conn) Conn { return ForceBufferedReaderConn(c, 0) }},
	}
	for _, w := range wrappers {
		t.Run(w.name, func(t *testing.T) {
			if got := MissingCapabilities(w.wrap(inner), inner); len(got) != 0 {
				t.Fatalf("wrapper hides capabilities %v; forward them or implement IntrinsicConnProvider", got)
			}
		})
	}
}
