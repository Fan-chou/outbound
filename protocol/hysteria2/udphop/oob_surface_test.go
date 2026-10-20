package udphop

import (
	"context"
	"net"
	"syscall"
	"testing"

	"github.com/olicesx/quic-go"
)

func newHopForSurfaceTest(t *testing.T, dial contextDialFunc) net.PacketConn {
	t.Helper()
	hopAddr, err := ParseUDPHopAddr("127.0.0.1:9001,9002")
	if err != nil {
		t.Fatalf("ParseUDPHopAddr: %v", err)
	}
	conn, err := NewUDPHopPacketConnContext(context.Background(), hopAddr, 0, dial)
	if err != nil {
		t.Fatalf("NewUDPHopPacketConnContext: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// A proxied underlay has no raw socket. quic-go's newConn calls SyscallConn on
// anything that looks OOB-capable and aborts the dial on error, so the hop conn
// must not advertise the OOB/batch/SyscallConn surface there.
func TestHopConnOverProxiedUnderlayHidesOOBSurface(t *testing.T) {
	conn := newHopForSurfaceTest(t, func(context.Context, net.Addr) (net.PacketConn, error) {
		return &stubPacketConn{}, nil
	})
	if _, ok := conn.(quic.OOBCapablePacketConn); ok {
		t.Error("proxied-underlay hop conn advertises quic.OOBCapablePacketConn")
	}
	if _, ok := conn.(syscall.Conn); ok {
		t.Error("proxied-underlay hop conn advertises SyscallConn")
	}
	if _, ok := conn.(batchReader); ok {
		t.Error("proxied-underlay hop conn advertises ReadBatch")
	}
}

// A direct dial keeps the optimized path: GSO, ECN and batch reads.
func TestHopConnOverRawUDPKeepsOOBSurface(t *testing.T) {
	conn := newHopForSurfaceTest(t, func(context.Context, net.Addr) (net.PacketConn, error) {
		return net.ListenPacket("udp", "127.0.0.1:0")
	})
	if _, ok := conn.(quic.OOBCapablePacketConn); !ok {
		t.Error("raw-socket hop conn lost quic.OOBCapablePacketConn")
	}
	if _, ok := conn.(batchReader); !ok {
		t.Error("raw-socket hop conn lost ReadBatch")
	}
}
