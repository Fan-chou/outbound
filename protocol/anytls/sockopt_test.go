package anytls

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

type fakeSyscallRawConn struct {
	called bool
}

func (r *fakeSyscallRawConn) Control(f func(uintptr)) error {
	r.called = true
	f(0)
	return nil
}
func (r *fakeSyscallRawConn) Read(func(uintptr) bool) error  { return nil }
func (r *fakeSyscallRawConn) Write(func(uintptr) bool) error { return nil }

type fakeSyscallConn struct {
	net.Conn
	raw syscall.RawConn
	err error
}

func (c *fakeSyscallConn) SyscallConn() (syscall.RawConn, error) {
	return c.raw, c.err
}

type fakeNetConnWrapper struct {
	net.Conn
}

func (w *fakeNetConnWrapper) NetConn() net.Conn { return w.Conn }

func TestExtractSyscallConnUnwrapsLayers(t *testing.T) {
	raw := &fakeSyscallRawConn{}
	base := &fakeSyscallConn{Conn: &stubConn{}, raw: raw}
	wrapped := &netproxy.FakeNetConn{Conn: &fakeNetConnWrapper{Conn: base}}

	got := extractSyscallConn(wrapped)
	if got != base {
		t.Fatalf("extractSyscallConn() = %#v, want base %#v", got, base)
	}
}

func TestTuneTCPCarrierConnHandlesErrorsAndNonSyscallConns(t *testing.T) {
	// Non-syscall conn is a safe no-op.
	tuneTCPCarrierConn(&stubConn{})
	tuneTCPCarrierConn(nil)

	// SyscallConn error is ignored cleanly.
	tuneTCPCarrierConn(&fakeSyscallConn{Conn: &stubConn{}, err: errors.New("not supported")})
}
