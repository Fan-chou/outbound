//go:build linux

package netproxy

import (
	"errors"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

type maxSegRaw struct {
	fd         int
	controlErr error
	calls      int
}

func (c *maxSegRaw) Control(fn func(uintptr)) error {
	c.calls++
	if c.controlErr != nil {
		return c.controlErr
	}
	fn(uintptr(c.fd))
	return nil
}
func (*maxSegRaw) Read(func(uintptr) bool) error  { panic("unused") }
func (*maxSegRaw) Write(func(uintptr) bool) error { panic("unused") }

var _ syscall.RawConn = (*maxSegRaw)(nil)

func TestTCPMaxSegControl(t *testing.T) {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
		if errors.Is(err, unix.EAFNOSUPPORT) {
			t.Log("IPv6 unavailable")
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer unix.Close(fd)
			raw := &maxSegRaw{fd: fd}
			before, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_MAXSEG)
			if err != nil {
				t.Fatal(err)
			}
			if err := TCPMaxSegControl(raw, 0); err != nil {
				t.Fatal(err)
			}
			after, _ := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_MAXSEG)
			if raw.calls != 0 || after != before {
				t.Fatal("disabled MSS touched socket")
			}
			if err := TCPMaxSegControl(raw, 1380); err != nil {
				t.Fatal(err)
			}
			got, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_MAXSEG)
			if err != nil || got != 1380 {
				t.Fatalf("MSS = %d, %v", got, err)
			}
			for _, opt := range []int{unix.TCP_NODELAY, unix.TCP_FASTOPEN_CONNECT} {
				value, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, opt)
				if errors.Is(err, unix.ENOPROTOOPT) {
					continue
				}
				if err != nil || value != 0 {
					t.Fatalf("unexpected TCP option %d: %d, %v", opt, value, err)
				}
			}
		}()
	}
}

func TestTCPMaxSegErrors(t *testing.T) {
	raw := &maxSegRaw{fd: -1}
	for _, mss := range []int{-1, 1, 87, 32768} {
		if err := TCPMaxSegControl(raw, mss); err == nil {
			t.Fatalf("accepted MSS %d", mss)
		}
	}
	if raw.calls != 0 {
		t.Fatal("invalid input reached socket")
	}
	if err := TCPMaxSegControl(raw, 1380); !errors.Is(err, unix.EBADF) {
		t.Fatalf("socket error = %v", err)
	}
	raw.controlErr = unix.EIO
	if err := TCPMaxSegControl(raw, 1380); !errors.Is(err, unix.EIO) {
		t.Fatalf("control error = %v", err)
	}
}
