//go:build linux

package anytls

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTuneTCPCarrierConnSetsNotSentLowatOnLinux(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if sc := <-accepted; sc != nil {
		defer sc.Close()
	}

	tuneTCPCarrierConn(conn)

	tcpConn := conn.(*net.TCPConn)
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var got int
	var getErr error
	if err := raw.Control(func(fd uintptr) {
		got, getErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if getErr != nil {
		t.Skipf("kernel does not expose TCP_NOTSENT_LOWAT: %v", getErr)
	}
	if got != defaultTCPNotSentLowat {
		t.Fatalf("TCP_NOTSENT_LOWAT = %d, want %d", got, defaultTCPNotSentLowat)
	}
	var gotUT int
	if err := raw.Control(func(fd uintptr) {
		gotUT, getErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT)
	}); err != nil {
		t.Fatalf("Control(TCP_USER_TIMEOUT): %v", err)
	}
	if getErr == nil && gotUT != defaultTCPUserTimeoutMs {
		t.Fatalf("TCP_USER_TIMEOUT = %d, want %d", gotUT, defaultTCPUserTimeoutMs)
	}
}

func TestSetTCPNotSentLowatIgnoresUnsupportedSocketError(t *testing.T) {
	// A Unix domain datagram/stream socket does not support IPPROTO_TCP/TCP_NOTSENT_LOWAT;
	// setTCPNotSentLowat must ignore ENOPROTOOPT/EOPNOTSUPP instead of failing.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	raw := &unixFDControl{fd: fds[0]}
	if err := setTCPNotSentLowat(raw, defaultTCPNotSentLowat); err != nil {
		t.Fatalf("setTCPNotSentLowat() on non-TCP socket = %v, want nil", err)
	}
}

type unixFDControl struct{ fd int }

func (u *unixFDControl) Control(f func(uintptr)) error {
	f(uintptr(u.fd))
	return nil
}
func (u *unixFDControl) Read(func(uintptr) bool) error  { return nil }
func (u *unixFDControl) Write(func(uintptr) bool) error { return nil }
