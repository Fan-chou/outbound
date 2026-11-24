//go:build linux

package anytls

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

func setTCPNotSentLowat(raw syscall.RawConn, lowat int) error {
	if raw == nil || lowat <= 0 {
		return nil
	}
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		optErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, lowat)
	}); err != nil {
		return err
	}
	// Older kernels or non-TCP sockets report ENOPROTOOPT/EOPNOTSUPP; ignore cleanly.
	if errors.Is(optErr, unix.ENOPROTOOPT) || errors.Is(optErr, unix.EOPNOTSUPP) {
		return nil
	}
	return optErr
}

func setTCPUserTimeout(raw syscall.RawConn, timeoutMs int) error {
	if raw == nil || timeoutMs <= 0 {
		return nil
	}
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		optErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, timeoutMs)
	}); err != nil {
		return err
	}
	if errors.Is(optErr, unix.ENOPROTOOPT) || errors.Is(optErr, unix.EOPNOTSUPP) {
		return nil
	}
	return optErr
}
