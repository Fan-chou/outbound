//go:build linux

package netproxy

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

const TCPMaxSegSupported = true

// TCPMaxSegControl sets only TCP_MAXSEG, before connect or listen. It does not
// enable TFO, change NODELAY, or modify process-wide socket defaults.
func TCPMaxSegControl(c syscall.RawConn, mss int) error {
	if err := ValidateTCPMaxSeg(mss); err != nil {
		return err
	}
	if mss == 0 {
		return nil
	}
	var optErr error
	if err := c.Control(func(fd uintptr) {
		optErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, mss)
	}); err != nil {
		return fmt.Errorf("TCP_MAXSEG socket control: %w", err)
	}
	if optErr != nil {
		return fmt.Errorf("set TCP_MAXSEG: %w", optErr)
	}
	return nil
}
