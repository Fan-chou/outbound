//go:build !linux

package netproxy

import "syscall"

const TCPMaxSegSupported = false

// The default remains a no-op on other platforms. An explicit experiment
// fails instead of silently claiming that it applied the requested MSS.
func TCPMaxSegControl(c syscall.RawConn, mss int) error {
	return ValidateTCPMaxSeg(mss)
}
