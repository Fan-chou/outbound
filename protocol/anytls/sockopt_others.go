//go:build !linux

package anytls

import "syscall"

func setTCPNotSentLowat(syscall.RawConn, int) error {
	return nil
}
