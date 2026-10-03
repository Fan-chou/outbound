//go:build !linux

package netproxy

import "testing"

func TestTCPMaxSegUnsupported(t *testing.T) {
	if err := TCPMaxSegControl(nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := TCPMaxSegControl(nil, 1380); err == nil {
		t.Fatal("explicit override silently ignored")
	}
}
