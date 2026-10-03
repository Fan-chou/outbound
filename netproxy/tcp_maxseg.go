package netproxy

import "fmt"

// ValidateTCPMaxSeg accepts zero (leave the kernel default unchanged), or the
// Linux TCP_MAXSEG range. MSS is an upper bound; TCP options and path MTU can
// reduce the negotiated payload size further.
func ValidateTCPMaxSeg(mss int) error {
	if mss != 0 && (mss < 88 || mss > 32767) {
		return fmt.Errorf("TCP_MAXSEG must be 0 or between 88 and 32767: %d", mss)
	}
	if mss != 0 && !TCPMaxSegSupported {
		return fmt.Errorf("TCP_MAXSEG override is unsupported on this platform")
	}
	return nil
}
