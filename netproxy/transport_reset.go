package netproxy

import "reflect"

// TransportResetter is implemented by dialers that hold long-lived underlay
// transports (such as pooled TLS sessions or multiplexed QUIC tunnels) and can
// drop those transports immediately when the host network changes (e.g. WAN
// IPv4/IPv6 renewal) without permanently closing the dialer.
type TransportResetter interface {
	ResetTransport()
}

// ResetTransport walks d and any DialerUnwrapper chain, invoking ResetTransport
// on every layer that implements TransportResetter. It returns true if at least
// one transport resetter was invoked.
func ResetTransport(d Dialer) bool {
	reset := false
	var visited []Dialer
	for depth := 0; depth < maxDialerUnwrapDepth && d != nil; depth++ {
		if seenDialer(visited, d) {
			break
		}
		visited = append(visited, d)
		if resetter, ok := d.(TransportResetter); ok {
			resetter.ResetTransport()
			reset = true
		}
		unwrapper, ok := d.(DialerUnwrapper)
		if !ok {
			break
		}
		d = unwrapper.UnwrapDialer()
	}
	return reset
}

func seenDialer(visited []Dialer, target Dialer) bool {
	if !reflect.ValueOf(target).Comparable() {
		return false
	}
	for _, prev := range visited {
		if reflect.ValueOf(prev).Comparable() && prev == target {
			return true
		}
	}
	return false
}
