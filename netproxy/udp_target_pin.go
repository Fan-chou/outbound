package netproxy

// UDPSessionTargetPinner is implemented by outbound protocols whose per-session
// UDP transport fixes a resolved target destination on the server for the
// lifetime of the logical UDP stream/session (for example AnyTLS UoT v2
// connected mode), so callers can forward domain:port on the first packet
// without blocking on a synchronous client-side DNS lookup.
type UDPSessionTargetPinner interface {
	PinsUDPSessionTarget() bool
}

// PinsUDPSessionTarget reports whether d itself guarantees per-session UDP
// destination pinning. It intentionally does not walk arbitrary DialerUnwrapper
// chains so an outer tunnel that lacks target pinning (e.g. hysteria2 over
// anytls) never inherits the inner transport's claim.
func PinsUDPSessionTarget(d Dialer) bool {
	if d == nil {
		return false
	}
	if p, ok := d.(UDPSessionTargetPinner); ok {
		return p.PinsUDPSessionTarget()
	}
	return false
}
