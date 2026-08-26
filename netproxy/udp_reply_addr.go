package netproxy

import (
	"context"
	"net/netip"
)

type udpReplyAddrContextKey struct{}

type udpReplyIdentity struct {
	Target string
	Addr   netip.AddrPort
}

// ContextWithUDPReplyAddr records the userspace-NAT identity for one UDP dial
// target. Datagram protocols must return this IP:port to dae instead of the
// server-resolved address or a local DNS lookup — the client socket is bound
// to the original destination (including FakeIP). The identity is keyed by
// target so a nested nextDialer cannot consume an application-level hint
// while connecting to the proxy server.
func ContextWithUDPReplyAddr(ctx context.Context, target string, addr netip.AddrPort) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if target == "" || !addr.IsValid() || addr.Port() == 0 {
		return ctx
	}
	return context.WithValue(ctx, udpReplyAddrContextKey{}, udpReplyIdentity{
		Target: target,
		Addr:   addr,
	})
}

// UDPReplyAddrFromContext returns the NAT identity for this dial target.
func UDPReplyAddrFromContext(ctx context.Context, target string) (netip.AddrPort, bool) {
	if ctx == nil || target == "" {
		return netip.AddrPort{}, false
	}
	id, ok := ctx.Value(udpReplyAddrContextKey{}).(udpReplyIdentity)
	if !ok || id.Target != target || !id.Addr.IsValid() || id.Addr.Port() == 0 {
		return netip.AddrPort{}, false
	}
	return id.Addr, true
}
