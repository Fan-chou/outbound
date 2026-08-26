package netproxy

import (
	"context"
	"net/netip"
	"testing"
)

func TestUDPReplyAddrContextRoundTrip(t *testing.T) {
	addr := netip.MustParseAddrPort("198.51.100.10:443")
	ctx := ContextWithUDPReplyAddr(context.Background(), "example.com:443", addr)
	got, ok := UDPReplyAddrFromContext(ctx, "example.com:443")
	if !ok || got != addr {
		t.Fatalf("UDPReplyAddrFromContext() = (%v, %v), want (%v, true)", got, ok, addr)
	}
}

func TestUDPReplyAddrContextIgnoresZeroPort(t *testing.T) {
	addr := netip.AddrPortFrom(netip.MustParseAddr("198.51.100.10"), 0)
	ctx := ContextWithUDPReplyAddr(context.Background(), "example.com:443", addr)
	if _, ok := UDPReplyAddrFromContext(ctx, "example.com:443"); ok {
		t.Fatal("zero-port FullCone key must not become a reply identity")
	}
}

func TestUDPReplyAddrContextDoesNotMatchOtherTarget(t *testing.T) {
	addr := netip.MustParseAddrPort("198.51.100.10:443")
	ctx := ContextWithUDPReplyAddr(context.Background(), "example.com:443", addr)
	if _, ok := UDPReplyAddrFromContext(ctx, "proxy.example:443"); ok {
		t.Fatal("next-hop proxy dial must not consume the application reply identity")
	}
}
