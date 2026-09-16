package protocol

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestDomainResolverCloseAndDeadlineCancelLookup(t *testing.T) {
	for _, mode := range []string{"close", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			entered := make(chan struct{})
			r := &DomainResolver{Resolve: func(ctx context.Context, _ string) (netip.Addr, error) {
				close(entered)
				<-ctx.Done()
				return netip.Addr{}, ctx.Err()
			}}
			defer r.Close()
			done := make(chan error, 1)
			go func() {
				_, err := r.Map(&Metadata{Type: MetadataTypeDomain, Hostname: "peer.test", Port: 443})
				done <- err
			}()
			<-entered
			want := error(net.ErrClosed)
			if mode == "close" {
				r.Close()
			} else {
				want = os.ErrDeadlineExceeded
				_ = r.SetReadDeadline(time.Now())
			}
			select {
			case err := <-done:
				if !errors.Is(err, want) || errors.Is(err, ErrDomainResolution) {
					t.Fatalf("got %v, want cancellation %v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("lookup did not cancel")
			}
		})
	}
}

func TestDatapathResolverStaysWithDialGeneration(t *testing.T) {
	m := &Metadata{Type: MetadataTypeDomain, Hostname: "peer.test", Port: 443}
	makeResolver := func(ip string) *DomainResolver {
		ctx := WithDatapathResolver(context.Background(), func(context.Context, string) (netip.Addr, error) { return netip.MustParseAddr(ip), nil })
		return &DomainResolver{Resolve: DatapathResolverFromContext(ctx)}
	}
	old := makeResolver("192.0.2.1")
	defer old.Close()
	candidate := makeResolver("192.0.2.2")
	defer candidate.Close()
	for _, r := range []*DomainResolver{old, candidate, old} {
		got, err := r.Map(m)
		want := "192.0.2.1:443"
		if r == candidate {
			want = "192.0.2.2:443"
		}
		if err != nil || got.String() != want {
			t.Fatalf("got %v, %v; want %s", got, err, want)
		}
	}
}
