package protocol

import (
	"context"
	"github.com/daeuniverse/outbound/netproxy"
	"net/netip"
	"sync"
	"time"
)

// DatapathResolver resolves real peer addresses, never FakeIP or routing rewrites.
type DatapathResolver = func(context.Context, string) (netip.Addr, error)
type datapathResolverKey struct{}

// WithDatapathResolver scopes the resolver to a dial, avoiding process-wide
// generation changes when a candidate configuration is constructed or rejected.
func WithDatapathResolver(ctx context.Context, resolve DatapathResolver) context.Context {
	return context.WithValue(ctx, datapathResolverKey{}, resolve)
}
func DatapathResolverFromContext(ctx context.Context) DatapathResolver {
	resolve, _ := ctx.Value(datapathResolverKey{}).(DatapathResolver)
	return resolve
}

// DomainResolver is owned by one UDP association. Contexts are lazy: literal-IP
// packets never create a DNS context or timer. SetReadDeadline and Close also
// interrupt a domain lookup already in progress.
type DomainResolver struct {
	Resolve  DatapathResolver
	deadline netproxy.PacketDeadline
	cache    sync.Map
}

func (r *DomainResolver) Map(m *Metadata) (netip.AddrPort, error) {
	if m.Type != MetadataTypeDomain {
		return m.AddrPort()
	}
	return m.domainIPMapping(r.deadline.Context(), &r.cache, r.Resolve)
}
func (r *DomainResolver) Close()                            { r.deadline.Close() }
func (r *DomainResolver) SetReadDeadline(t time.Time) error { return r.deadline.Set(t) }
