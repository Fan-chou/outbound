package stickyip

import (
	"context"
	stderrors "errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

func TestSplitHostPortSupportsPortUnion(t *testing.T) {
	host, port, err := SplitHostPort("example.com:443,8443-8450")
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	if got, want := host, "example.com"; got != want {
		t.Fatalf("host = %q, want %q", got, want)
	}
	if got, want := port, "443,8443-8450"; got != want {
		t.Fatalf("port = %q, want %q", got, want)
	}
}

func TestSplitHostPortSupportsBracketedIPv6(t *testing.T) {
	host, port, err := SplitHostPort("[2001:db8::1]:443,8443")
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	if got, want := host, "2001:db8::1"; got != want {
		t.Fatalf("host = %q, want %q", got, want)
	}
	if got, want := port, "443,8443"; got != want {
		t.Fatalf("port = %q, want %q", got, want)
	}
}

func TestRewriteAddrPortKeepsResolvedHostAndCurrentPort(t *testing.T) {
	if got, want := rewriteAddrPort("203.0.113.10:443", "example.com:8443"), "203.0.113.10:8443"; got != want {
		t.Fatalf("rewriteAddrPort() = %q, want %q", got, want)
	}
}

func TestRewriteAddrPortKeepsIPv6Formatting(t *testing.T) {
	if got, want := rewriteAddrPort("[2001:db8::10]:443", "example.com:8443"), "[2001:db8::10]:8443"; got != want {
		t.Fatalf("rewriteAddrPort() = %q, want %q", got, want)
	}
}

type recordingLookupDialer struct {
	mu sync.Mutex

	lookupCalls   int
	lookupNetwork string
	lookupHost    string
	lookupResult  []net.IPAddr
	lookupErr     error

	dialCalls       [][2]string
	conn            netproxy.Conn
	dialErr         error
	dialFunc        func(network, addr string) (netproxy.Conn, error)
	dialContextFunc func(ctx context.Context, network, addr string) (netproxy.Conn, error)
}

func (d *recordingLookupDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	d.mu.Lock()
	d.dialCalls = append(d.dialCalls, [2]string{network, addr})
	d.mu.Unlock()
	if d.dialContextFunc != nil {
		return d.dialContextFunc(ctx, network, addr)
	}
	if d.dialFunc != nil {
		return d.dialFunc(network, addr)
	}
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	return d.conn, nil
}

func (d *recordingLookupDialer) LookupIPAddr(_ context.Context, network, host string) ([]net.IPAddr, error) {
	d.mu.Lock()
	d.lookupCalls++
	d.lookupNetwork = network
	d.lookupHost = host
	d.mu.Unlock()
	if d.lookupErr != nil {
		return nil, d.lookupErr
	}
	return append([]net.IPAddr(nil), d.lookupResult...), nil
}

type nopConn struct{}

func (nopConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (nopConn) Write(p []byte) (int, error)        { return len(p), nil }
func (nopConn) Close() error                       { return nil }
func (nopConn) SetDeadline(_ time.Time) error      { return nil }
func (nopConn) SetReadDeadline(_ time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(_ time.Time) error { return nil }

type trackingPacketConn struct {
	readFromCalls        int
	setReadDeadlineCalls int
	readErr              error
}

func (c *trackingPacketConn) Read(_ []byte) (int, error)    { return 0, io.EOF }
func (c *trackingPacketConn) Write(p []byte) (int, error)   { return len(p), nil }
func (c *trackingPacketConn) Close() error                  { return nil }
func (c *trackingPacketConn) SetDeadline(_ time.Time) error { return nil }
func (c *trackingPacketConn) SetReadDeadline(_ time.Time) error {
	c.setReadDeadlineCalls++
	return nil
}
func (c *trackingPacketConn) SetWriteDeadline(_ time.Time) error { return nil }
func (c *trackingPacketConn) ReadFrom(_ []byte) (int, netip.AddrPort, error) {
	c.readFromCalls++
	return 0, netip.AddrPort{}, c.readErr
}
func (c *trackingPacketConn) WriteTo(p []byte, _ string) (int, error) { return len(p), nil }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestStickyIpDialerUsesUnderlyingResolverForProxyLookup(t *testing.T) {
	network := netproxy.MagicNetwork{Network: "tcp", Mark: 123}.Encode()
	parent := &recordingLookupDialer{
		lookupResult: []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}},
		conn:         nopConn{},
	}
	dialer := NewStickyIpDialer(parent, "proxy.example:443,8443-8450", NewProxyIpCache())

	conn, err := dialer.DialContext(context.Background(), network, "proxy.example:8443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if conn == nil {
		t.Fatal("DialContext() returned nil conn")
	}

	parent.mu.Lock()
	defer parent.mu.Unlock()
	if parent.lookupCalls != 1 {
		t.Fatalf("LookupIPAddr() calls = %d, want 1", parent.lookupCalls)
	}
	if got, want := parent.lookupNetwork, network; got != want {
		t.Fatalf("LookupIPAddr() network = %q, want %q", got, want)
	}
	if got, want := parent.lookupHost, "proxy.example"; got != want {
		t.Fatalf("LookupIPAddr() host = %q, want %q", got, want)
	}
	if len(parent.dialCalls) != 1 {
		t.Fatalf("DialContext() calls = %d, want 1", len(parent.dialCalls))
	}
	if got, want := parent.dialCalls[0][1], "203.0.113.10:8443"; got != want {
		t.Fatalf("DialContext() addr = %q, want %q", got, want)
	}
}

func TestStickyIpDialerDoesNotTreatDifferentFixedPortAsProxyAddress(t *testing.T) {
	parent := &recordingLookupDialer{
		conn: nopConn{},
	}
	dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())

	conn, err := dialer.DialContext(context.Background(), "tcp", "proxy.example:8443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if conn == nil {
		t.Fatal("DialContext() returned nil conn")
	}

	parent.mu.Lock()
	defer parent.mu.Unlock()
	if parent.lookupCalls != 0 {
		t.Fatalf("LookupIPAddr() calls = %d, want 0", parent.lookupCalls)
	}
	if len(parent.dialCalls) != 1 {
		t.Fatalf("DialContext() calls = %d, want 1", len(parent.dialCalls))
	}
	if got, want := parent.dialCalls[0][1], "proxy.example:8443"; got != want {
		t.Fatalf("DialContext() addr = %q, want %q", got, want)
	}
}

func TestStickyIpDialerDoesNotProbeResolvedUDPProxyConnBeforeCaching(t *testing.T) {
	packetConn := &trackingPacketConn{readErr: timeoutErr{}}
	parent := &recordingLookupDialer{
		lookupResult: []net.IPAddr{{IP: net.ParseIP("198.51.100.20")}},
		conn:         packetConn,
	}
	dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())

	conn, err := dialer.DialContext(context.Background(), "udp", "proxy.example:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if conn == nil {
		t.Fatal("DialContext() returned nil conn")
	}
	if packetConn.readFromCalls != 0 {
		t.Fatalf("ReadFrom() calls = %d, want 0", packetConn.readFromCalls)
	}
	if packetConn.setReadDeadlineCalls != 0 {
		t.Fatalf("SetReadDeadline() calls = %d, want 0", packetConn.setReadDeadlineCalls)
	}
}

func TestStickyIpDialerUsesCachedUDPProxyAddrWithoutReadProbe(t *testing.T) {
	firstConn := &trackingPacketConn{readErr: timeoutErr{}}
	secondConn := &trackingPacketConn{readErr: timeoutErr{}}
	parent := &recordingLookupDialer{
		lookupResult: []net.IPAddr{
			{IP: net.ParseIP("198.51.100.10")},
			{IP: net.ParseIP("198.51.100.20")},
		},
		dialFunc: func(_ string, addr string) (netproxy.Conn, error) {
			switch addr {
			case "198.51.100.10:443":
				return firstConn, nil
			default:
				return secondConn, nil
			}
		},
	}
	dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())

	conn, err := dialer.DialContext(context.Background(), "udp", "proxy.example:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if conn != firstConn {
		t.Fatal("DialContext() did not return the first successfully dialed UDP conn")
	}
	conn, err = dialer.DialContext(context.Background(), "udp", "proxy.example:443")
	if err != nil {
		t.Fatalf("second DialContext() error = %v", err)
	}
	if conn != firstConn {
		t.Fatal("second DialContext() did not use the cached UDP proxy addr")
	}

	parent.mu.Lock()
	defer parent.mu.Unlock()
	if parent.lookupCalls != 1 {
		t.Fatalf("LookupIPAddr() calls = %d, want 1", parent.lookupCalls)
	}
	if len(parent.dialCalls) != 2 {
		t.Fatalf("DialContext() calls = %d, want 2", len(parent.dialCalls))
	}
	if got, want := parent.dialCalls[0][1], "198.51.100.10:443"; got != want {
		t.Fatalf("first dial addr = %q, want %q", got, want)
	}
	if got, want := parent.dialCalls[1][1], "198.51.100.10:443"; got != want {
		t.Fatalf("second dial addr = %q, want %q", got, want)
	}
	if firstConn.readFromCalls != 0 {
		t.Fatalf("first conn ReadFrom() calls = %d, want 0", firstConn.readFromCalls)
	}
	if firstConn.setReadDeadlineCalls != 0 {
		t.Fatalf("first conn SetReadDeadline() calls = %d, want 0", firstConn.setReadDeadlineCalls)
	}
	if secondConn.readFromCalls != 0 {
		t.Fatalf("second conn ReadFrom() calls = %d, want 0", secondConn.readFromCalls)
	}
	if secondConn.setReadDeadlineCalls != 0 {
		t.Fatalf("second conn SetReadDeadline() calls = %d, want 0", secondConn.setReadDeadlineCalls)
	}
}

func TestStickyIpDialerKeepsBudgetForAlternativeResolvedIPs(t *testing.T) {
	parent := &recordingLookupDialer{
		lookupResult: []net.IPAddr{
			{IP: net.ParseIP("198.51.100.10")},
			{IP: net.ParseIP("198.51.100.20")},
		},
	}
	parent.dialContextFunc = func(ctx context.Context, _ string, addr string) (netproxy.Conn, error) {
		if addr == "198.51.100.10:443" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return nopConn{}, nil
	}

	dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", "proxy.example:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if conn == nil {
		t.Fatal("DialContext() returned nil conn")
	}

	parent.mu.Lock()
	defer parent.mu.Unlock()
	if len(parent.dialCalls) != 2 {
		t.Fatalf("DialContext() calls = %d, want 2", len(parent.dialCalls))
	}
	if got, want := parent.dialCalls[0][1], "198.51.100.10:443"; got != want {
		t.Fatalf("first dial addr = %q, want %q", got, want)
	}
	if got, want := parent.dialCalls[1][1], "198.51.100.20:443"; got != want {
		t.Fatalf("second dial addr = %q, want %q", got, want)
	}
}

func TestDialAttemptContextLeavesReserveWithoutEqualSplit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	attemptCtx, attemptCancel := dialAttemptContext(ctx, 4)
	defer attemptCancel()

	deadline, ok := attemptCtx.Deadline()
	if !ok {
		t.Fatal("dialAttemptContext() did not preserve a deadline")
	}

	remaining := time.Until(deadline)
	if remaining < 5*time.Second || remaining > 7*time.Second {
		t.Fatalf("first-attempt budget = %v, want a majority of the original budget with fallback reserve preserved", remaining)
	}
}

func TestStickyIpDialerReturnsStableErrorWhenNoUsableIPsResolved(t *testing.T) {
	parent := &recordingLookupDialer{
		lookupResult: []net.IPAddr{{}},
	}
	dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())

	_, err := dialer.DialContext(context.Background(), "tcp", "proxy.example:443")
	if err == nil {
		t.Fatal("DialContext() error = nil, want non-nil")
	}
	if got, want := err.Error(), "no usable proxy IP addresses"; got == want {
		return
	}
	if !strings.Contains(err.Error(), "no usable proxy IP addresses") {
		t.Fatalf("DialContext() error = %q, want substring %q", err.Error(), "no usable proxy IP addresses")
	}
}

func TestStickyIpDialerFallsBackToOriginalAddrWhenResolverReturnsEmptySet(t *testing.T) {
	parent := &recordingLookupDialer{
		lookupResult: []net.IPAddr{},
		conn:         nopConn{},
	}
	dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())

	conn, err := dialer.DialContext(context.Background(), "tcp", "proxy.example:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if conn == nil {
		t.Fatal("DialContext() returned nil conn")
	}

	parent.mu.Lock()
	defer parent.mu.Unlock()
	if len(parent.dialCalls) != 1 {
		t.Fatalf("DialContext() calls = %d, want 1", len(parent.dialCalls))
	}
	if got, want := parent.dialCalls[0][1], "proxy.example:443"; got != want {
		t.Fatalf("DialContext() addr = %q, want %q", got, want)
	}
}

func TestStickyIpDialerHonorsRequestedIPVersion(t *testing.T) {
	network := netproxy.MagicNetwork{Network: "udp", IPVersion: "6"}.Encode()
	parent := &recordingLookupDialer{
		lookupResult: []net.IPAddr{
			{IP: net.ParseIP("203.0.113.10")},
			{IP: net.ParseIP("2001:db8::10")},
		},
		conn: &trackingPacketConn{readErr: timeoutErr{}},
	}
	dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())

	conn, err := dialer.DialContext(context.Background(), network, "proxy.example:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if conn == nil {
		t.Fatal("DialContext() returned nil conn")
	}

	parent.mu.Lock()
	defer parent.mu.Unlock()
	if len(parent.dialCalls) != 1 {
		t.Fatalf("DialContext() calls = %d, want 1", len(parent.dialCalls))
	}
	if got, want := parent.dialCalls[0][1], "[2001:db8::10]:443"; got != want {
		t.Fatalf("DialContext() addr = %q, want %q", got, want)
	}
}

func TestProxyIpCacheGetRemovesExpiredEntry(t *testing.T) {
	cache := NewProxyIpCache()
	proxyAddr := "proxy.example:443"
	cache.cache[proxyAddr] = &proxyIpEntry{
		tcp4Addr:   "1.1.1.1:443",
		expiresAt:  time.Now().Add(-time.Second),
		checkCycle: 7,
	}

	if got := cache.GetWithCycleAndIpVersion(proxyAddr, "tcp", "4", 7); got != proxyAddr {
		t.Fatalf("GetWithCycleAndIpVersion() = %q, want original addr %q", got, proxyAddr)
	}
	if _, ok := cache.cache[proxyAddr]; ok {
		t.Fatal("expired entry was not deleted from cache")
	}
}

func TestProxyIpCacheSetRefreshesExistingEntryMetadata(t *testing.T) {
	cache := NewProxyIpCache()
	proxyAddr := "proxy.example:443"
	cache.cache[proxyAddr] = &proxyIpEntry{
		tcp4Addr:   "1.1.1.1:443",
		expiresAt:  time.Now().Add(-time.Minute),
		checkCycle: 1,
	}

	cache.Set(proxyAddr, "2.2.2.2:443", "tcp", "4", 9)

	entry := cache.cache[proxyAddr]
	if entry == nil {
		t.Fatal("expected cache entry to exist after Set")
	}
	if entry.tcp4Addr != "2.2.2.2:443" {
		t.Fatalf("entry.tcp4Addr = %q, want refreshed address", entry.tcp4Addr)
	}
	if entry.checkCycle != 9 {
		t.Fatalf("entry.checkCycle = %d, want 9", entry.checkCycle)
	}
	if !entry.expiresAt.After(time.Now()) {
		t.Fatalf("entry.expiresAt = %v, want a future timestamp", entry.expiresAt)
	}
	if got := cache.GetWithCycleAndIpVersion(proxyAddr, "tcp", "4", 9); got != "2.2.2.2:443" {
		t.Fatalf("GetWithCycleAndIpVersion() = %q, want refreshed cached address", got)
	}
}

func TestProxyIpCacheSetCleansOtherExpiredEntries(t *testing.T) {
	cache := NewProxyIpCache()
	cache.cache["stale.example:443"] = &proxyIpEntry{
		tcp4Addr:   "1.1.1.1:443",
		expiresAt:  time.Now().Add(-time.Minute),
		checkCycle: 1,
	}
	cache.nextCleanupAt = time.Time{}

	cache.Set("fresh.example:443", "2.2.2.2:443", "tcp", "4", 2)

	if _, ok := cache.cache["stale.example:443"]; ok {
		t.Fatal("periodic cleanup did not remove stale entry")
	}
	if _, ok := cache.cache["fresh.example:443"]; !ok {
		t.Fatal("fresh entry missing after Set")
	}
}

func TestStickyIpDialerCycleInvalidationIsScopedToProxy(t *testing.T) {
	cache := NewProxyIpCache()
	parentA := &recordingLookupDialer{conn: nopConn{}}
	parentB := &recordingLookupDialer{conn: nopConn{}}
	cache.Set("proxy-a.example:443", "203.0.113.10:443", "tcp", "4", 0)
	cache.Set("proxy-b.example:443", "203.0.113.20:443", "tcp", "4", 0)

	dialerA := NewStickyIpDialer(parentA, "proxy-a.example:443", cache)
	dialerB := NewStickyIpDialer(parentB, "proxy-b.example:443", cache)
	dialerA.IncrementCheckCycle()

	if _, err := dialerB.DialContext(context.Background(), "tcp", "proxy-b.example:443"); err != nil {
		t.Fatalf("dialerB DialContext() error = %v", err)
	}
	parentB.mu.Lock()
	defer parentB.mu.Unlock()
	if len(parentB.dialCalls) != 1 || parentB.dialCalls[0][1] != "203.0.113.20:443" {
		t.Fatalf("dialerB calls = %+v, want preserved cached address", parentB.dialCalls)
	}
	if parentB.lookupCalls != 0 {
		t.Fatalf("dialerB lookup calls = %d, want 0", parentB.lookupCalls)
	}
}

func TestStickyIpDialerCachedProxyCancellationDoesNotInvalidateCache(t *testing.T) {
	cache := NewProxyIpCache()
	cache.Set("proxy.example:443", "203.0.113.10:443", "tcp", "4", 0)
	parent := &recordingLookupDialer{dialErr: context.Canceled}
	dialer := NewStickyIpDialer(parent, "proxy.example:443", cache)

	_, err := dialer.DialContext(context.Background(), "tcp4", "proxy.example:443")
	if !stderrors.Is(err, context.Canceled) {
		t.Fatalf("DialContext() err = %v, want context.Canceled", err)
	}

	parent.mu.Lock()
	defer parent.mu.Unlock()
	if len(parent.dialCalls) != 1 {
		t.Fatalf("DialContext() calls = %d, want 1", len(parent.dialCalls))
	}
	if got := cache.GetWithCycleAndIpVersion("proxy.example:443", "tcp", "4", 0); got != "203.0.113.10:443" {
		t.Fatalf("cached addr after cancellation = %q, want cache preserved", got)
	}
}

func TestStickyIpDialerResolvedProxyCancellationStopsFallback(t *testing.T) {
	parent := &recordingLookupDialer{
		lookupResult: []net.IPAddr{
			{IP: net.ParseIP("203.0.113.10")},
			{IP: net.ParseIP("203.0.113.11")},
		},
		dialFunc: func(network, addr string) (netproxy.Conn, error) {
			return nil, context.Canceled
		},
	}
	dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())

	_, err := dialer.DialContext(context.Background(), "tcp", "proxy.example:443")
	if !stderrors.Is(err, context.Canceled) {
		t.Fatalf("DialContext() err = %v, want context.Canceled", err)
	}

	parent.mu.Lock()
	defer parent.mu.Unlock()
	if parent.lookupCalls != 1 {
		t.Fatalf("LookupIPAddr() calls = %d, want 1", parent.lookupCalls)
	}
	if len(parent.dialCalls) != 1 {
		t.Fatalf("DialContext() calls = %d, want 1", len(parent.dialCalls))
	}
	if got, want := parent.dialCalls[0][1], "203.0.113.10:443"; got != want {
		t.Fatalf("DialContext() addr = %q, want %q", got, want)
	}
}

type closeCountingConn struct {
	nopConn
	id     string
	closed atomic.Bool
}

func (c *closeCountingConn) Close() error {
	c.closed.Store(true)
	return nil
}

func TestStickyIpDialerStaleFallbackAfterIncrementCheckCycle(t *testing.T) {
	t.Run("uses last confirmed IP when re-resolution fails", func(t *testing.T) {
		parent := &recordingLookupDialer{
			lookupResult: []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}},
			conn:         nopConn{},
		}
		dialer := NewStickyIpDialer(parent, "proxy.example:443,8443", NewProxyIpCache())

		if _, err := dialer.DialContext(context.Background(), "tcp", "proxy.example:443"); err != nil {
			t.Fatalf("cycle 0 DialContext() error = %v", err)
		}

		dialer.IncrementCheckCycle()
		if got := dialer.GetCachedProxyAddr("tcp"); got != "proxy.example:443,8443" {
			t.Fatalf("GetCachedProxyAddr() after cycle increment = %q, want cache miss", got)
		}

		parent.mu.Lock()
		parent.lookupErr = stderrors.New("dns timeout")
		parent.dialCalls = nil
		parent.mu.Unlock()

		conn, err := dialer.DialContext(context.Background(), "tcp", "proxy.example:8443")
		if err != nil {
			t.Fatalf("cycle 1 DialContext() with DNS error = %v", err)
		}
		if conn == nil {
			t.Fatal("expected non-nil conn from stale fallback")
		}

		parent.mu.Lock()
		defer parent.mu.Unlock()
		if len(parent.dialCalls) != 1 {
			t.Fatalf("DialContext() calls = %d, want 1", len(parent.dialCalls))
		}
		if got, want := parent.dialCalls[0][1], "203.0.113.10:8443"; got != want {
			t.Fatalf("stale fallback dial addr = %q, want %q (must not fall back to unresolved domain)", got, want)
		}
		if got := dialer.GetCachedProxyAddr("tcp"); got != "203.0.113.10:8443" {
			t.Fatalf("GetCachedProxyAddr() after stale recovery = %q, want promoted to current cycle", got)
		}
	})

	t.Run("does not retry stale IP on context cancellation", func(t *testing.T) {
		parent := &recordingLookupDialer{
			lookupResult: []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}},
			conn:         nopConn{},
		}
		dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())
		if _, err := dialer.DialContext(context.Background(), "tcp", "proxy.example:443"); err != nil {
			t.Fatalf("initial dial error = %v", err)
		}

		dialer.IncrementCheckCycle()
		parent.mu.Lock()
		parent.lookupErr = context.Canceled
		parent.dialCalls = nil
		parent.mu.Unlock()

		_, err := dialer.DialContext(context.Background(), "tcp", "proxy.example:443")
		if !stderrors.Is(err, context.Canceled) {
			t.Fatalf("DialContext() err = %v, want context.Canceled", err)
		}
		parent.mu.Lock()
		defer parent.mu.Unlock()
		if len(parent.dialCalls) != 0 {
			t.Fatalf("DialContext() calls = %d, want 0 on canceled lookup", len(parent.dialCalls))
		}
	})

	t.Run("stale failure invalidates stale entry without dialing unresolved domain", func(t *testing.T) {
		parent := &recordingLookupDialer{
			lookupResult: []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}},
			conn:         nopConn{},
		}
		dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())
		if _, err := dialer.DialContext(context.Background(), "tcp", "proxy.example:443"); err != nil {
			t.Fatalf("initial dial error = %v", err)
		}

		dialer.IncrementCheckCycle()
		parent.mu.Lock()
		parent.lookupErr = stderrors.New("dns down")
		parent.dialErr = stderrors.New("connection refused")
		parent.dialCalls = nil
		parent.mu.Unlock()

		if _, err := dialer.DialContext(context.Background(), "tcp", "proxy.example:443"); err == nil {
			t.Fatal("expected error when both DNS and stale IP fail")
		}

		parent.mu.Lock()
		if len(parent.dialCalls) != 1 || parent.dialCalls[0][1] != "203.0.113.10:443" {
			t.Fatalf("dialCalls = %+v, want single stale IP attempt without unresolved domain fallback", parent.dialCalls)
		}
		parent.mu.Unlock()

		if stale := dialer.cache.getStaleCandidates("proxy.example:443", "proxy.example:443", "tcp", ""); len(stale) != 0 {
			t.Fatalf("expected failed stale entry to be invalidated, got %+v", stale)
		}
	})

	t.Run("cross-protocol cycle isolation", func(t *testing.T) {
		cache := NewProxyIpCache()
		cache.Set("proxy.example:443", "203.0.113.10:443", "tcp", "4", 0)
		cache.Set("proxy.example:443", "203.0.113.10:443", "udp", "4", 0)

		// Advancing to cycle 1 and setting tcp4 must not promote cycle-0 udp4 to cycle 1.
		cache.Set("proxy.example:443", "203.0.113.11:443", "tcp", "4", 1)
		if got := cache.GetWithCycleAndIpVersion("proxy.example:443", "udp", "4", 1); got != "proxy.example:443" {
			t.Fatalf("udp4 leaked across cycles: got %q, want miss", got)
		}
		if stale := cache.getStaleCandidates("proxy.example:443", "proxy.example:443", "udp", "4"); len(stale) != 1 || stale[0].targetAddr != "203.0.113.10:443" {
			t.Fatalf("udp4 stale = %+v, want 203.0.113.10:443", stale)
		}
	})
}

func TestStickyIpDialerStaggeredRace(t *testing.T) {
	t.Run("primary head start avoids extra dials when fast", func(t *testing.T) {
		parent := &recordingLookupDialer{
			lookupResult: []net.IPAddr{
				{IP: net.ParseIP("198.51.100.10")},
				{IP: net.ParseIP("198.51.100.20")},
				{IP: net.ParseIP("198.51.100.30")},
			},
			conn: nopConn{},
		}
		dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())
		conn, err := dialer.DialContext(context.Background(), "tcp", "proxy.example:443")
		if err != nil {
			t.Fatalf("DialContext() error = %v", err)
		}
		if conn == nil {
			t.Fatal("expected non-nil conn")
		}
		parent.mu.Lock()
		defer parent.mu.Unlock()
		if len(parent.dialCalls) != 1 || parent.dialCalls[0][1] != "198.51.100.10:443" {
			t.Fatalf("dialCalls = %+v, want only primary IP dialed", parent.dialCalls)
		}
	})

	t.Run("staggered race launches remaining after head start and cancels losers", func(t *testing.T) {
		var mu sync.Mutex
		startedAt := make(map[string]time.Time)
		canceled := make(map[string]chan struct{})
		for _, ip := range []string{"198.51.100.10:443", "198.51.100.20:443", "198.51.100.30:443"} {
			canceled[ip] = make(chan struct{})
		}
		winConn := &closeCountingConn{id: "winner"}

		parent := &recordingLookupDialer{
			lookupResult: []net.IPAddr{
				{IP: net.ParseIP("198.51.100.10")},
				{IP: net.ParseIP("198.51.100.20")},
				{IP: net.ParseIP("198.51.100.30")},
			},
		}
		parent.dialContextFunc = func(ctx context.Context, _ string, addr string) (netproxy.Conn, error) {
			mu.Lock()
			startedAt[addr] = time.Now()
			mu.Unlock()

			switch addr {
			case "198.51.100.10:443":
				<-ctx.Done()
				close(canceled[addr])
				return nil, ctx.Err()
			case "198.51.100.20:443":
				<-ctx.Done()
				close(canceled[addr])
				return nil, ctx.Err()
			case "198.51.100.30:443":
				return winConn, nil
			default:
				return nil, stderrors.New("unexpected addr")
			}
		}

		dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())
		conn, err := dialer.DialContext(context.Background(), "tcp", "proxy.example:443")
		if err != nil {
			t.Fatalf("DialContext() error = %v", err)
		}
		if conn != winConn {
			t.Fatalf("DialContext() returned %#v, want winConn", conn)
		}
		if winConn.closed.Load() {
			t.Fatal("winning conn was closed")
		}
		if got := dialer.GetCachedProxyAddr("tcp"); got != "198.51.100.30:443" {
			t.Fatalf("cached winner = %q, want 198.51.100.30:443", got)
		}

		for _, loser := range []string{"198.51.100.10:443", "198.51.100.20:443"} {
			select {
			case <-canceled[loser]:
			case <-time.After(time.Second):
				t.Fatalf("loser %s was not canceled promptly", loser)
			}
		}

		mu.Lock()
		delay := startedAt["198.51.100.30:443"].Sub(startedAt["198.51.100.10:443"])
		mu.Unlock()
		if delay < 200*time.Millisecond {
			t.Fatalf("secondary launch delay = %v, want ~250ms head start", delay)
		}
	})

	t.Run("early primary failure launches remaining immediately without waiting 250ms", func(t *testing.T) {
		parent := &recordingLookupDialer{
			lookupResult: []net.IPAddr{
				{IP: net.ParseIP("198.51.100.10")},
				{IP: net.ParseIP("198.51.100.20")},
			},
		}
		parent.dialContextFunc = func(_ context.Context, _ string, addr string) (netproxy.Conn, error) {
			if addr == "198.51.100.10:443" {
				return nil, stderrors.New("connection refused")
			}
			return nopConn{}, nil
		}

		dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())
		start := time.Now()
		conn, err := dialer.DialContext(context.Background(), "tcp", "proxy.example:443")
		elapsed := time.Since(start)
		if err != nil || conn == nil {
			t.Fatalf("DialContext() = (%v, %v), want success", conn, err)
		}
		if elapsed >= 150*time.Millisecond {
			t.Fatalf("DialContext() took %v after immediate primary failure, want < 150ms", elapsed)
		}
	})

	t.Run("simultaneous winner closes losing conn without leak", func(t *testing.T) {
		conn1 := &closeCountingConn{id: "c1"}
		conn2 := &closeCountingConn{id: "c2"}
		parent := &recordingLookupDialer{
			lookupResult: []net.IPAddr{
				{IP: net.ParseIP("198.51.100.10")},
				{IP: net.ParseIP("198.51.100.20")},
			},
		}
		ready := make(chan struct{})
		var gate sync.Once
		parent.dialContextFunc = func(_ context.Context, _ string, addr string) (netproxy.Conn, error) {
			if addr == "198.51.100.10:443" {
				<-ready
				return conn1, nil
			}
			gate.Do(func() { close(ready) })
			return conn2, nil
		}

		dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())
		winner, err := dialer.DialContext(context.Background(), "tcp", "proxy.example:443")
		if err != nil {
			t.Fatalf("DialContext() error = %v", err)
		}

		// Wait briefly for the concurrent loser to observe outcomeDone and close.
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			if conn1.closed.Load() != conn2.closed.Load() {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if winner == conn1 {
			if conn1.closed.Load() || !conn2.closed.Load() {
				t.Fatalf("expected conn1 open (%v) and conn2 closed (%v)", conn1.closed.Load(), conn2.closed.Load())
			}
		} else if winner == conn2 {
			if conn2.closed.Load() || !conn1.closed.Load() {
				t.Fatalf("expected conn2 open (%v) and conn1 closed (%v)", conn2.closed.Load(), conn1.closed.Load())
			}
		} else {
			t.Fatalf("unexpected winner %#v", winner)
		}
	})
}
