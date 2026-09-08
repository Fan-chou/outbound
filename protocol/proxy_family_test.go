package protocol_test

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	h "github.com/daeuniverse/outbound/protocol/http"
	"github.com/daeuniverse/outbound/protocol/juicity"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	s22 "github.com/daeuniverse/outbound/protocol/shadowsocks_2022"
	ss "github.com/daeuniverse/outbound/protocol/shadowsocks_stream"
	"github.com/daeuniverse/outbound/protocol/socks5"
	"github.com/daeuniverse/outbound/protocol/tuic"
	"io"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"
)

var errFamilyAuditStop = errors.New("stop after checking outer socket")

type familyProbe struct {
	mu    sync.Mutex
	calls int
	t     *testing.T
	proxy string
}

func (p *familyProbe) DialContext(ctx context.Context, n, a string) (netproxy.Conn, error) {
	mn, e := netproxy.ParseMagicNetwork(n)
	if e != nil {
		return nil, e
	}
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	if a != p.proxy || mn.IPVersion != "" || mn.Mark != 123 || !mn.Mptcp {
		p.t.Errorf("outer hop: addr=%s network=%+v", a, mn)
	}
	// Assert the policy mark above, then omit it for unprivileged CI socket creation.
	mn.Mark = 0
	c, e := direct.SymmetricDirect.DialContext(ctx, mn.Encode(), a)
	if e != nil {
		p.t.Errorf("outer socket: %v", e)
		return nil, e
	}
	c.Close()
	return nil, errFamilyAuditStop
}
func familyDialer(name, proxy string, p netproxy.Dialer) (netproxy.Dialer, error) {
	head := protocol.Header{ProxyAddress: proxy, Cipher: "aes-128-gcm", Password: "audit-only", User: "00000000-0000-0000-0000-000000000001", Feature1: "bbr", TlsConfig: &tls.Config{ServerName: "audit.test"}, IsClient: true}
	var d netproxy.Dialer
	var e error
	switch name {
	case "ss":
		d, e = shadowsocks.NewDialer(p, head)
	case "ss2022":
		head.Cipher = "2022-blake3-aes-128-gcm"
		head.Password = "AAAAAAAAAAAAAAAAAAAAAA=="
		d, e = s22.NewDialer(p, head)
	case "ss-stream":
		head.Cipher = "aes-128-cfb"
		d, e = ss.NewDialer(p, head)
	case "socks5":
		d, e = socks5.NewSocks5("socks5://"+proxy, p)
	case "http", "https":
		u, _ := url.Parse(name + "://" + proxy)
		d, e = h.NewHTTPProxy(u, p)
	case "tuic":
		d, e = tuic.NewDialer(p, head)
	case "juicity":
		d, e = juicity.NewDialer(p, head)
	}
	return d, e
}
func TestProxyHopAddressFamily(t *testing.T) {
	for _, name := range []string{"ss", "ss2022", "ss-stream", "socks5", "http", "https", "tuic", "juicity"} {
		for _, l4 := range []string{"tcp", "udp"} {
			if (name == "http" || name == "https" || name == "socks5") && l4 == "udp" {
				continue
			}
			for _, families := range []struct{ outer, inner string }{{"4", "6"}, {"6", "4"}, {"4", "4"}} {
				t.Run(name+"/"+l4+"/outer"+families.outer+"-inner"+families.inner, func(t *testing.T) {
					ip := "127.0.0.1"
					if families.outer == "6" {
						ip = "::1"
					}
					// A real listener makes TCP connection success distinguishable from a bad family.
					ln, e := net.Listen("tcp"+families.outer, net.JoinHostPort(ip, "0"))
					if e != nil {
						t.Fatal(e)
					}
					defer ln.Close()
					p := &familyProbe{t: t, proxy: ln.Addr().String()}
					d, e := familyDialer(name, p.proxy, p)
					if e != nil {
						t.Fatal(e)
					}
					if closer, ok := d.(io.Closer); ok {
						defer closer.Close()
					}
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					target := "[2001:db8::1]:443"
					if families.inner == "4" {
						target = "192.0.2.1:443"
					}
					c, e := d.DialContext(ctx, (netproxy.MagicNetwork{Network: l4, IPVersion: families.inner, Mark: 123, Mptcp: true}).Encode(), target)
					if c != nil {
						c.SetWriteDeadline(time.Now().Add(time.Second))
						_, e = c.Write([]byte("check"))
						c.Close()
					}
					if !errors.Is(e, errFamilyAuditStop) {
						t.Errorf("unexpected protocol result: %v", e)
					}
					p.mu.Lock()
					defer p.mu.Unlock()
					if p.calls == 0 {
						t.Fatal("outer socket was not exercised")
					}
				})
			}
		}
	}
}

// A Shadowsocks server reached through SOCKS5 is a target of the SOCKS hop;
// neither that server nor the application target fixes the physical hop family.
type familyHopRecorder struct {
	netproxy.Dialer
	target string
}

func (r *familyHopRecorder) DialContext(ctx context.Context, network, target string) (netproxy.Conn, error) {
	r.target = target
	return r.Dialer.DialContext(ctx, network, target)
}
func TestProxyHopFamilyInChain(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	p := &familyProbe{t: t, proxy: ln.Addr().String()}
	socks, err := familyDialer("socks5", p.proxy, p)
	if err != nil {
		t.Fatal(err)
	}
	hop := &familyHopRecorder{Dialer: socks}
	const ssServer = "[::1]:34564"
	d, err := familyDialer("ss", ssServer, hop)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = d.DialContext(ctx, (netproxy.MagicNetwork{Network: "tcp", IPVersion: "6", Mark: 123, Mptcp: true}).Encode(), "[2001:db8::1]:443")
	if !errors.Is(err, errFamilyAuditStop) {
		t.Fatal(err)
	}
	if hop.target != ssServer {
		t.Fatalf("chain lost intermediate target: %s", hop.target)
	}
	if p.calls != 1 {
		t.Fatalf("outer calls=%d", p.calls)
	}
}
