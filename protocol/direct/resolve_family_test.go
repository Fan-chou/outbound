package direct

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/net/dns/dnsmessage"
)

// Local DNS returns both families, or only the family named in the query.
func familyResolver(t *testing.T) *net.Resolver {
	t.Helper()
	s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	go func() {
		b := make([]byte, 1500)
		for {
			n, peer, err := s.ReadFromUDP(b)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(b[:n]) != nil {
				continue
			}
			r := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true}, Questions: q.Questions}
			for _, question := range q.Questions {
				h := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}
				if question.Type == dnsmessage.TypeA && question.Name.String() != "v6.example." {
					h.Type = dnsmessage.TypeA
					r.Answers = append(r.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}})
				}
				if question.Type == dnsmessage.TypeAAAA && question.Name.String() != "v4.example." {
					h.Type = dnsmessage.TypeAAAA
					ip := [16]byte{}
					ip[15] = 1
					r.Answers = append(r.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AAAAResource{AAAA: ip}})
				}
			}
			out, err := r.Pack()
			if err == nil {
				s.WriteToUDP(out, peer)
			}
		}
	}()
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", s.LocalAddr().String())
	}}
}

func TestDirectUDPResolutionMatchesSocketFamily(t *testing.T) {
	resolver := familyResolver(t)
	for _, version := range []string{"4", "6", ""} {
		t.Run("udp"+version, func(t *testing.T) {
			listenNetwork, listenIP := "udp4", net.IPv4(127, 0, 0, 1)
			if version == "6" {
				listenNetwork, listenIP = "udp6", net.IPv6loopback
			}
			server, err := net.ListenUDP(listenNetwork, &net.UDPAddr{IP: listenIP})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			port := strconv.Itoa(server.LocalAddr().(*net.UDPAddr).Port)
			d := &directDialer{Option: Option{FullCone: true}}
			pc, err := d.dialUdp(context.Background(), "both.example.:"+port, 0, version, false)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			c := pc.(*directPacketConn)
			c.resolver = resolver
			for _, op := range []string{"write", "alternate", "batch", "cached"} {
				payload := []byte(op)
				switch op {
				case "write", "cached":
					_, err = c.Write(payload)
				case "alternate":
					_, err = c.WriteTo(payload, "alternate.example.:"+port)
				case "batch":
					_, err = c.WriteBatch([]netproxy.BatchItem{{Data: payload, Addr: "batch.example.:" + port}})
				}
				if err != nil {
					t.Fatalf("%s: %v", op, err)
				}
				server.SetReadDeadline(time.Now().Add(time.Second))
				buf := make([]byte, 64)
				n, _, e := server.ReadFromUDP(buf)
				if e != nil || string(buf[:n]) != op {
					t.Fatalf("%s delivery: %q %v", op, buf[:n], e)
				}
			}
			if version != "" {
				incompatible := "v6.example.:" + port
				if version == "6" {
					incompatible = "v4.example.:" + port
				}
				if _, err := c.WriteTo([]byte("wrong"), incompatible); err == nil {
					t.Fatal("incompatible DNS answer accepted")
				}
				if _, ok := c.writeTgtCache.Load(incompatible); ok {
					t.Fatal("incompatible target cached")
				}
			} else {
				// The same unrestricted socket must still deliver to an IPv6-only peer.
				v6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
				if err != nil {
					t.Fatal(err)
				}
				defer v6.Close()
				target := "v6.example.:" + strconv.Itoa(v6.LocalAddr().(*net.UDPAddr).Port)
				if _, err := c.WriteTo([]byte("cross"), target); err != nil {
					t.Fatal(err)
				}
				v6.SetReadDeadline(time.Now().Add(time.Second))
				b := make([]byte, 64)
				n, _, err := v6.ReadFromUDP(b)
				if err != nil || string(b[:n]) != "cross" {
					t.Fatalf("dual stack: %q %v", b[:n], err)
				}
			}
		})
	}
}
