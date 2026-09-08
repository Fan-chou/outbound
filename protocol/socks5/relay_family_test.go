package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
)

type relayFamilyDialer struct {
	next netproxy.Dialer
	udp  *netproxy.MagicNetwork
}

func (d *relayFamilyDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	m, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	if m.Network == "udp" {
		copy := *m
		d.udp = &copy
	}
	// Verify mark propagation without requiring SO_MARK privileges in CI.
	m.Mark = 0
	return d.next.DialContext(ctx, m.Encode(), addr)
}

func TestUDPRelayFamilyIndependentOfControlAndTarget(t *testing.T) {
	for _, relay6 := range []bool{false, true} {
		for _, full := range []bool{false, true} {
			t.Run(fmt.Sprintf("relay6=%v_fullcone=%v", relay6, full), func(t *testing.T) {
				ctrl, relayAddr, hint, inner := "[::1]:0", "127.0.0.1:0", "6", "[2001:db8::100]:27015"
				if relay6 {
					ctrl, relayAddr, hint, inner = "127.0.0.1:0", "[::1]:0", "4", "203.0.113.100:27015"
				}
				relay, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(relayAddr)))
				if err != nil {
					t.Fatal(err)
				}
				defer relay.Close()
				_ = relay.SetDeadline(time.Now().Add(3 * time.Second))
				ln, err := net.Listen("tcp", ctrl)
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				served := make(chan error, 1)
				go func() { served <- serveRelayFamilyHandshake(ln, relay.LocalAddr().(*net.UDPAddr).AddrPort()) }()
				next := direct.SymmetricDirect
				if full {
					next = direct.FullconeDirect
				}
				base := &relayFamilyDialer{next: next}
				d, err := NewSocks5("socks5://"+ln.Addr().String(), base)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				conn, err := d.DialContext(ctx, netproxy.MagicNetwork{Network: "udp", IPVersion: hint, Mark: 0x123, Mptcp: true}.Encode(), inner)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				if base.udp == nil || base.udp.IPVersion != "" || base.udp.Mark != 0x123 || !base.udp.Mptcp {
					t.Fatalf("wrong relay network: %+v", base.udp)
				}
				pc := conn.(netproxy.PacketConn)
				if _, err := pc.WriteTo([]byte("game-packet"), inner); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 256)
				n, from, err := relay.ReadFromUDPAddrPort(buf)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := relay.WriteToUDPAddrPort(buf[:n], from); err != nil {
					t.Fatal(err)
				}
				n, peer, err := pc.ReadFrom(buf)
				if err != nil {
					t.Fatal(err)
				}
				if string(buf[:n]) != "game-packet" || peer.String() != inner {
					t.Fatalf("lost inner target: payload=%q peer=%s", buf[:n], peer)
				}
				_ = conn.Close()
				select {
				case err := <-served:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("control connection did not close")
				}
			})
		}
	}
}

func serveRelayFamilyHandshake(ln net.Listener, relay netip.AddrPort) error {
	c, err := ln.Accept()
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	h := make([]byte, 4)
	if _, err = io.ReadFull(c, h[:2]); err != nil {
		return err
	}
	if _, err = io.CopyN(io.Discard, c, int64(h[1])); err != nil {
		return err
	}
	if _, err = c.Write([]byte{5, 0}); err != nil {
		return err
	}
	if _, err = io.ReadFull(c, h); err != nil {
		return err
	}
	n := int64(0)
	switch h[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		if _, err = io.ReadFull(c, h[:1]); err != nil {
			return err
		}
		n = int64(h[0])
	default:
		return fmt.Errorf("bad address type: %d", h[3])
	}
	if _, err = io.CopyN(io.Discard, c, n+2); err != nil {
		return err
	}
	typ := byte(1)
	if relay.Addr().Is6() {
		typ = 4
	}
	reply := append([]byte{5, 0, 0, typ}, relay.Addr().AsSlice()...)
	reply = append(reply, byte(relay.Port()>>8), byte(relay.Port()))
	if _, err = c.Write(reply); err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, c)
	return err
}
