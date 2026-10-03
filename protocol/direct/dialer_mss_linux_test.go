//go:build linux

package direct

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

func directSocketOpt(t *testing.T, conn interface {
	SyscallConn() (syscall.RawConn, error)
}, level, opt int) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var value int
	var optErr error
	if err := raw.Control(func(fd uintptr) { value, optErr = unix.GetsockoptInt(int(fd), level, opt) }); err != nil {
		t.Fatal(err)
	}
	if optErr != nil {
		t.Fatal(optErr)
	}
	return value
}

func TestDirectTCPMaxSegNegotiation(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, mss := range []int{0, 1380, 1200} {
			for _, fullcone := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/mss%d/fullcone%t", network, mss, fullcone), func(t *testing.T) {
					bind := "127.0.0.1:0"
					if network == "tcp6" {
						bind = "[::1]:0"
					}
					listener, err := net.Listen(network, bind)
					if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EADDRNOTAVAIL) {
						t.Skip("IPv6 unavailable")
					}
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					accepted := make(chan *net.TCPConn, 1)
					go func() {
						c, err := listener.Accept()
						if err != nil {
							accepted <- nil
							return
						}
						accepted <- c.(*net.TCPConn)
					}()
					pair := NewDirectDialersWithOption(Option{TCPMaxSeg: mss})
					dialer := pair.Symmetric
					if fullcone {
						dialer = pair.Fullcone
					}
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					conn, err := dialer.DialContext(ctx, netproxy.MagicNetwork{Network: "tcp", IPVersion: network[3:]}.Encode(), listener.Addr().String())
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					server := <-accepted
					if server == nil {
						t.Fatal("accept failed")
					}
					defer server.Close()
					client := conn.(*net.TCPConn)
					client.SetDeadline(time.Now().Add(3 * time.Second))
					server.SetDeadline(time.Now().Add(3 * time.Second))
					for _, c := range []*net.TCPConn{client, server} {
						got := directSocketOpt(t, c, unix.IPPROTO_TCP, unix.TCP_MAXSEG)
						if got <= 0 || (mss != 0 && got > mss) {
							t.Fatalf("negotiated MSS %d, requested %d", got, mss)
						}
						t.Logf("%s requested=%d negotiated=%d", c.LocalAddr(), mss, got)
					}
					if directSocketOpt(t, client, unix.IPPROTO_TCP, unix.TCP_NODELAY) != 1 {
						t.Fatal("lost Go NODELAY default")
					}
					if directSocketOpt(t, client, unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT) != 0 {
						t.Fatal("enabled TFO")
					}
					payload := bytes.Repeat([]byte("mss-boundary"), 4096)
					done := make(chan error, 1)
					go func() {
						b := make([]byte, len(payload))
						_, err := io.ReadFull(server, b)
						if err == nil && !bytes.Equal(b, payload) {
							err = fmt.Errorf("payload changed")
						}
						if err == nil {
							_, err = server.Write(b)
						}
						done <- err
					}()
					if _, err := client.Write(payload); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, len(payload))
					if _, err := io.ReadFull(client, got); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, payload) {
						t.Fatal("echo changed")
					}
					if err := <-done; err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestTCPMaxSegKeepsMarkAndMPTCPDialer(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	d := NewDirectDialersWithOption(Option{TCPMaxSeg: 1380}).Symmetric.(*directDialer)
	const mark = 0x100
	conn, err := d.dialTcp(context.Background(), listener.Addr().String(), mark, "4", true, false)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("SO_MARK requires privilege: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client := conn.(*net.TCPConn)
	if directSocketOpt(t, client, unix.SOL_SOCKET, unix.SO_MARK) != mark {
		t.Fatal("lost SO_MARK")
	}
	if directSocketOpt(t, client, unix.IPPROTO_TCP, unix.TCP_MAXSEG) > 1380 {
		t.Fatal("lost MSS")
	}
	if d.tcpDialer.Control != nil || d.tcpDialerMptcp.Control != nil || !d.tcpDialerMptcp.MultipathTCP() {
		t.Fatal("mutated cached dialers")
	}
}

func TestTCPMaxSegLeavesResolverAndUDPUnchanged(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	baseline, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer baseline.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	want := directSocketOpt(t, baseline.(*net.TCPConn), unix.IPPROTO_TCP, unix.TCP_MAXSEG)
	d := NewDirectDialersWithOption(Option{TCPMaxSeg: 1380, FallbackDNS: listener.Addr().String()}).Symmetric.(*directDialer)
	resolverConn, err := d.createResolver(0, true).Dial(context.Background(), "tcp4", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	defer resolverConn.Close()
	resolverServer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer resolverServer.Close()
	if got := directSocketOpt(t, resolverConn.(*net.TCPConn), unix.IPPROTO_TCP, unix.TCP_MAXSEG); got != want {
		t.Fatalf("resolver MSS changed: %d, baseline %d", got, want)
	}
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	conn, err := d.DialContext(context.Background(), netproxy.MagicNetwork{Network: "udp", IPVersion: "4"}.Encode(), server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("udp-with-tcp-option")); err != nil {
		t.Fatal(err)
	}
	var b [64]byte
	n, _, err := server.ReadFromUDP(b[:])
	if err != nil || string(b[:n]) != "udp-with-tcp-option" {
		t.Fatalf("UDP = %q, %v", b[:n], err)
	}
}
