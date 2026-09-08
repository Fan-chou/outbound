package direct

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

func newResolveTestConn(t *testing.T) *directPacketConn {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	c := &directPacketConn{UDPConn: socket, FullCone: true, dialTgt: "pending.example:27015", resolver: net.DefaultResolver}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestDirectDNSCancellationForAllWritePaths(t *testing.T) {
	for _, op := range []string{"write", "alternate", "batch"} {
		for _, closeConn := range []bool{false, true} {
			name := op + "/deadline"
			if closeConn {
				name = op + "/close"
			}
			t.Run(name, func(t *testing.T) {
				c := newResolveTestConn(t)
				entered := make(chan struct{})
				var once sync.Once
				// Exercise the actual common resolver: no DNS packet leaves the test.
				c.resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					once.Do(func() { close(entered) })
					<-ctx.Done()
					return nil, ctx.Err()
				}}
				done := make(chan error, 4)
				write := func() {
					var err error
					switch op {
					case "write":
						_, err = c.Write([]byte("x"))
					case "alternate":
						_, err = c.WriteTo([]byte("x"), "other.example:27015")
					case "batch":
						_, err = c.WriteBatch([]netproxy.BatchItem{{Data: []byte("x"), Addr: c.dialTgt}})
					}
					done <- err
				}
				go write()
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("lookup did not start")
				}
				for i := 0; i < 3; i++ {
					go write()
				}
				want := os.ErrDeadlineExceeded
				if closeConn {
					want = net.ErrClosed
					if err := c.Close(); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := c.SetWriteDeadline(time.Now()); err != nil {
						t.Fatal(err)
					}
				}
				for i := 0; i < 4; i++ {
					select {
					case err := <-done:
						if !errors.Is(err, want) {
							t.Fatalf("got %v want %v", err, want)
						}
					case <-time.After(time.Second):
						t.Fatal("DNS or its waiter ignored cancellation")
					}
				}
				if c.cachedDialTgt.Load() != nil {
					t.Fatal("cancelled DNS populated cache")
				}
			})
		}
	}
}

func TestDirectDNSDeadlineChangeAndRetry(t *testing.T) {
	for _, mode := range []string{"extend", "clear", "shorten"} {
		t.Run(mode, func(t *testing.T) {
			c := newResolveTestConn(t)
			server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			entered, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			var once sync.Once
			old := resolveUDPAddr
			t.Cleanup(func() { resolveUDPAddr = old })
			resolveUDPAddr = func(ctx context.Context, _ *net.Resolver, _ string) (*net.UDPAddr, error) {
				calls.Add(1)
				once.Do(func() { close(entered) })
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-release:
					return server.LocalAddr().(*net.UDPAddr), nil
				}
			}
			initial := time.Now().Add(250 * time.Millisecond)
			if mode == "shorten" {
				initial = time.Now().Add(5 * time.Second)
			}
			if err := c.SetDeadline(initial); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := c.Write([]byte("first")); done <- err }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("DNS did not start")
			}
			switch mode {
			case "extend":
				err = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
			case "clear":
				err = c.SetDeadline(time.Time{})
			case "shorten":
				err = c.SetDeadline(time.Now().Add(20 * time.Millisecond))
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "shorten" {
				select {
				case err := <-done:
					if !errors.Is(err, os.ErrDeadlineExceeded) {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("shortened deadline ignored")
				}
				if c.cachedDialTgt.Load() != nil {
					t.Fatal("timeout cached a target")
				}
				if err := c.SetWriteDeadline(time.Time{}); err != nil {
					t.Fatal(err)
				}
				close(release)
				if _, err := c.Write([]byte("retry")); err != nil {
					t.Fatal(err)
				}
			} else {
				select {
				case err := <-done:
					t.Fatalf("old deadline fired after %s: %v", mode, err)
				case <-time.After(time.Until(initial) + 50*time.Millisecond):
				}
				close(release)
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("DNS did not finish")
				}
			}
			n := calls.Load()
			if _, err := c.Write([]byte("cached")); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != n {
				t.Fatal("successful lookup was not cached")
			}
			if mode == "shorten" && n != 2 {
				t.Fatalf("retry lookups=%d want 2", n)
			}
		})
	}
}
