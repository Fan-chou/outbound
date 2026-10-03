package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	utls "github.com/refraction-networking/utls"
)

func TestRealityBackoffExpiresDuringContinuousTraffic(t *testing.T) {
	for _, hybrid := range []bool{false, true} {
		x := &Reality{}
		x.pqHybrid.Store(hybrid)
		start := time.Unix(1000, 0)
		x.pqRetryAfter.Store(start.Add(realityBothShapesBackoff).Unix())
		for step := time.Minute; step < realityBothShapesBackoff; step += time.Minute {
			if x.claimHelloProbe(start.Add(step)) {
				t.Fatalf("hybrid=%v bypassed backoff", hybrid)
			}
		}
		if !x.claimHelloProbe(start.Add(realityBothShapesBackoff)) {
			t.Fatalf("hybrid=%v never recovered probe eligibility", hybrid)
		}
		x.pqProbing.Store(false)
	}
}

func TestRealityAlternateProbeHasSingleOwner(t *testing.T) {
	x := &Reality{}
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if x.claimHelloProbe(time.Unix(1000, 0)) {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != 1 {
		t.Fatalf("alternate probes admitted=%d", admitted.Load())
	}
}

type helloRetryConn struct {
	closed    atomic.Int32
	writes    atomic.Int32
	premature atomic.Bool
}

func (c *helloRetryConn) Read([]byte) (int, error) { return 0, errRealityStubConnect }
func (c *helloRetryConn) Write(p []byte) (int, error) {
	if c.closed.Load() != 0 {
		c.premature.Store(true)
		return 0, net.ErrClosed
	}
	c.writes.Add(1)
	return len(p), nil
}
func (c *helloRetryConn) Close() error                   { c.closed.Add(1); return nil }
func (*helloRetryConn) SetDeadline(time.Time) error      { return nil }
func (*helloRetryConn) SetReadDeadline(time.Time) error  { return nil }
func (*helloRetryConn) SetWriteDeadline(time.Time) error { return nil }

type helloRetryDialer struct{ c *helloRetryConn }

func (d helloRetryDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return d.c, nil
}

func TestRealityDialRandomHelloKeepsUnderlayUntilHandshake(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Drive the actual DialContext, including hello rebuilding and its first
	// network write. The peer deliberately fails before authentication.
	for range 64 {
		conn := &helloRetryConn{}
		fp := utls.HelloRandomized
		x := &Reality{nextDialer: helloRetryDialer{conn}, fingerprint: &fp, serverName: "example.com", publicKey: key.PublicKey()}
		_, err := x.DialContext(context.Background(), "tcp", "example.com:443")
		if err == nil || conn.premature.Load() || conn.closed.Load() != 1 {
			t.Fatalf("closed=%d premature=%v err=%v", conn.closed.Load(), conn.premature.Load(), err)
		}
		if conn.writes.Load() > 0 && !errors.Is(err, errRealityStubConnect) {
			t.Fatalf("handshake failed before reaching peer: %v", err)
		}
	}
}
