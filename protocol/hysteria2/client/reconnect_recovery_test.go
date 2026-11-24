package client

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

func TestSilentBlackholeCircuitBreaker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	conn := &closeTrackingQuicConn{ctx: ctx, cancel: cancel}
	pktConn := &closeTrackingPacketConn{}
	c := &clientImpl{
		conn:    conn,
		pktConn: pktConn,
	}

	// Single timeout must NOT tear down the tunnel.
	c.recordStreamError(timeoutNetError{}, conn)
	if got := conn.closes.Load(); got != 0 {
		t.Fatalf("closed after 1 timeout = %d, want 0", got)
	}

	// A healthy stream response resets the counter.
	c.recordStreamSuccess(conn)
	c.recordStreamError(timeoutNetError{}, conn)
	if got := conn.closes.Load(); got != 0 {
		t.Fatalf("closed after reset + 1 timeout = %d, want 0", got)
	}

	// 2nd and 3rd consecutive timeouts trip the hard consecutive circuit breaker.
	c.recordStreamError(timeoutNetError{}, conn)
	if got := conn.closes.Load(); got != 0 {
		t.Fatalf("closed after 2 immediate timeouts = %d, want 0", got)
	}
	c.recordStreamError(timeoutNetError{}, conn)
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("closed after 3 consecutive timeouts = %d, want 1", got)
	}
	if got := pktConn.closes.Load(); got != 1 {
		t.Fatalf("pktConn closed = %d, want 1", got)
	}
}

func TestResetTransportClosesExistingWithoutClosingClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	conn := &closeTrackingQuicConn{ctx: ctx, cancel: cancel}
	pktConn := &closeTrackingPacketConn{}
	c := &clientImpl{
		conn:    conn,
		pktConn: pktConn,
	}

	c.ResetTransport()
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("QUIC closes = %d, want 1", got)
	}
	if got := pktConn.closes.Load(); got != 1 {
		t.Fatalf("pktConn closes = %d, want 1", got)
	}
	if c.closed {
		t.Fatal("ResetTransport marked client permanently closed")
	}
}

func TestEnsureConnectedSingleflightHonorsShortCallerContext(t *testing.T) {
	var newConnCalls atomic.Int32
	gate := make(chan struct{})
	cfg := &Config{
		ConnFactory: &UdpConnFactory{
			NewFunc: func(ctx context.Context) (net.PacketConn, error) {
				newConnCalls.Add(1)
				select {
				case <-gate:
					return nil, errors.New("dial finished")
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			},
		},
		ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443},
	}
	rawClient, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c := rawClient.(*clientImpl)
	defer c.Close()

	// Start a long-lived caller that triggers the singleflight connect.
	longDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := c.TCP("127.0.0.1:80", ctx)
		longDone <- err
	}()

	// Wait until the singleflight connect is in flight.
	deadline := time.Now().Add(time.Second)
	for newConnCalls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	// Launch 8 short-ctx callers: every single one must cancel right at ~30ms,
	// without waiting for the blocked handshake and without triggering extra dials.
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			t0 := time.Now()
			_, err := c.TCP("127.0.0.1:80", ctx)
			dur := time.Since(t0)
			if !errors.Is(err, context.DeadlineExceeded) {
				errs <- errors.New("expected DeadlineExceeded, got: " + err.Error())
				return
			}
			if dur > 250*time.Millisecond {
				errs <- errors.New("short caller blocked too long: " + dur.String())
				return
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	close(gate)
	<-longDone

	if got := newConnCalls.Load(); got != 1 {
		t.Fatalf("ConnFactory.New calls = %d, want 1 (singleflight)", got)
	}
}
