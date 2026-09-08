package direct

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

type pendingResolution struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	done   chan struct{}
	addr   netip.AddrPort
	err    error
}

type directResolveState struct {
	resolveMu     sync.Mutex
	closed        bool
	writeDeadline time.Time
	writeTimer    *time.Timer
	resolving     map[string]*pendingResolution
}

// resolveAddr shares a pending lookup without holding a mutex during DNS or
// while waiting. Closed/timed-out lookups never poison the successful caches.
func (c *directPacketConn) resolveAddr(target string) (netip.AddrPort, error) {
	c.resolveMu.Lock()
	if c.closed {
		c.resolveMu.Unlock()
		return netip.AddrPort{}, net.ErrClosed
	}
	if !c.writeDeadline.IsZero() && !time.Now().Before(c.writeDeadline) {
		c.resolveMu.Unlock()
		return netip.AddrPort{}, os.ErrDeadlineExceeded
	}
	if addr, ok := c.cachedTarget(target); ok {
		c.resolveMu.Unlock()
		return addr, nil
	}
	if f := c.resolving[target]; f != nil && f.ctx.Err() == nil {
		c.resolveMu.Unlock()
		select {
		case <-f.done:
			return f.addr, f.err
		case <-f.ctx.Done():
			return netip.AddrPort{}, context.Cause(f.ctx)
		}
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	f := &pendingResolution{ctx: ctx, cancel: cancel, done: make(chan struct{})}
	if c.resolving == nil {
		c.resolving = make(map[string]*pendingResolution)
	}
	c.resolving[target] = f
	c.armResolutionDeadlineLocked()
	c.resolveMu.Unlock()

	network := c.resolveNetwork
	if network == "" {
		network = "ip"
	}
	addr, err := resolveUDPAddr(ctx, c.resolver, network, target)
	c.resolveMu.Lock()
	if cause := context.Cause(ctx); cause != nil {
		err = cause
	}
	if err == nil {
		ap := addr.AddrPort()
		f.addr = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		if target == c.dialTgt {
			c.cachedDialTgt.Store(f.addr)
		} else {
			c.writeTgtCache.Store(target, f.addr)
		}
	}
	f.err = err
	if c.resolving[target] == f {
		delete(c.resolving, target)
	}
	if len(c.resolving) == 0 && c.writeTimer != nil {
		c.writeTimer.Stop()
		c.writeTimer = nil
	}
	close(f.done)
	c.resolveMu.Unlock()
	return f.addr, f.err
}

func (c *directPacketConn) armResolutionDeadlineLocked() {
	if c.writeTimer != nil {
		c.writeTimer.Stop()
		c.writeTimer = nil
	}
	if c.closed || c.writeDeadline.IsZero() || len(c.resolving) == 0 {
		return
	}
	if !time.Now().Before(c.writeDeadline) {
		for _, f := range c.resolving {
			f.cancel(os.ErrDeadlineExceeded)
		}
		return
	}
	c.writeTimer = time.AfterFunc(time.Until(c.writeDeadline), func() {
		c.resolveMu.Lock()
		defer c.resolveMu.Unlock()
		// A timer stopped during a deadline change may already be running.
		if c.closed || c.writeDeadline.IsZero() || time.Now().Before(c.writeDeadline) {
			return
		}
		for _, f := range c.resolving {
			f.cancel(os.ErrDeadlineExceeded)
		}
	})
}

func (c *directPacketConn) cancelResolution() {
	c.resolveMu.Lock()
	defer c.resolveMu.Unlock()
	c.closed = true
	if c.writeTimer != nil {
		c.writeTimer.Stop()
		c.writeTimer = nil
	}
	for _, f := range c.resolving {
		f.cancel(net.ErrClosed)
	}
}

func (c *directPacketConn) SetWriteDeadline(t time.Time) error { return c.setDeadline(t, false) }
func (c *directPacketConn) SetDeadline(t time.Time) error      { return c.setDeadline(t, true) }
func (c *directPacketConn) setDeadline(t time.Time, both bool) error {
	c.resolveMu.Lock()
	defer c.resolveMu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	var err error
	if both {
		err = c.UDPConn.SetDeadline(t)
	} else {
		err = c.UDPConn.SetWriteDeadline(t)
	}
	if err != nil {
		return err
	}
	c.writeDeadline = t
	c.armResolutionDeadlineLocked()
	return nil
}

// CancelPendingPacketWrites lets a retiring owner unblock DNS and socket writes
// before waiting for a batch flusher. Read-side teardown remains owned by Close.
func (c *directPacketConn) CancelPendingPacketWrites() { _ = c.SetWriteDeadline(time.Now()) }
