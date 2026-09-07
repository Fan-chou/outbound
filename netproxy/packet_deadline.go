package netproxy

import (
	"context"
	"net"
	"os"
	"sync"
	"time"
)

// PacketDeadline provides a reusable, independently cancellable I/O direction.
// Extending or clearing a pending deadline keeps its context alive. After expiry,
// a new context is used for subsequent operations. The zero value is ready to use.
// Contexts and timers are per deadline generation, not per datagram.
type PacketDeadline struct {
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelCauseFunc
	timer      *time.Timer
	generation uint64
	closed     bool
}

func (d *PacketDeadline) Context() context.Context {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ctx == nil {
		d.ctx, d.cancel = context.WithCancelCause(context.Background())
		if d.closed {
			d.cancel(net.ErrClosed)
		}
	}
	return d.ctx
}

func (d *PacketDeadline) Set(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return net.ErrClosed
	}
	d.generation++
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	if d.ctx == nil || d.ctx.Err() != nil {
		d.ctx, d.cancel = context.WithCancelCause(context.Background())
	}
	if t.IsZero() {
		return nil
	}
	delay := time.Until(t)
	if delay <= 0 {
		d.cancel(os.ErrDeadlineExceeded)
		return nil
	}
	gen := d.generation
	d.timer = time.AfterFunc(delay, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if gen == d.generation && !d.closed {
			d.cancel(os.ErrDeadlineExceeded)
			d.timer = nil
		}
	})
	return nil
}

func (d *PacketDeadline) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	d.generation++
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	if d.cancel != nil {
		d.cancel(net.ErrClosed)
	}
}

// IndependentPacketWriteDeadline identifies datagram transports whose write
// deadline cancels only the current I/O direction, not the logical session.
type IndependentPacketWriteDeadline interface {
	SupportsIndependentPacketWriteDeadline() bool
}
