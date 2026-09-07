package netproxy

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestPacketDeadlineUpdateClearAndClose(t *testing.T) {
	var d PacketDeadline
	ctx := d.Context()
	if err := d.Set(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := d.Set(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
		t.Fatal("old deadline fired after extension")
	case <-time.After(40 * time.Millisecond):
	}
	if err := d.Set(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if d.Context() != ctx {
		t.Fatal("clearing a live deadline must preserve pending context")
	}
	if err := d.Set(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(context.Cause(ctx), os.ErrDeadlineExceeded) {
		t.Fatal(context.Cause(ctx))
	}
	if err := d.Set(time.Time{}); err != nil {
		t.Fatal(err)
	}
	next := d.Context()
	if next.Err() != nil {
		t.Fatal(next.Err())
	}
	d.Close()
	if !errors.Is(context.Cause(next), net.ErrClosed) {
		t.Fatal(context.Cause(next))
	}
	if !errors.Is(d.Set(time.Time{}), net.ErrClosed) {
		t.Fatal("closed direction resurrected")
	}
}
