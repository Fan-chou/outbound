package tuic

import (
	"context"
	"errors"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/olicesx/quic-go"
	"net"
	"os"
	"testing"
	"time"
)

type cancellableDatagramConn struct {
	quic.Connection
	entered chan struct{}
	block   bool
}

func (c *cancellableDatagramConn) SendDatagramContext(ctx context.Context, _ []byte) error {
	if c.entered != nil {
		close(c.entered)
		c.entered = nil
	}
	if !c.block {
		return context.Cause(ctx)
	}
	<-ctx.Done()
	return context.Cause(ctx)
}
func (c *cancellableDatagramConn) OpenUniStream() (quic.SendStream, error) { return nil, net.ErrClosed }

func TestPacketWriteDeadlineAndCloseAreSessionLocal(t *testing.T) {
	transport := &cancellableDatagramConn{entered: make(chan struct{}), block: true}
	q := &quicStreamPacketConn{quicConn: transport, incomingPackets: NewPackets(), udpRelayMode: common.NATIVE}
	defer q.Close()
	entered := transport.entered
	written := make(chan error, 1)
	go func() { _, err := q.WriteTo([]byte("tick"), "192.0.2.1:27015"); written <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("send not entered")
	}
	if err := q.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-written:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("write did not time out")
	}
	if q.closed.Load() {
		t.Fatal("write deadline closed association")
	}
	if q.readDeadline.Context().Err() != nil {
		t.Fatal("write deadline cancelled read")
	}
	if err := q.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	transport.entered = make(chan struct{})
	entered = transport.entered
	go func() { _, err := q.WriteTo([]byte("tick"), "192.0.2.1:27015"); written <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("send not entered")
	}
	closed := make(chan struct{})
	go func() { _ = q.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close blocked on pending send")
	}
	select {
	case err := <-written:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("write did not cancel")
	}
}

func TestPacketReadDeadlineKeepsAssociation(t *testing.T) {
	q := &quicStreamPacketConn{incomingPackets: NewPackets()}
	defer q.Close()
	result := make(chan error, 1)
	go func() { _, _, err := q.ReadFrom(make([]byte, 128)); result <- err }()
	if err := q.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("read did not time out")
	}
	if q.closed.Load() || q.writeDeadline.Context().Err() != nil {
		t.Fatal("read deadline closed other direction")
	}
	if err := q.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if q.readDeadline.Context().Err() != nil {
		t.Fatal("read deadline not cleared")
	}
}
