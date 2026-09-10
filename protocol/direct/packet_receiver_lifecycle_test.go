//go:build linux

package direct

import (
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// Pause inside the real socket's Control callback, after drain's active check.
// This models a receiver descheduled immediately before its nonblocking read.
type pausedReceiverRawConn struct {
	syscall.RawConn
	entered chan struct{}
	resume  chan struct{}
}

func (r *pausedReceiverRawConn) Control(f func(uintptr)) error {
	return r.RawConn.Control(func(fd uintptr) {
		close(r.entered)
		<-r.resume
		f(fd)
	})
}

func TestDirectPacketReceiverCloseProtectsInFlightRead(t *testing.T) {
	old := mustListenDirectReceiverUDP(t)
	defer old.Close()
	sender := mustListenDirectReceiverUDP(t)
	defer sender.Close()
	raw, err := old.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	paused := &pausedReceiverRawConn{RawConn: raw, entered: make(chan struct{}), resume: make(chan struct{})}
	entry := &directPacketReceiverEntry{raw: paused}
	entry.receiveCallback = entry.receiveProtected
	entry.active.Store(true)
	entry.handler = func(p *netproxy.ReceivedPacket) bool { p.Release(); return true }
	stopped := make(chan struct{})
	conn := &directPacketConn{UDPConn: old, receiverStop: func() { entry.active.Store(false); close(stopped) }}
	writeDirectReceiverPacket(t, sender, old, []byte("old"))
	drained := make(chan struct{})
	go func() { defer close(drained); (&packetReceiverRegistry{}).drain(entry) }()
	select {
	case <-paused.entered:
	case <-time.After(time.Second):
		t.Fatal("read did not start")
	}
	closed := make(chan struct{})
	go func() { defer close(closed); _ = conn.Close() }()
	// Always release the paused read, including on an assertion failure.
	var resumeOnce sync.Once
	resume := func() { resumeOnce.Do(func() { close(paused.resume) }); <-drained; <-closed }
	defer resume()
	<-stopped
	select {
	case <-closed:
		t.Fatal("socket closed during protected read")
	case <-time.After(10 * time.Millisecond):
	}
	fresh := mustListenDirectReceiverUDP(t)
	defer fresh.Close()
	writeDirectReceiverPacket(t, sender, fresh, []byte("new"))
	resume()
	if err := fresh.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, _, err := fresh.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "new" {
		t.Fatalf("new socket packet: data=%q err=%v", buf[:n], err)
	}
}

func TestDirectPacketReceiverHandlerCanCloseSocket(t *testing.T) {
	sender := mustListenDirectReceiverUDP(t)
	defer sender.Close()
	socket := mustListenDirectReceiverUDP(t)
	conn := &directPacketConn{UDPConn: socket, FullCone: true, receiver: defaultPacketReceiverRegistry}
	defer conn.Close()
	closed := make(chan error, 1)
	_, ok := conn.RegisterPacketReceiver(func(p *netproxy.ReceivedPacket) bool {
		err := conn.Close()
		p.Release()
		closed <- err
		return true
	})
	if !ok {
		t.Fatal("register failed")
	}
	writeDirectReceiverPacket(t, sender, socket, []byte("close"))
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("callback close deadlocked")
	}
}
