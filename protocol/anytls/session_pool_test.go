package anytls

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type writeCountConn struct {
	net.Conn
	writes atomic.Int32
}

func (c *writeCountConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(p)
}

func TestIdlePoolLIFOAndCapacitySix(t *testing.T) {
	d := &Dialer{
		idleSessions: make(map[uint64]*session),
		sessions:     make(map[uint64]*session),
	}
	defer d.Close()

	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()

	now := time.Now()
	for i := uint64(1); i <= 7; i++ {
		c1, c2 := net.Pipe()
		conns = append(conns, c1, c2)
		s := newSession(c1, i)
		s.owner = d
		s.state.Store(sessionStateIdle)
		s.idleAt.Store(now.Add(time.Duration(i) * time.Millisecond).UnixNano())
		d.sessions[i] = s
		shouldClose := d.sessionIdle(s)
		if i <= maxIdleSessions && shouldClose {
			t.Fatalf("session %d rejected while pool < %d", i, maxIdleSessions)
		}
		if i > maxIdleSessions && !shouldClose {
			t.Fatalf("session %d accepted beyond maxIdleSessions=%d", i, maxIdleSessions)
		}
	}

	// LIFO: popping should return seq=6 first, then 5, 4, 3, 2, 1.
	for want := uint64(maxIdleSessions); want >= 1; want-- {
		got, err := d.popIdleSessionForReuse()
		if err != nil {
			t.Fatalf("popIdleSessionForReuse: %v", err)
		}
		if got == nil || got.seq != want {
			t.Fatalf("popped seq = %v, want %d", got, want)
		}
	}
}

func TestResetTransportEvictsIdleSessionsOnly(t *testing.T) {
	d := &Dialer{
		idleSessions: make(map[uint64]*session),
		sessions:     make(map[uint64]*session),
	}
	defer d.Close()

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	s := newSession(c1, 1)
	s.owner = d
	s.state.Store(sessionStateIdle)
	s.idleAt.Store(time.Now().UnixNano())
	d.sessions[1] = s
	if d.sessionIdle(s) {
		t.Fatal("sessionIdle returned true unexpectedly")
	}

	d.ResetTransport()
	if !s.Closed() {
		t.Fatal("ResetTransport did not close idle session")
	}
	if d.closed {
		t.Fatal("ResetTransport marked dialer permanently closed")
	}
	if len(d.idleSessions) != 0 {
		t.Fatalf("idleSessions remaining = %d, want 0", len(d.idleSessions))
	}
}

func TestReusedStreamCoalescesSYNAndInitialPSH(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Drain server reads so writes never block.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()

	wc := &writeCountConn{Conn: client}
	s := newSession(wc, 1)
	s.sendPadding = false
	defer s.Close()

	// First stream (sid=1) sends settings+SYN+PSH in 1 write.
	st1, err := s.newStream("127.0.0.1:80")
	if err != nil {
		t.Fatalf("newStream 1: %v", err)
	}
	defer st1.Close()

	wc.writes.Store(0)
	// Reused stream (sid=2) must coalesce SYN+PSH into 1 carrier Write().
	st2, err := s.newStream("127.0.0.1:80")
	if err != nil {
		t.Fatalf("newStream 2: %v", err)
	}
	defer st2.Close()

	if got := wc.writes.Load(); got != 1 {
		t.Fatalf("reused stream carrier Write() calls = %d, want 1", got)
	}
}
