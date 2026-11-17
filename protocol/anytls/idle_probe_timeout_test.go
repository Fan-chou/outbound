package anytls

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

type probeWriteStartedConn struct {
	net.Conn
	once    sync.Once
	started chan struct{}
}

func (c *probeWriteStartedConn) Write(b []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(b)
}

func TestIdleProbeTimeoutInterruptsRetiredStreamWrite(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	conn := &probeWriteStartedConn{Conn: client, started: make(chan struct{})}
	d := &Dialer{
		idleSessions:       make(map[uint64]*session),
		sessions:           make(map[uint64]*session),
		idleProbeTimeout:   25 * time.Millisecond,
		idleProbeThreshold: time.Millisecond,
	}
	defer d.Close()
	s := newSession(conn, 1)
	s.owner = d
	s.sendPadding = false
	d.sessions[s.seq] = s
	stream := newStream(s, 1)
	if err := s.addStream(stream); err != nil {
		t.Fatal(err)
	}
	runDone := make(chan struct{})
	go func() { _ = s.run(); close(runDone) }()
	writeDone := make(chan struct{})
	go func() { _, _ = stream.Write([]byte("blocked payload")); close(writeDone) }()
	<-conn.started

	var fin rawHeader
	fin[0] = cmdFIN
	binary.BigEndian.PutUint32(fin[1:], stream.id)
	if _, err := server.Write(fin[:]); err != nil {
		t.Fatal(err)
	}
	// The remote FIN must publish the idle session before the janitor runs.
	deadline := time.Now().Add(time.Second)
	for {
		d.idleSessionLock.Lock()
		idle := d.idleSessions[s.seq] == s
		d.idleSessionLock.Unlock()
		if idle {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("remote FIN did not retire the stream")
		}
		time.Sleep(time.Millisecond)
	}
	maintained := make(chan struct{})
	go func() { d.maintainIdleSessions(time.Now().Add(time.Second)); close(maintained) }()
	select {
	case <-maintained:
	case <-time.After(time.Second):
		t.Fatal("probe timeout did not release the janitor")
	}
	for _, done := range []chan struct{}{writeDone, runDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("probe timeout left session I/O blocked")
		}
	}
	d.idleSessionLock.Lock()
	defer d.idleSessionLock.Unlock()
	if !s.Closed() || len(d.sessions) != 0 || len(d.idleSessions) != 0 {
		t.Fatal("expired probe left the session tracked")
	}
}
