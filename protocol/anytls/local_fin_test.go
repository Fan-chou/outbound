package anytls

import (
	"github.com/daeuniverse/outbound/pool"
	"io"
	"testing"
	"time"
)

func TestLocalFINDrainsWithoutPeerReply(t *testing.T) {
	s := newSession(&recordingConn{}, 1)
	defer s.Close()
	st := newStream(s, 1)
	if err := s.addStream(st); err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	data := pool.Get(6)
	copy(data, "abcdef")
	if err := st.enqueue(data); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatal(err)
	}
	if err := st.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = st.SetReadDeadline(time.Now().Add(time.Second))
	got, err := io.ReadAll(st)
	if err != nil || string(got) != "cdef" {
		t.Fatalf("tail=%q err=%v", got, err)
	}
	if s.activeStreams.Load() != 0 || !s.isReusableIdle() {
		t.Fatal("FIN did not retire stream")
	}
	if err := st.CloseWrite(); err != nil {
		t.Fatal(err)
	}
}

func TestLocalFINLeavesOtherStreamOpen(t *testing.T) {
	s := newSession(&recordingConn{}, 1)
	defer s.Close()
	a, b := newStream(s, 1), newStream(s, 2)
	_ = s.addStream(a)
	_ = s.addStream(b)
	defer a.Close()
	defer b.Close()
	if err := a.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if s.Closed() || s.isReusableIdle() || s.activeStreams.Load() != 1 {
		t.Fatal("closed active session")
	}
	if _, err := b.Write([]byte("still open")); err != nil {
		t.Fatal(err)
	}
}
