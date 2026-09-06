package anytls

import (
	"sync"
	"testing"
)

func TestSessionCallbackCloseReuseRace(t *testing.T) {
	for i := 0; i < 50; i++ {
		d := &Dialer{sessions: make(map[uint64]*session), idleSessions: make(map[uint64]*session)}
		s := newSession(&recordingConn{}, 1)
		s.owner = d
		d.sessions[1] = s
		st := newStream(s, 1)
		_ = s.addStream(st)
		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); _ = st.CloseWrite() }()
		go func() { defer wg.Done(); _, _ = d.popIdleSessionForReuse() }()
		go func() { defer wg.Done(); _ = d.Close() }()
		wg.Wait()
		if len(d.sessions) != 0 || len(d.idleSessions) != 0 {
			t.Fatal("closed dialer retained session")
		}
		_ = st.Close()
	}
}

func TestSessionCallbackIdleOverflow(t *testing.T) {
	d := &Dialer{sessions: make(map[uint64]*session), idleSessions: make(map[uint64]*session)}
	defer d.Close()
	for i := uint64(1); i <= 2; i++ {
		s := newSession(&recordingConn{}, i)
		s.owner = d
		d.sessions[i] = s
		st := newStream(s, 1)
		_ = s.addStream(st)
		if err := st.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
	}
	if len(d.idleSessions) != 1 || len(d.sessions) != 1 {
		t.Fatal("overflow session not retired")
	}
}
