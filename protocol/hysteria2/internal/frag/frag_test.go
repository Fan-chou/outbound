package frag

import (
	"bytes"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

func TestFragUDPMessage(t *testing.T) {
	type args struct {
		m       *protocol.UDPMessage
		maxSize int
	}
	tests := []struct {
		name string
		args args
		want []protocol.UDPMessage
	}{
		{
			"no frag",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      []byte("test:123"),
					Data:      []byte("hello"),
				},
				100,
			},
			[]protocol.UDPMessage{
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      []byte("test:123"),
					Data:      []byte("hello"),
				},
			},
		},
		{
			"2 frags",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      []byte("test:123"),
					Data:      []byte("hello"),
				},
				20,
			},
			[]protocol.UDPMessage{
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 2,
					Addr:      []byte("test:123"),
					Data:      []byte("hel"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    1,
					FragCount: 2,
					Addr:      []byte("test:123"),
					Data:      []byte("lo"),
				},
			},
		},
		{
			"4 frags",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      []byte("test:123"),
					Data:      []byte("abcdefgh"),
				},
				19,
			},
			[]protocol.UDPMessage{
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 4,
					Addr:      []byte("test:123"),
					Data:      []byte("ab"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    1,
					FragCount: 4,
					Addr:      []byte("test:123"),
					Data:      []byte("cd"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    2,
					FragCount: 4,
					Addr:      []byte("test:123"),
					Data:      []byte("ef"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    3,
					FragCount: 4,
					Addr:      []byte("test:123"),
					Data:      []byte("gh"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FragUDPMessage(tt.args.m, tt.args.maxSize)
			if err != nil {
				t.Fatalf("FragUDPMessage() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FragUDPMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFragUDPMessageRejectsUndersizedMaxSize(t *testing.T) {
	msg := &protocol.UDPMessage{
		SessionID: 1,
		PacketID:  1,
		FragCount: 1,
		Addr:      []byte("192.0.2.1:443"),
		Data:      []byte("payload-too-large-for-tiny-datagram"),
	}
	for _, maxSize := range []int{msg.HeaderSize(), msg.HeaderSize() - 1, 0, -1} {
		got, err := FragUDPMessage(msg, maxSize)
		if !errors.Is(err, ErrMaxSizeTooSmall) {
			t.Fatalf("maxSize=%d: error = %v, want ErrMaxSizeTooSmall", maxSize, err)
		}
		if got != nil {
			t.Fatalf("maxSize=%d: got %d fragments, want nil", maxSize, len(got))
		}
	}
}

func TestFragUDPMessageRejectsTooManyFragments(t *testing.T) {
	msg := &protocol.UDPMessage{
		SessionID: 1,
		PacketID:  1,
		FragCount: 1,
		Addr:      []byte("192.0.2.1:443"),
		Data:      make([]byte, 256),
	}
	maxSize := msg.HeaderSize() + 1 // 1-byte payloads → 256 fragments
	got, err := FragUDPMessage(msg, maxSize)
	if !errors.Is(err, ErrTooManyFragments) {
		t.Fatalf("error = %v, want ErrTooManyFragments", err)
	}
	if got != nil {
		t.Fatalf("got %d fragments, want nil", len(got))
	}
}

func TestDefragger(t *testing.T) {
	type args struct {
		m *protocol.UDPMessage
	}
	tests := []struct {
		name string
		args args
		want *protocol.UDPMessage
	}{
		{
			"no frag",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    0,
					FragCount: 1,
					Addr:      []byte("test:123"),
					Data:      []byte("hello"),
				},
			},
			&protocol.UDPMessage{
				SessionID: 123,
				PacketID:  987,
				FragID:    0,
				FragCount: 1,
				Addr:      []byte("test:123"),
				Data:      []byte("hello"),
			},
		},
		{
			"frag 0 - 1/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    0,
					FragCount: 2,
					Addr:      []byte("test:123"),
					Data:      []byte("hello "),
				},
			},
			nil,
		},
		{
			"frag 0 - 2/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    1,
					FragCount: 2,
					Addr:      []byte("test:123"),
					Data:      []byte("moto"),
				},
			},
			&protocol.UDPMessage{
				SessionID: 123,
				PacketID:  987,
				FragID:    0,
				FragCount: 1,
				Addr:      []byte("test:123"),
				Data:      []byte("hello moto"),
			},
		},
		{
			"frag 1 - 1/3",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    0,
					FragCount: 3,
					Addr:      []byte("test:123"),
					Data:      []byte("deco"),
				},
			},
			nil,
		},
		{
			"frag 1 - 2/3",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    1,
					FragCount: 3,
					Addr:      []byte("test:123"),
					Data:      []byte("*"),
				},
			},
			nil,
		},
		{
			"frag 1 - 3/3",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    2,
					FragCount: 3,
					Addr:      []byte("test:123"),
					Data:      []byte("27"),
				},
			},
			&protocol.UDPMessage{
				SessionID: 123,
				PacketID:  987,
				FragID:    0,
				FragCount: 1,
				Addr:      []byte("test:123"),
				Data:      []byte("deco*27"),
			},
		},
		{
			"frag 2 - 1/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    1,
					FragCount: 2,
					Addr:      []byte("test:123"),
					Data:      []byte("shinsekai"),
				},
			},
			nil,
		},
		{
			"frag 3 - 2/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  244,
					FragID:    1,
					FragCount: 2,
					Addr:      []byte("test:123"),
					Data:      []byte("what???"),
				},
			},
			nil,
		},
		{
			"frag 2 - 2/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    1,
					FragCount: 2,
					Addr:      []byte("test:123"),
					Data:      []byte(" annaijo"),
				},
			},
			nil,
		},
		{
			"invalid id",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    88,
					FragCount: 2,
					Addr:      []byte("test:123"),
					Data:      []byte("shinsekai"),
				},
			},
			nil,
		},
		{
			"frag 2 - 1/2 re",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    0,
					FragCount: 2,
					Addr:      []byte("test:123"),
					Data:      []byte("shinsekai"),
				},
			},
			&protocol.UDPMessage{
				SessionID: 123,
				PacketID:  233,
				FragID:    0,
				FragCount: 1,
				Addr:      []byte("test:123"),
				Data:      []byte("shinsekaishinsekai"),
			},
		},
	}

	d := &Defragger{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.Feed(tt.args.m); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Feed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func fragmentMessage(sessionID uint32, packetID uint16, fragID, fragCount uint8, data string) *protocol.UDPMessage {
	return &protocol.UDPMessage{
		SessionID: sessionID,
		PacketID:  packetID,
		FragID:    fragID,
		FragCount: fragCount,
		Addr:      []byte("192.0.2.1:443"),
		Data:      []byte(data),
	}
}

func TestDefraggerInterleavesPacketIDs(t *testing.T) {
	d := NewDefragger()
	a1 := fragmentMessage(1, 100, 0, 2, "A1")
	b1 := fragmentMessage(1, 200, 0, 2, "B1")
	a2 := fragmentMessage(1, 100, 1, 2, "A2")
	b2 := fragmentMessage(1, 200, 1, 2, "B2")

	if got := d.Feed(a1); got != nil {
		t.Fatalf("A1 = %v, want incomplete", got)
	}
	if got := d.Feed(b1); got != nil {
		t.Fatalf("B1 = %v, want incomplete", got)
	}
	if got := d.Feed(a2); got == nil || !bytes.Equal(got.Data, []byte("A1A2")) {
		t.Fatalf("A2 = %v, want A1A2", got)
	}
	if got := d.Feed(b2); got == nil || !bytes.Equal(got.Data, []byte("B1B2")) {
		t.Fatalf("B2 = %v, want B1B2", got)
	}
	d.Close()
}

func TestDefraggerOutOfOrderFragments(t *testing.T) {
	d := NewDefragger()
	for _, msg := range []*protocol.UDPMessage{
		fragmentMessage(1, 300, 2, 3, "C"),
		fragmentMessage(1, 300, 0, 3, "A"),
	} {
		if got := d.Feed(msg); got != nil {
			t.Fatalf("partial out-of-order feed = %v, want incomplete", got)
		}
	}
	got := d.Feed(fragmentMessage(1, 300, 1, 3, "B"))
	if got == nil || !bytes.Equal(got.Data, []byte("ABC")) {
		t.Fatalf("out-of-order completion = %v, want ABC", got)
	}
	d.Close()
}

func TestDefraggerRejectsInvalidFragmentsAndReleases(t *testing.T) {
	var released atomic.Int32
	tracked := func(m *protocol.UDPMessage) *protocol.UDPMessage {
		m.Release = func() { released.Add(1) }
		return m
	}
	d := NewDefragger()
	invalid := []*protocol.UDPMessage{
		tracked(fragmentMessage(1, 1, 0, 0, "invalid-count")),
		tracked(fragmentMessage(1, 2, 2, 2, "invalid-index")),
	}
	for _, msg := range invalid {
		if got := d.Feed(msg); got != nil {
			t.Fatalf("invalid fragment produced %v", got)
		}
	}

	if got := d.Feed(tracked(fragmentMessage(1, 3, 0, 2, "first"))); got != nil {
		t.Fatalf("first fragment = %v, want incomplete", got)
	}
	if got := d.Feed(tracked(fragmentMessage(1, 3, 0, 2, "duplicate"))); got != nil {
		t.Fatalf("duplicate fragment = %v, want nil", got)
	}
	if got := d.Feed(tracked(fragmentMessage(1, 3, 1, 3, "mismatched-count"))); got != nil {
		t.Fatalf("mismatched fragment = %v, want nil", got)
	}
	d.Close()
	if got := released.Load(); got != 5 {
		t.Fatalf("release count = %d, want 5 (2 invalid + duplicate + mismatch + pending)", got)
	}
}

func TestDefraggerTTLAndResourceLimits(t *testing.T) {
	var expired atomic.Int32
	d := NewDefragger(DefraggerConfig{FragmentTTL: 20 * time.Millisecond})
	msg := fragmentMessage(1, 10, 0, 2, "expired")
	msg.Release = func() { expired.Add(1) }
	d.Feed(msg)
	deadline := time.Now().Add(time.Second)
	for expired.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if expired.Load() != 1 {
		t.Fatalf("expired release count = %d, want 1", expired.Load())
	}
	d.mu.Lock()
	pending := len(d.packets)
	d.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pending packets after TTL = %d, want 0", pending)
	}
	d.Close()

	var capped atomic.Int32
	track := func(m *protocol.UDPMessage) *protocol.UDPMessage {
		m.Release = func() { capped.Add(1) }
		return m
	}
	ids := NewDefragger(DefraggerConfig{
		MaxPacketIDs:   1,
		MaxPacketSize:  8,
		MaxMemoryBytes: 8,
	})
	ids.Feed(track(fragmentMessage(1, 20, 0, 2, "aa")))
	if got := ids.Feed(track(fragmentMessage(1, 21, 0, 2, "bb"))); got != nil {
		t.Fatalf("packet beyond ID cap = %v, want nil", got)
	}
	if got := ids.Feed(track(fragmentMessage(1, 21, 1, 2, "cc"))); got == nil {
		t.Fatal("newest packet at ID cap did not complete")
	}
	if capped.Load() != 3 {
		t.Fatalf("ID cap release count = %d, want 3", capped.Load())
	}
	ids.Close()

	var bounded atomic.Int32
	memory := NewDefragger(DefraggerConfig{
		MaxPacketIDs:   4,
		MaxPacketSize:  3,
		MaxMemoryBytes: 3,
	})
	memory.Feed(trackWithCounter(fragmentMessage(1, 30, 0, 2, "ab"), &bounded))
	if got := memory.Feed(trackWithCounter(fragmentMessage(1, 31, 0, 2, "cd"), &bounded)); got != nil {
		t.Fatalf("packet beyond memory cap = %v, want nil", got)
	}
	if got := memory.Feed(trackWithCounter(fragmentMessage(1, 31, 1, 2, "cd"), &bounded)); got != nil {
		t.Fatalf("oversized completion = %v, want nil", got)
	}
	memory.Close()
	if bounded.Load() != 3 {
		t.Fatalf("memory/packet limit release count = %d, want 3", bounded.Load())
	}
}

func trackWithCounter(m *protocol.UDPMessage, counter *atomic.Int32) *protocol.UDPMessage {
	m.Release = func() { counter.Add(1) }
	return m
}
