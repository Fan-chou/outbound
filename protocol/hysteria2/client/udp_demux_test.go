package client

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

// chanUDPIO feeds datagrams from a channel and reports a fatal transport
// error when closed, mirroring the real udpIOImpl contract.
type chanUDPIO struct {
	msgs chan *protocol.UDPMessage
	dead chan struct{}
}

func (io *chanUDPIO) ReceiveMessage() (*protocol.UDPMessage, error) {
	select {
	case msg := <-io.msgs:
		return msg, nil
	case <-io.dead:
		return nil, errors.New("transport closed")
	}
}

func (io *chanUDPIO) SendMessage([]byte, *protocol.UDPMessage) error { return nil }

// TestUDPSessionManagerDemuxPreservesPerSessionOrder is the ordering
// counterpart of the parallel-demux test above: datagrams of one session
// must be delivered to the receiver in arrival order. Reordered delivery
// makes the inner protocol (QUIC/H3, games) see spurious loss: cwnd
// collapse and periodic throughput dips. The per-message payload carries a
// per-session sequence number; the receiver records the delivery order and
// the test asserts it is strictly increasing for every session.
func TestUDPSessionManagerDemuxPreservesPerSessionOrder(t *testing.T) {
	const numSessions = 4
	const msgsPerSession = 2000

	io := &chanUDPIO{
		msgs: make(chan *protocol.UDPMessage, 256),
		dead: make(chan struct{}),
	}
	m := newUDPSessionManager(io)

	conns := make([]*udpConn, numSessions)
	var mu sync.Mutex
	delivered := make([][]int, numSessions)
	for i := range numSessions {
		c, err := m.NewUDP("192.0.2.1:443")
		if err != nil {
			t.Fatalf("NewUDP #%d: %v", i, err)
		}
		uc := c.(*udpConn)
		conns[i] = uc
		idx := i
		_, ok := uc.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
			j := int(packet.Data[1]) | int(packet.Data[2])<<8
			mu.Lock()
			delivered[idx] = append(delivered[idx], j)
			mu.Unlock()
			packet.Release()
			return true
		})
		if !ok {
			t.Fatalf("RegisterPacketReceiver #%d failed", i)
		}
	}

	// Concurrent senders interleaving sessions, mirroring a saturated
	// multi-session tunnel where demux goroutines race.
	var wg sync.WaitGroup
	wg.Add(numSessions)
	for i := range numSessions {
		go func(idx int) {
			defer wg.Done()
			for j := range msgsPerSession {
				io.msgs <- &protocol.UDPMessage{
					SessionID: conns[idx].ID,
					PacketID:  0,
					FragID:    0,
					FragCount: 1,
					Addr:      "192.0.2.1:443",
					Data:      []byte{byte(idx), byte(j), byte(j >> 8)},
				}
			}
		}(i)
	}
	wg.Wait()

	deadline := time.Now().Add(20 * time.Second)
	for {
		mu.Lock()
		done := true
		for i := range numSessions {
			if len(delivered[i]) != msgsPerSession {
				done = false
				break
			}
		}
		mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			for i := range numSessions {
				t.Logf("session %d received %d/%d", i, len(delivered[i]), msgsPerSession)
			}
			t.Fatal("messages were not fully delivered")
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	for i, seq := range delivered {
		if len(seq) != msgsPerSession {
			t.Fatalf("session %d: delivered %d, want %d", i, len(seq), msgsPerSession)
		}
		for pos, j := range seq {
			if j != pos {
				t.Fatalf("session %d: delivery %d carries sequence %d (out of order); first inversion in the first %d deliveries", i, pos, j, pos)
			}
		}
	}

	close(io.dead)
	select {
	case <-m.done:
	case <-time.After(5 * time.Second):
		t.Fatal("manager done channel was not closed")
	}
}

// TestUDPSessionManagerParallelDemux 回归测试：多个 run() goroutine 并发
// 消费 datagram 时，各 session 的消息仍被完整、正确地分发。
func TestUDPSessionManagerParallelDemux(t *testing.T) {
	const numSessions = 4
	const msgsPerSession = 500

	io := &chanUDPIO{
		msgs: make(chan *protocol.UDPMessage, 64),
		dead: make(chan struct{}),
	}
	m := newUDPSessionManager(io)

	conns := make([]*udpConn, numSessions)
	var counts [numSessions]atomic.Int32
	for i := range numSessions {
		c, err := m.NewUDP("192.0.2.1:443")
		if err != nil {
			t.Fatalf("NewUDP #%d: %v", i, err)
		}
		uc := c.(*udpConn)
		conns[i] = uc
		idx := i
		_, ok := uc.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
			counts[idx].Add(1)
			packet.Release()
			return true
		})
		if !ok {
			t.Fatalf("RegisterPacketReceiver #%d failed", i)
		}
	}

	// Interleave messages from all sessions so concurrent run() goroutines
	// must demux them in parallel.
	var wg sync.WaitGroup
	wg.Add(numSessions)
	for i := range numSessions {
		go func(idx int) {
			defer wg.Done()
			for j := range msgsPerSession {
				io.msgs <- &protocol.UDPMessage{
					SessionID: conns[idx].ID,
					PacketID:  0,
					FragID:    0,
					FragCount: 1,
					Addr:      "192.0.2.1:443",
					Data:      []byte{byte(idx), byte(j)},
				}
			}
		}(i)
	}
	wg.Wait()

	deadline := time.Now().Add(10 * time.Second)
	for {
		done := true
		for i := range numSessions {
			if counts[i].Load() != msgsPerSession {
				done = false
				break
			}
		}
		if done {
			break
		}
		if time.Now().After(deadline) {
			for i := range numSessions {
				t.Logf("session %d received %d/%d", i, counts[i].Load(), msgsPerSession)
			}
			t.Fatal("messages were not fully delivered")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Fatal transport error: every run() goroutine exits; closeCleanup must
	// run exactly once (sync.Once) without panicking on close(m.done).
	close(io.dead)
	select {
	case <-m.done:
	case <-time.After(5 * time.Second):
		t.Fatal("manager done channel was not closed")
	}
	m.mutex.RLock()
	closed := m.closed
	m.mutex.RUnlock()
	if !closed {
		t.Fatal("manager not marked closed after transport death")
	}
	for i, c := range conns {
		if _, ok := <-c.ReceiveCh; ok {
			t.Fatalf("session %d ReceiveCh still open after cleanup", i)
		}
	}
}

func TestUDPSessionManagerStopsBlockedRouteOnTransportClose(t *testing.T) {
	const queued = demuxWorkerQueueLen + 2
	io := &chanUDPIO{
		msgs: make(chan *protocol.UDPMessage, queued),
		dead: make(chan struct{}),
	}
	m := newUDPSessionManager(io)
	connRaw, err := m.NewUDP("192.0.2.1:443")
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}
	conn := connRaw.(*udpConn)

	started := make(chan struct{})
	releaseHandler := make(chan struct{})
	var released atomic.Int32
	_, ok := conn.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
		close(started)
		<-releaseHandler
		packet.Release()
		return true
	})
	if !ok {
		t.Fatal("RegisterPacketReceiver() failed")
	}

	for i := 0; i < queued; i++ {
		io.msgs <- &protocol.UDPMessage{
			SessionID: conn.ID,
			PacketID:  uint16(i + 1),
			FragID:    0,
			FragCount: 1,
			Addr:      "192.0.2.1:443",
			Data:      []byte{byte(i)},
			Release:   func() { released.Add(1) },
		}
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start blocking handler")
	}
	worker := m.workers[conn.ID%uint32(len(m.workers))]
	deadline := time.Now().Add(time.Second)
	for len(worker) != demuxWorkerQueueLen && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(worker); got != demuxWorkerQueueLen {
		t.Fatalf("worker queue length = %d, want full queue length %d", got, demuxWorkerQueueLen)
	}

	// routeDemux is now blocked on the next worker send. The stop signal must
	// interrupt that send and let cleanup close the manager without waiting for
	// another ReceiveMessage result.
	m.signalStop()
	select {
	case <-m.done:
	case <-time.After(time.Second):
		t.Fatal("manager did not close while route was blocked on a full queue")
	}
	close(releaseHandler)
	m.workerWG.Wait()

	// The fake transport still owns any datagrams that routeDemux did not pop;
	// release them to model the transport discarding its receive queue.
	for {
		select {
		case msg := <-io.msgs:
			releaseUDPMessage(msg)
		default:
			if got := released.Load(); got != queued {
				t.Fatalf("released datagrams = %d, want %d", got, queued)
			}
			return
		}
	}
}
