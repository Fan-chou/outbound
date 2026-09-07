package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	rand "github.com/daeuniverse/outbound/pkg/fastrand"

	"github.com/olicesx/quic-go"

	"github.com/daeuniverse/outbound/netproxy"
	coreErrs "github.com/daeuniverse/outbound/protocol/hysteria2/errors"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/frag"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

const (
	// Keep enough headroom for short scheduler stalls and bursty game ticks.
	// dae already backpressures its own reply path, so the remaining drop window
	// is mainly pre-drain bursts before this session goroutine gets CPU time.
	// udpMessageChanSize bounds the per-session receive queue. 128 slots is
	// enough to absorb bursty game ticks / DNS floods (~512KB of 4KB packets)
	// while keeping the steady-state channel footprint at 1KB per session
	// instead of 16KB. RFC 9221 DATAGRAM has no flow control: a full queue
	// drops the datagram (and returns its buffer) rather than blocking the
	// demux worker.
	udpMessageChanSize = 128
)

// sendBufPool recycles the per-session MaxUDPSize send buffer. Sessions are
// created/closed frequently (game ticks, DNS), so pooling avoids a 4KB
// allocation churn and its GC pressure on each session churn.
var sendBufPool = sync.Pool{
	New: func() any { return make([]byte, protocol.MaxUDPSize) },
}

type udpIO interface {
	ReceiveMessage() (*protocol.UDPMessage, error)
	SendMessage(context.Context, []byte, *protocol.UDPMessage) error
}

type udpConn struct {
	ID        uint32
	D         *frag.Defragger
	ReceiveCh chan *protocol.UDPMessage
	SendBuf   []byte
	SendFunc  func(context.Context, []byte, *protocol.UDPMessage) error
	CloseFunc func()
	closed    atomic.Bool

	// transportDone is closed when the underlying QUIC transport connection
	// is permanently closed.  Allows upstream consumers (e.g. dae UdpEndpoint)
	// to detect transport death without waiting for ReadFrom/WriteTo errors.
	transportDone <-chan struct{}

	writeMu   sync.Mutex
	receiveMu sync.Mutex
	// deliverMu serializes RegisterPacketReceiver's drain against feed's
	// deliver/queue path so queued datagrams stay FIFO with live ones.
	deliverMu     sync.Mutex
	readDeadline  netproxy.PacketDeadline
	writeDeadline netproxy.PacketDeadline
	target        string
	// targetBytes is target as bytes for the per-datagram default-target
	// comparison (message addresses are byte slices since they stopped
	// being materialized as strings on receive).
	targetBytes []byte
	// writeAddrBytes caches the []byte form of the last WriteTo target
	// under writeMu, so the steady-state single-target send path does not
	// convert the address string per datagram.
	writeAddrStr      string
	writeAddrBytes    []byte
	defaultTargetAddr netip.AddrPort
	natIdentity       netip.AddrPort
	receiverMu        sync.Mutex
	receiver          netproxy.PacketReceiveHandler
}

var _ netproxy.PacketReceiver = (*udpConn)(nil)

// TransportDone implements netproxy.TransportLifecycle.
// The returned channel is closed when the QUIC transport backing this
// UDP session is permanently dead.
func (u *udpConn) TransportDone() <-chan struct{} {
	if u.transportDone == nil {
		// Return a never-closed channel for safety.
		return make(chan struct{})
	}
	return u.transportDone
}

func (u *udpConn) Read(b []byte) (n int, err error) {
	msg, _, err := u.ReadFrom(b)
	return msg, err
}

func (u *udpConn) Write(b []byte) (n int, err error) {
	return u.WriteTo(b, u.target)
}

func (u *udpConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	for {
		ctx := u.readDeadline.Context()
		if err := context.Cause(ctx); err != nil {
			return 0, netip.AddrPort{}, err
		}
		var msg *protocol.UDPMessage
		select {
		case msg = <-u.ReceiveCh:
		case <-ctx.Done():
			return 0, netip.AddrPort{}, context.Cause(ctx)
		}
		if msg == nil {
			// Closed
			return 0, netip.AddrPort{}, io.EOF
		}
		dfMsg := u.feedMessage(msg)
		if dfMsg == nil {
			// Incomplete message, wait for more
			continue
		}
		from, err := u.addrForMessage(dfMsg.Addr)
		if err != nil {
			releaseUDPMessage(dfMsg)
			return 0, netip.AddrPort{}, err
		}
		n := copy(p, dfMsg.Data)
		releaseUDPMessage(dfMsg)
		return n, from, nil
	}
}

// RegisterPacketReceiver lets dae consume packets from the session manager's
// existing transport reader without adding a blocking ReadFrom goroutine for
// this logical UDP session.
func (u *udpConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	if handler == nil {
		return nil, false
	}
	var unregisterOnce sync.Once
	unregister := func() {
		unregisterOnce.Do(func() {
			u.receiverMu.Lock()
			u.receiver = nil
			u.receiverMu.Unlock()
		})
	}

	// Hold deliverMu across the receiver swap and the drain so a concurrent
	// feed cannot deliver a later packet before the queued prefix.
	u.deliverMu.Lock()
	defer u.deliverMu.Unlock()
	u.receiverMu.Lock()
	if u.receiver != nil {
		u.receiverMu.Unlock()
		return nil, false
	}
	u.receiver = handler
	u.receiverMu.Unlock()

	// Preserve messages that arrived between session creation and registration.
	for {
		select {
		case msg, ok := <-u.ReceiveCh:
			if !ok {
				unregister()
				return unregister, true
			}
			if !u.deliverMessage(msg) {
				releaseUDPMessage(msg)
			}
		default:
			return unregister, true
		}
	}
}

func (u *udpConn) addrForMessage(addr []byte) (netip.AddrPort, error) {
	if u.natIdentity.IsValid() {
		return u.natIdentity, nil
	}
	if bytes.Equal(addr, u.targetBytes) && u.defaultTargetAddr.IsValid() {
		return u.defaultTargetAddr, nil
	}
	return netip.ParseAddrPort(string(addr))
}

// addrBytesForWrite converts a WriteTo target to the []byte form the message
// carries. Callers hold writeMu; the steady state repeatedly targets the
// session's fixed destination, so the conversion is cached per target.
func (u *udpConn) addrBytesForWrite(addr string) []byte {
	if addr == u.writeAddrStr {
		return u.writeAddrBytes
	}
	b := []byte(addr)
	u.writeAddrStr = addr
	u.writeAddrBytes = b
	return b
}

func (u *udpConn) feedMessage(msg *protocol.UDPMessage) *protocol.UDPMessage {
	u.receiveMu.Lock()
	defer u.receiveMu.Unlock()
	return u.D.Feed(msg)
}

func (u *udpConn) deliverMessage(msg *protocol.UDPMessage) bool {
	u.receiverMu.Lock()
	handler := u.receiver
	u.receiverMu.Unlock()
	if handler == nil {
		return false
	}
	msg = u.feedMessage(msg)
	if msg == nil {
		return true
	}
	from, err := u.addrForMessage(msg.Addr)
	if err != nil {
		releaseUDPMessage(msg)
		return true
	}
	packet := netproxy.NewReceivedPacket(msg.Data, from, nil, msg.Release)
	if handler(packet) {
		return true
	}
	packet.Release()
	return true
}

// queueIfNoReceiver queues a message only while the receiver state is held
// stable. A false result means the caller should retry transport delivery.
func (u *udpConn) queueIfNoReceiver(msg *protocol.UDPMessage) bool {
	u.receiverMu.Lock()
	defer u.receiverMu.Unlock()
	if u.receiver != nil {
		return false
	}
	if u.closed.Load() {
		releaseUDPMessage(msg)
		return true
	}
	select {
	case u.ReceiveCh <- msg:
	default:
		// Channel full, drop the message. Return the pooled datagram
		// buffer to quic-go now: nobody will ever consume it.
		releaseUDPMessage(msg)
	}
	return true
}

func (u *udpConn) WriteTo(b []byte, addr string) (n int, err error) {
	u.writeMu.Lock()
	defer u.writeMu.Unlock()
	if u.closed.Load() || u.SendBuf == nil {
		return 0, coreErrs.ClosedError{}
	}

	ctx := u.writeDeadline.Context()
	if err := context.Cause(ctx); err != nil {
		return 0, err
	}

	udpOriginalPackets.Add(1)
	// Try no frag first
	msg := &protocol.UDPMessage{
		SessionID: u.ID,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      u.addrBytesForWrite(addr),
		Data:      b,
	}
	// The session's fixed serialization buffer is smaller than the theoretical
	// UDP payload limit. Treat local buffer exhaustion the same way quic-go
	// reports path MTU exhaustion so we fragment instead of silently dropping.
	if msg.Size() > len(u.SendBuf) {
		err = &quic.DatagramTooLargeError{MaxDataLen: int64(len(u.SendBuf))}
	} else {
		err = u.SendFunc(ctx, u.SendBuf, msg)
	}
	var errTooLarge *quic.DatagramTooLargeError
	if errors.As(err, &errTooLarge) {
		// Message too large, try fragmentation
		msg.PacketID = uint16(rand.Intn(0xFFFF)) + 1
		fMsgs, fragErr := frag.FragUDPMessage(msg, int(errTooLarge.MaxDataLen))
		if fragErr != nil {
			return 0, coreErrs.ProtocolError{Message: fragErr.Error()}
		}
		udpFragmentedPackets.Add(1)
		for _, fMsg := range fMsgs {
			udpFragmentAttempts.Add(1)
			err := u.SendFunc(ctx, u.SendBuf, &fMsg)
			if err != nil {
				return 0, err
			}
		}
		return len(b), nil
	} else {
		return len(b), err
	}
}

func (u *udpConn) Close() error {
	u.readDeadline.Close()
	u.writeDeadline.Close()
	u.CloseFunc()
	return nil
}

func (u *udpConn) SetDeadline(t time.Time) error {
	if err := u.SetReadDeadline(t); err != nil {
		return err
	}
	return u.SetWriteDeadline(t)
}
func (u *udpConn) SetReadDeadline(t time.Time) error            { return u.readDeadline.Set(t) }
func (u *udpConn) SetWriteDeadline(t time.Time) error           { return u.writeDeadline.Set(t) }
func (u *udpConn) SupportsIndependentPacketWriteDeadline() bool { return true }

type udpSessionManager struct {
	io udpIO

	mutex  sync.RWMutex
	m      map[uint32]*udpConn
	nextID uint32

	// workers are session-affinity demux queues indexed by SessionID. The
	// single router (routeDemux) dispatches into them; each demuxWorker
	// drains its queue in order.
	workers []chan *protocol.UDPMessage

	closed    bool
	draining  bool
	onIdle    func()
	done      chan struct{}
	closeOnce sync.Once
}

// maxDemuxWorkers caps how many session-affinity workers drain dispatched
// datagrams. Each worker owns a disjoint set of sessions (by SessionID), so
// per-session processing stays strictly ordered while consumer work still
// parallelizes across sessions.
const maxDemuxWorkers = 8

// demuxWorkerQueueLen sizes the per-worker dispatch queues. Bounded
// smoothing only: under overload the router blocks, pushing backpressure
// to the transport's own bounded receive queue, which is where the drop
// policy belongs (a single, well-sized drop point).
const demuxWorkerQueueLen = 256

func newUDPSessionManager(io udpIO) *udpSessionManager {
	m := &udpSessionManager{
		io:     io,
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}
	n := runtime.GOMAXPROCS(0)
	if n > maxDemuxWorkers {
		n = maxDemuxWorkers
	}
	if n < 1 {
		n = 1
	}
	m.workers = make([]chan *protocol.UDPMessage, n)
	for i := range m.workers {
		m.workers[i] = make(chan *protocol.UDPMessage, demuxWorkerQueueLen)
	}
	// Order-preserving parallel demux. A single router goroutine is the
	// only receiver on the shared datagram queue, so dispatch order equals
	// arrival order; each datagram then goes to the worker owning its
	// session, which processes it (defrag + delivery) synchronously. The
	// previous design popped the queue from multiple goroutines: pop order
	// is not processing order, so consecutive datagrams of one session
	// could be delivered interleaved — the inner protocol (QUIC/H3) then
	// sees spurious loss, halves its congestion window, and throughput
	// collapses periodically. Per-session serialization is also required
	// by the receiver callback itself, which runs outside receiveMu.
	go m.routeDemux()
	for i := range m.workers {
		go m.demuxWorker(i)
	}
	return m
}

// routeDemux pops datagrams from the shared transport queue and hands each
// to the worker owning its session. It must remain the only ReceiveMessage
// caller: a second concurrent popper would reintroduce per-session
// reordering.
func (m *udpSessionManager) routeDemux() {
	defer m.closeOnce.Do(m.closeCleanup)
	for {
		msg, err := m.io.ReceiveMessage()
		if err != nil {
			return
		}
		ch := m.workers[msg.SessionID%uint32(len(m.workers))]
		// Blocking dispatch: when a worker falls behind, backpressure
		// propagates to the transport's bounded receive queue, which owns
		// the overload drop policy. Dropping here instead would add a
		// second, less well-sized drop point that fires on bursts the
		// system could have processed. m.done unblocks a send parked on a
		// full worker queue when the manager is closed (Close / transport
		// death) so closeCleanup does not wait on ReceiveMessage.
		dispatchStarted := demuxDispatchWait.start()
		select {
		case ch <- msg:
			demuxDispatchWait.finish(dispatchStarted)
		case <-m.done:
			releaseUDPMessage(msg)
			return
		}
	}
}

// demuxWorker drains its session-affinity queue in FIFO order. All work for
// one message (session recheck, defrag, receiver callback) happens inline,
// so per-session delivery order is exactly the dispatch order.
func (m *udpSessionManager) demuxWorker(index int) {
	ch := m.workers[index]
	for {
		select {
		case msg := <-ch:
			m.feed(msg)
		case <-m.done:
			// Transport is gone: return still-queued buffers to the
			// pool instead of leaving them for the GC.
			for {
				select {
				case msg := <-ch:
					releaseUDPMessage(msg)
				default:
					return
				}
			}
		}
	}
}

func releaseUDPMessage(msg *protocol.UDPMessage) {
	if msg != nil && msg.Release != nil {
		msg.Release()
	}
}

func (m *udpSessionManager) Close() {
	m.closeOnce.Do(m.closeCleanup)
}

func (m *udpSessionManager) closeCleanup() {
	m.mutex.Lock()
	// Close done first so routeDemux can drop a send parked on a full
	// worker queue instead of waiting for ReceiveMessage to fail.
	select {
	case <-m.done:
	default:
		close(m.done)
	}
	var onIdle func()
	conns := make([]*udpConn, 0, len(m.m))
	for _, conn := range m.m {
		conns = append(conns, conn)
		if cb := m.closeLocked(conn); cb != nil {
			onIdle = cb
		}
	}
	if m.onIdle != nil {
		onIdle = m.onIdle
		m.onIdle = nil
	}
	m.closed = true
	m.mutex.Unlock()
	for _, conn := range conns {
		conn.releaseSendBuffer()
	}

	if onIdle != nil {
		onIdle()
	}
}

func (m *udpSessionManager) feed(msg *protocol.UDPMessage) {
	m.mutex.RLock()
	conn, ok := m.m[msg.SessionID]
	m.mutex.RUnlock()
	if !ok {
		// Ignore message from unknown session (e.g. arrived after cleanup).
		// Return its pooled datagram buffer to quic-go.
		releaseUDPMessage(msg)
		return
	}
	conn.deliverMu.Lock()
	defer conn.deliverMu.Unlock()
	if conn.deliverMessage(msg) {
		return
	}

	for {
		// A receiver may be registered or unregistered concurrently with this
		// lookup. Recheck the session under the manager read lock before
		// touching ReceiveCh so closeLocked cannot race a channel send.
		m.mutex.RLock()
		if current, exists := m.m[msg.SessionID]; !exists || current != conn {
			m.mutex.RUnlock()
			releaseUDPMessage(msg)
			return
		}
		if conn.queueIfNoReceiver(msg) {
			m.mutex.RUnlock()
			return
		}
		m.mutex.RUnlock()
		if conn.deliverMessage(msg) {
			return
		}
	}
}

// NewUDP creates a new UDP session.
func (m *udpSessionManager) NewUDP(addr string) (netproxy.Conn, error) {
	return m.openUDP(addr, netip.AddrPort{})
}

func (m *udpSessionManager) openUDP(addr string, replyAddr netip.AddrPort) (netproxy.Conn, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.closed || m.draining {
		return nil, coreErrs.ClosedError{}
	}

	id := m.nextID
	m.nextID++

	// Validate the default target at session creation. WriteTo may send to
	// other targets, and each reply carries its actual peer in UDPMessage.Addr.
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, err
	}
	defaultTargetAddr, _ := netip.ParseAddrPort(addr)
	var natIdentity netip.AddrPort
	if replyAddr.IsValid() && replyAddr.Port() != 0 {
		natIdentity = replyAddr
	}

	conn := &udpConn{
		ID:            id,
		D:             &frag.Defragger{},
		ReceiveCh:     make(chan *protocol.UDPMessage, udpMessageChanSize),
		SendBuf:       sendBufPool.Get().([]byte),
		SendFunc:      m.io.SendMessage,
		transportDone: m.done,

		writeMu:           sync.Mutex{},
		target:            addr,
		targetBytes:       []byte(addr),
		writeAddrStr:      addr,
		writeAddrBytes:    []byte(addr),
		defaultTargetAddr: defaultTargetAddr,
		natIdentity:       natIdentity,
	}
	conn.CloseFunc = func() {
		m.close(conn)
	}
	m.m[id] = conn

	return conn, nil
}

func (m *udpSessionManager) close(conn *udpConn) {
	m.mutex.Lock()
	onIdle := m.closeLocked(conn)
	m.mutex.Unlock()
	conn.releaseSendBuffer()

	if onIdle != nil {
		onIdle()
	}
}

func (conn *udpConn) releaseSendBuffer() {
	// WriteTo holds writeMu around Serialize+SendDatagram. Take it before
	// returning SendBuf so a concurrent write cannot use-after-put the
	// serialize buffer.
	conn.writeMu.Lock()
	if conn.SendBuf != nil {
		sendBufPool.Put(conn.SendBuf)
		conn.SendBuf = nil
	}
	conn.writeMu.Unlock()
}

func (m *udpSessionManager) closeLocked(conn *udpConn) func() {
	if conn == nil || conn.closed.Load() {
		return nil
	}
	// Publish closure before clearing the receiver. queueIfNoReceiver observes
	// both while holding receiverMu; WriteTo observes the atomic closed flag.
	conn.receiverMu.Lock()
	conn.closed.Store(true)
	conn.receiver = nil
	conn.receiverMu.Unlock()
	conn.readDeadline.Close()
	conn.writeDeadline.Close()
	// Return any partially-reassembled fragments to the quic-go pool; the
	// session is dead and nobody will complete the reassembly. Take
	// receiveMu: concurrent deliverMessage/ReadFrom hold it around D.Feed,
	// and Defragger's state is not otherwise synchronized.
	conn.receiveMu.Lock()
	conn.D.Close()
	conn.receiveMu.Unlock()
	close(conn.ReceiveCh)
	for msg := range conn.ReceiveCh {
		releaseUDPMessage(msg)
	}
	delete(m.m, conn.ID)
	if m.draining && len(m.m) == 0 {
		onIdle := m.onIdle
		m.onIdle = nil
		return onIdle
	}
	return nil
}

func (m *udpSessionManager) closeWhenIdle(onIdle func()) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.closed || len(m.m) == 0 {
		return true
	}
	m.draining = true
	m.onIdle = onIdle
	return false
}

func (m *udpSessionManager) Count() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.m)
}
