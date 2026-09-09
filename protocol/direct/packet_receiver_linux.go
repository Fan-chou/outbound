//go:build linux

package direct

import (
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/sys/unix"
)

const (
	directPacketReceiverBufferSize = 65535
	// Small tier covers EDNS/DNSSEC and almost all QUIC initial/handshake
	// datagrams. The receiver peeks only the datagram length, then consumes it
	// into the smallest fitting tier so a queue never permanently pins 64 KiB
	// buffers and the first jumbo datagram is preserved.
	directPacketReceiverSmallBufferSize = 8192
	directPacketReceiverBatchSize       = 64
	directPacketReceiverYieldBudget     = 32
)

// packetReceiverRegistry multiplexes direct UDP sockets through one Linux
// epoll reader. The socket itself remains owned by its logical PacketConn;
// only packet readiness and delivery are shared.
type packetReceiverRegistry struct {
	mu                 sync.RWMutex
	started            bool
	epollFD            int
	entries            map[int]*directPacketReceiverEntry
	pollFile           *os.File
	receivedSinceYield int // owned by the receive loop, across descriptors and epoll batches
}

type directPacketReceiverEntry struct {
	fd      int
	handler netproxy.PacketReceiveHandler
	active  atomic.Bool
}

var defaultPacketReceiverRegistry = &packetReceiverRegistry{}

func newPacketReceiverRegistry() *packetReceiverRegistry {
	return defaultPacketReceiverRegistry
}

// RegisterPacketReceiver delivers direct UDP datagrams through the shared
// Linux epoll reader instead of starting one blocking reader per socket.
func (c *directPacketConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	if c == nil || c.receiver == nil || handler == nil || c.UDPConn == nil {
		return nil, false
	}

	c.receiverMu.Lock()
	if c.receiverStop != nil {
		c.receiverMu.Unlock()
		return nil, false
	}
	c.receiverGeneration++
	generation := c.receiverGeneration
	entry := &directPacketReceiverEntry{handler: handler}
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			entry.active.Store(false)
			c.receiver.unregister(entry)
			c.receiverMu.Lock()
			if c.receiverGeneration == generation {
				c.receiverStop = nil
			}
			c.receiverMu.Unlock()
		})
	}
	c.receiverStop = stop
	if !c.receiver.register(c, entry) {
		c.receiverStop = nil
		c.receiverMu.Unlock()
		return nil, false
	}
	c.receiverMu.Unlock()
	return stop, true
}

func (r *packetReceiverRegistry) register(conn *directPacketConn, entry *directPacketReceiverEntry) bool {
	if conn == nil || entry == nil || entry.handler == nil {
		return false
	}
	fd, err := directPacketReceiverFD(conn)
	if err != nil {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ensureStartedLocked() {
		return false
	}
	if _, exists := r.entries[fd]; exists {
		return false
	}
	entry.fd = fd
	entry.active.Store(true)
	r.entries[fd] = entry
	event := &unix.EpollEvent{
		Events: unix.EPOLLIN | unix.EPOLLERR | unix.EPOLLHUP,
		Fd:     int32(fd),
	}
	if err := unix.EpollCtl(r.epollFD, unix.EPOLL_CTL_ADD, fd, event); err != nil {
		delete(r.entries, fd)
		entry.active.Store(false)
		return false
	}
	return true
}

func (r *packetReceiverRegistry) unregister(entry *directPacketReceiverEntry) {
	if r == nil || entry == nil {
		return
	}
	entry.active.Store(false)
	r.mu.Lock()
	if current, ok := r.entries[entry.fd]; ok && current == entry {
		delete(r.entries, entry.fd)
		if r.started {
			_ = unix.EpollCtl(r.epollFD, unix.EPOLL_CTL_DEL, entry.fd, nil)
		}
	}
	r.mu.Unlock()
}

func (r *packetReceiverRegistry) ensureStartedLocked() bool {
	if r.started {
		return r.epollFD >= 0
	}
	epollFD, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return false
	}
	// Let Go netpoll wait for epoll readiness. A blocking raw EpollWait
	// can retain a P in syscall until sysmon retakes it, delaying consumers
	// after a fairness yield. The epoll descriptor is itself pollable.
	if err := unix.SetNonblock(epollFD, true); err != nil {
		_ = unix.Close(epollFD)
		return false
	}
	file := os.NewFile(uintptr(epollFD), "direct-udp-epoll")
	// If runtime poll registration failed, retain the ordinary per-socket fallback.
	if err := file.SetReadDeadline(time.Time{}); err != nil {
		_ = file.Close()
		return false
	}
	raw, err := file.SyscallConn()
	if err != nil {
		_ = file.Close()
		return false
	}
	r.pollFile = file
	r.started = true
	r.epollFD = epollFD
	r.entries = make(map[int]*directPacketReceiverEntry)
	go r.loop(raw)
	return true
}

func (r *packetReceiverRegistry) loop(raw syscall.RawConn) {
	events := make([]unix.EpollEvent, 64)
	for {
		var n int
		var waitErr error
		err := raw.Read(func(fd uintptr) bool {
			for {
				n, waitErr = unix.EpollWait(int(fd), events, 0)
				if waitErr == unix.EINTR {
					continue
				}
				return n > 0 || waitErr != nil
			}
		})
		if err == nil {
			err = waitErr
		}
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return
		}
		for i := 0; i < n; i++ {
			fd := int(events[i].Fd)
			r.mu.RLock()
			entry := r.entries[fd]
			r.mu.RUnlock()
			if entry != nil {
				r.drain(entry)
			}
		}
	}
}

func (r *packetReceiverRegistry) drain(entry *directPacketReceiverEntry) {
	for range directPacketReceiverBatchSize {
		if !entry.active.Load() {
			return
		}
		var peek [1]byte
		packetLen, _, err := unix.Recvfrom(entry.fd, peek[:], unix.MSG_DONTWAIT|unix.MSG_PEEK|unix.MSG_TRUNC)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				if err == unix.EINTR {
					continue
				}
				return
			}
			r.deliverError(entry, err)
			return
		}
		bufSize := directPacketReceiverSmallBufferSize
		if packetLen > bufSize {
			bufSize = packetLen
			if bufSize > directPacketReceiverBufferSize {
				bufSize = directPacketReceiverBufferSize
			}
		}
		buf := pool.GetFullCap(bufSize)
		n, sockaddr, err := unix.Recvfrom(entry.fd, buf, unix.MSG_DONTWAIT)
		if err != nil {
			pool.Put(buf)
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				if err == unix.EINTR {
					continue
				}
				return
			}
			r.deliverError(entry, err)
			return
		}

		from, ok := directPacketReceiverAddrPort(sockaddr)
		if !ok {
			pool.Put(buf)
			r.deliverError(entry, fmt.Errorf("unsupported direct UDP peer address %T", sockaddr))
			return
		}
		packet := netproxy.NewReceivedPacket(buf[:n], from, nil, func() {
			pool.Put(buf)
		})
		if !entry.active.Load() || !entry.handler(packet) {
			packet.Release()
		}
		r.receivedSinceYield++
		if r.receivedSinceYield >= directPacketReceiverYieldBudget {
			r.receivedSinceYield = 0
			runtime.Gosched()
		}
	}
}

func (r *packetReceiverRegistry) deliverError(entry *directPacketReceiverEntry, err error) {
	if !entry.active.Load() {
		return
	}
	packet := netproxy.NewReceivedPacket(nil, netip.AddrPort{}, err, nil)
	if !entry.handler(packet) {
		packet.Release()
	}
}

func directPacketReceiverFD(conn *directPacketConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	fd := -1
	if err := raw.Control(func(rawFD uintptr) {
		fd = int(rawFD)
	}); err != nil {
		return -1, err
	}
	if fd < 0 {
		return -1, fmt.Errorf("invalid direct UDP socket descriptor")
	}
	return fd, nil
}

func directPacketReceiverAddrPort(sockaddr unix.Sockaddr) (netip.AddrPort, bool) {
	switch addr := sockaddr.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(addr.Addr), uint16(addr.Port)), true
	case *unix.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(addr.Addr), uint16(addr.Port)), true
	case *unix.SockaddrUnix:
		// Production sockets are UDP; unnamed unix datagrams are used by
		// tests to inject oversize payloads past this environment's
		// loopback UDP ~1472-byte ceiling.
		return netip.AddrPort{}, true
	case nil:
		// Recvfrom on a connected socket (including SOCK_DGRAM socketpair)
		// reports no peer address.
		return netip.AddrPort{}, true
	default:
		return netip.AddrPort{}, false
	}
}
