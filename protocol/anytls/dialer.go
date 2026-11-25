package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/bufferred_conn"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

const (
	sessionReadBufferSize     = 4 << 10
	maxIdleSessions           = 6
	idleSessionTimeout        = 30 * time.Second
	idleSessionCheckInterval  = 1 * time.Second
	idleSessionProbeThreshold = 3 * time.Second
	idleSessionProbeTimeout   = 2 * time.Second
)

func init() {
	protocol.Register("anytls", NewDialer)
}

type Dialer struct {
	proxyAddress string
	nextDialer   netproxy.Dialer
	metadata     protocol.Metadata
	key          []byte
	tlsConfig    *tls.Config
	padding      atomic.Pointer[paddingFactory]

	sessionCounter atomic.Uint64

	idleSessionLock sync.Mutex
	idleSessions    map[uint64]*session
	sessions        map[uint64]*session
	closed          bool
	janitorDone     chan struct{}

	// Optional test overrides; zero values fall back to package constants.
	idleCheckInterval  time.Duration
	idleProbeThreshold time.Duration
	idleProbeTimeout   time.Duration
	idleTimeout        time.Duration
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}
	sum := sha256.Sum256([]byte(header.Password))
	tlsCfg := header.TlsConfig
	if tlsCfg != nil && tlsCfg.ClientSessionCache == nil {
		cloned := tlsCfg.Clone()
		cloned.ClientSessionCache = tls.NewLRUClientSessionCache(16)
		tlsCfg = cloned
	}
	d := &Dialer{
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
		metadata:     metadata,
		key:          sum[:],
		tlsConfig:    tlsCfg,
		idleSessions: make(map[uint64]*session),
		sessions:     make(map[uint64]*session),
		janitorDone:  make(chan struct{}),
	}
	d.padding.Store(DefaultPaddingFactory.Load())
	go d.runIdleJanitor()
	return d, nil
}

func (d *Dialer) UnwrapDialer() netproxy.Dialer {
	return d.nextDialer
}

// PinsUDPSessionTarget reports true because AnyTLS UDP-over-TCP v2 opens each
// logical packet stream in connected mode (command byte 1), fixing the remote
// UDP target on the server for the stream's lifetime.
func (d *Dialer) PinsUDPSessionTarget() bool {
	return true
}

// sessionIdle returns whether the caller should close the idle session.
// Callers hold no session locks; connection teardown happens after this returns.
func (d *Dialer) sessionIdle(s *session) bool {
	d.idleSessionLock.Lock()
	defer d.idleSessionLock.Unlock()
	if d.closed {
		return true
	}
	if d.sessions[s.seq] != s || !s.isReusableIdle() {
		return false
	}
	if d.idleSessions[s.seq] == s {
		return false
	}
	if len(d.idleSessions) >= maxIdleSessions {
		return true
	}
	d.idleSessions[s.seq] = s
	return false
}

func (d *Dialer) sessionClosed(s *session) {
	d.idleSessionLock.Lock()
	defer d.idleSessionLock.Unlock()
	if d.idleSessions[s.seq] == s {
		delete(d.idleSessions, s.seq)
	}
	if d.sessions[s.seq] == s {
		delete(d.sessions, s.seq)
	}
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp", "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.IsClient = d.metadata.IsClient
		if magicNetwork.Network == "udp" {
			mdata.Hostname = "sp.v2.udp-over-tcp.arpa"
		}
		tcpNetwork := netproxy.MagicNetwork{
			Network: "tcp",
			Mark:    magicNetwork.Mark,
			Mptcp:   magicNetwork.Mptcp,
		}.Encode()

		s, err := d.getSession(ctx, tcpNetwork)
		if err != nil {
			return nil, err
		}
		if magicNetwork.Network == "udp" {
			streamAddr := net.JoinHostPort(mdata.Hostname, strconv.Itoa(int(mdata.Port)))
			packetStream, err := s.newPacketStream(streamAddr, addr)
			if err != nil {
				_ = s.Close()
				return nil, err
			}
			if hint, ok := netproxy.UDPReplyAddrFromContext(ctx, addr); ok {
				packetStream.replyFrom = hint
			}
			return packetStream, nil
		}
		stream, err := s.newStream(addr)
		if err != nil {
			_ = s.Close()
			return nil, err
		}
		return stream, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
}

func (d *Dialer) getSession(ctx context.Context, tcpNetwork string) (*session, error) {
	idleTimeout := d.effectiveIdleTimeout()
	for {
		candidate, err := d.popIdleSessionForReuse()
		if err != nil {
			return nil, err
		}
		if candidate == nil {
			break
		}

		// Health probing runs asynchronously in runIdleJanitor() so DialContext
		// never stalls up to 2s on a half-dead idle socket.
		if candidate.idleTimedOut(time.Now(), idleTimeout) {
			_ = candidate.Close()
			continue
		}
		return candidate, nil
	}

	rawConn, err := d.nextDialer.DialContext(ctx, tcpNetwork, d.proxyAddress)
	if err != nil {
		return nil, err
	}
	conn, ok := rawConn.(net.Conn)
	if !ok {
		_ = rawConn.Close()
		return nil, fmt.Errorf("anytls requires net.Conn, got %T", rawConn)
	}
	tuneTCPCarrierConn(conn)

	tlsConn := tls.Client(conn, d.tlsConfig)
	if err := netproxy.HandshakeWithContext(ctx, tlsConn); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	buf, err := buildAuthenticationPacket(d.key, d.padding.Load())
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	defer pool.Put(buf)
	restoreDeadline, err := netproxy.ApplyConnDeadlineFromContext(ctx, tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	defer restoreDeadline()
	if _, err := tlsConn.Write(buf); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	// The session read loop owns this buffer and releases it only after its
	// final Read returns. Creating it after authentication avoids failure-path
	// allocations for sessions that are never published.
	bufferedConn := bufferred_conn.NewBufferedConnSize(tlsConn, sessionReadBufferSize)
	seq := d.sessionCounter.Add(1)
	s := newSessionWithPadding(bufferedConn, seq, &d.padding)
	s.owner = d
	d.idleSessionLock.Lock()
	if d.closed {
		d.idleSessionLock.Unlock()
		_ = s.Close()
		bufferedConn.ReleaseReader()
		return nil, net.ErrClosed
	}
	d.sessions[seq] = s
	d.idleSessionLock.Unlock()

	go func() { _ = s.run() }()

	return s, nil
}

func buildAuthenticationPacket(key []byte, padding *paddingFactory) (pool.PB, error) {
	paddingLen := 0
	if sizes := padding.GenerateRecordPayloadSizes(0); len(sizes) > 0 {
		paddingLen = sizes[0]
	}
	if paddingLen < 0 || paddingLen > maxFramePayloadSize {
		return nil, fmt.Errorf("invalid anytls authentication padding length: %d", paddingLen)
	}

	buffer := pool.Get(len(key) + 2 + paddingLen)
	copy(buffer, key)
	binary.BigEndian.PutUint16(buffer[len(key):], uint16(paddingLen))
	clear(buffer[len(key)+2:])
	return buffer, nil
}

func (d *Dialer) popIdleSessionForReuse() (*session, error) {
	d.idleSessionLock.Lock()
	defer d.idleSessionLock.Unlock()
	if d.closed {
		return nil, net.ErrClosed
	}
	// Prefer the most recently active (LIFO) idle session so reused streams
	// ride the warmest TCP cwnd and freshest middlebox NAT mapping while
	// colder sessions naturally age out via idleSessionTimeout.
	for len(d.idleSessions) > 0 {
		var bestSeq uint64
		var best *session
		var bestIdleAt int64 = -1
		for seq, s := range d.idleSessions {
			idleAt := s.idleAt.Load()
			if best == nil || idleAt > bestIdleAt || (idleAt == bestIdleAt && seq > bestSeq) {
				best = s
				bestSeq = seq
				bestIdleAt = idleAt
			}
		}
		delete(d.idleSessions, bestSeq)
		if best.closed.Load() || best.activeStreams.Load() != 0 || !best.state.CompareAndSwap(sessionStateIdle, sessionStateActive) {
			continue
		}
		return best, nil
	}
	return nil, nil
}

func (d *Dialer) effectiveIdleCheckInterval() time.Duration {
	if d.idleCheckInterval > 0 {
		return d.idleCheckInterval
	}
	return idleSessionCheckInterval
}

func (d *Dialer) effectiveIdleProbeThreshold() time.Duration {
	if d.idleProbeThreshold > 0 {
		return d.idleProbeThreshold
	}
	return idleSessionProbeThreshold
}

func (d *Dialer) effectiveIdleProbeTimeout() time.Duration {
	if d.idleProbeTimeout > 0 {
		return d.idleProbeTimeout
	}
	return idleSessionProbeTimeout
}

func (d *Dialer) effectiveIdleTimeout() time.Duration {
	if d.idleTimeout > 0 {
		return d.idleTimeout
	}
	return idleSessionTimeout
}

func (d *Dialer) runIdleJanitor() {
	ticker := time.NewTicker(d.effectiveIdleCheckInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			d.maintainIdleSessions(time.Now())
		case <-d.janitorDone:
			return
		}
	}
}

func (d *Dialer) maintainIdleSessions(now time.Time) {
	var expired []*session
	var toProbe []*session

	idleTimeout := d.effectiveIdleTimeout()
	probeThreshold := d.effectiveIdleProbeThreshold()

	d.idleSessionLock.Lock()
	if d.closed {
		d.idleSessionLock.Unlock()
		return
	}
	for seq, s := range d.idleSessions {
		if s.closed.Load() || s.idleTimedOut(now, idleTimeout) {
			delete(d.idleSessions, seq)
			expired = append(expired, s)
			continue
		}
		if s.needsIdleProbe(now, probeThreshold) && s.activeStreams.Load() == 0 && s.state.CompareAndSwap(sessionStateIdle, sessionStateProbing) {
			delete(d.idleSessions, seq)
			toProbe = append(toProbe, s)
		}
	}
	d.idleSessionLock.Unlock()

	for _, s := range expired {
		_ = s.Close()
	}

	probeTimeout := d.effectiveIdleProbeTimeout()
	for _, s := range toProbe {
		if !s.probeIdleHealth(probeTimeout) {
			_ = s.Close()
			continue
		}
		reclose := false
		d.idleSessionLock.Lock()
		if d.closed || s.closed.Load() || d.sessions[s.seq] != s || s.activeStreams.Load() != 0 {
			reclose = d.closed
		} else if s.idleTimedOut(time.Now(), idleTimeout) || len(d.idleSessions) >= maxIdleSessions {
			reclose = true
		} else if s.state.CompareAndSwap(sessionStateProbing, sessionStateIdle) {
			d.idleSessions[s.seq] = s
		}
		d.idleSessionLock.Unlock()
		if reclose {
			_ = s.Close()
		}
	}
}

// ResetTransport immediately evicts and closes all pooled idle carrier sessions
// without closing the dialer, so subsequent dials after a WAN IP change open
// fresh TCP+TLS carriers instead of hitting dead NAT/routing state.
func (d *Dialer) ResetTransport() {
	d.idleSessionLock.Lock()
	if d.closed || len(d.idleSessions) == 0 {
		d.idleSessionLock.Unlock()
		return
	}
	stale := make([]*session, 0, len(d.idleSessions))
	for seq, s := range d.idleSessions {
		delete(d.idleSessions, seq)
		stale = append(stale, s)
	}
	d.idleSessionLock.Unlock()

	for _, s := range stale {
		_ = s.Close()
	}
}

func (d *Dialer) Close() error {
	d.idleSessionLock.Lock()
	if d.closed {
		d.idleSessionLock.Unlock()
		return nil
	}
	d.closed = true
	if d.janitorDone != nil {
		close(d.janitorDone)
	}
	sessions := make([]*session, 0, len(d.sessions))
	for _, s := range d.sessions {
		sessions = append(sessions, s)
	}
	d.idleSessions = make(map[uint64]*session)
	d.sessions = make(map[uint64]*session)
	d.idleSessionLock.Unlock()

	for _, s := range sessions {
		_ = s.Close()
	}
	return nil
}
