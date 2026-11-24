package client

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	outbounderrors "github.com/daeuniverse/outbound/common/errors"
	"github.com/daeuniverse/outbound/netproxy"
	coreErrs "github.com/daeuniverse/outbound/protocol/hysteria2/errors"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/utils"
	"github.com/daeuniverse/outbound/protocol/hysteria2/obfs"
	"github.com/daeuniverse/outbound/protocol/tuic/congestion"

	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/http3"
)

const (
	closeErrCodeOK            = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeProtocolError = 0x101 // HTTP3 ErrCodeGeneralProtocolError

	defaultConnectTimeout        = 10 * time.Second
	blackholeMinConsecutive      = 2
	blackholeMinElapsed          = 2 * time.Second
	blackholeHardConsecutive     = 3
	defaultClientSessionCacheCap = 8
)

var errConnectReset = errors.New("hysteria2: connect superseded by transport reset")

type connectAttempt struct {
	done   chan struct{}
	cancel context.CancelFunc
	once   sync.Once
	err    error
}

func (a *connectAttempt) finish(err error) {
	a.once.Do(func() {
		a.err = err
		close(a.done)
	})
}

type Client interface {
	TCP(addr string, ctx context.Context) (netproxy.Conn, error)
	UDP(addr string, ctx context.Context) (netproxy.Conn, error)
	Close() error
}

type HandshakeInfo struct {
	UDPEnabled bool
	Tx         uint64 // 0 if using BBR
}

func NewClient(config *Config) (Client, error) {
	if err := config.verifyAndFill(); err != nil {
		return nil, err
	}
	c := &clientImpl{
		config:       config,
		sessionCache: tls.NewLRUClientSessionCache(defaultClientSessionCacheCap),
	}
	return c, nil
}

// TODO: How to handle quic conn for the same dialer with different marks?

type clientImpl struct {
	config       *Config
	sessionCache tls.ClientSessionCache

	pktConn net.PacketConn
	conn    quic.Connection

	udpSM *udpSessionManager

	m          sync.Mutex
	closed     bool
	connecting *connectAttempt

	// Silent blackhole rapid circuit-breaker state (guarded by m; fast-path
	// reads hasStreamTimeouts atomically to avoid lock contention when healthy).
	hasStreamTimeouts         atomic.Bool
	consecutiveStreamTimeouts int
	firstStreamTimeoutAt      time.Time
}

// closeExistingLocked closes the old QUIC connection, packet conn, and UDP
// session manager before establishing a new connection. Must be called with
// c.m held.
func (c *clientImpl) closeExistingLocked() {
	// Close the session manager first: this closes m.done so routeDemux can
	// unblock from a full worker queue instead of waiting for ReceiveMessage
	// to fail after the QUIC connection is already gone.
	if c.udpSM != nil {
		c.udpSM.Close()
		c.udpSM = nil
	}
	if c.conn != nil {
		_ = c.conn.CloseWithError(closeErrCodeOK, "reconnecting")
	}
	if c.pktConn != nil {
		_ = c.pktConn.Close()
	}
	c.conn = nil
	c.pktConn = nil
	c.consecutiveStreamTimeouts = 0
	c.firstStreamTimeoutAt = time.Time{}
	c.hasStreamTimeouts.Store(false)
}

func (c *clientImpl) dialTransport(ctx context.Context) (net.PacketConn, quic.Connection, *udpSessionManager, *HandshakeInfo, error) {
	pktConn, err := c.config.ConnFactory.New(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if c.config.ObfsPassword != "" {
		// Salamander obfuscation: wrap the packet conn so every QUIC packet
		// becomes indistinguishable random bytes on the wire.
		pktConn, err = obfs.WrapPacketConnSalamander(pktConn, []byte(c.config.ObfsPassword))
		if err != nil {
			_ = pktConn.Close()
			return nil, nil, nil, nil, err
		}
	}
	serverAddr := quicRemoteAddr(pktConn, c.config.ServerAddr)
	// Convert config to TLS config & QUIC config
	tlsConfig := c.config.TLSConfig.toTLSConfig()
	if tlsConfig.ClientSessionCache == nil && c.sessionCache != nil {
		tlsConfig.ClientSessionCache = c.sessionCache
	}
	quicConfig := buildQUICConfig(c.config)
	// Prepare Transport
	var conn quic.EarlyConnection
	rt := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConfig,
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			qc, err := quic.DialEarly(ctx, pktConn, serverAddr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			conn = qc
			return qc, nil
		},
	}
	// Send auth HTTP request
	u := &url.URL{
		Scheme: "https",
		Host:   protocol.URLHost,
		Path:   protocol.URLPath,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		_ = pktConn.Close()
		return nil, nil, nil, nil, err
	}
	req.Header = make(http.Header)
	protocol.AuthRequestToHeader(req.Header, protocol.AuthRequest{
		Auth: c.config.Auth,
		Rx:   c.config.BandwidthConfig.MaxRx,
	})
	resp, err := rt.RoundTrip(req)
	if err != nil {
		if conn != nil {
			_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		}
		_ = pktConn.Close()
		return nil, nil, nil, nil, coreErrs.ConnectError{Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != protocol.StatusAuthOK {
		if conn != nil {
			_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		}
		_ = pktConn.Close()
		return nil, nil, nil, nil, coreErrs.AuthError{StatusCode: resp.StatusCode}
	}
	// Auth OK
	authResp := protocol.AuthResponseFromHeader(resp.Header)
	var actualTx uint64
	if authResp.RxAuto {
		// Server asks client to use bandwidth detection,
		// ignore local bandwidth config and use BBR
		congestion.UseBBR(conn)
	} else {
		// actualTx = min(serverRx, clientTx)
		actualTx = authResp.Rx
		if actualTx == 0 || actualTx > c.config.BandwidthConfig.MaxTx {
			// Server doesn't have a limit, or our clientTx is smaller than serverRx
			actualTx = c.config.BandwidthConfig.MaxTx
		}
		if actualTx > 0 {
			congestion.UseBrutal(conn, actualTx)
		} else {
			// We don't know our own bandwidth either, use BBR
			congestion.UseBBR(conn)
		}
	}
	var udpSM *udpSessionManager
	if authResp.UDPEnabled {
		udpSM = newUDPSessionManager(&udpIOImpl{Conn: conn})
	}
	return pktConn, conn, udpSM, &HandshakeInfo{
		UDPEnabled: authResp.UDPEnabled,
		Tx:         actualTx,
	}, nil
}

func (c *clientImpl) runConnectAttempt(connectCtx context.Context, attempt *connectAttempt) {
	defer attempt.cancel()
	pktConn, conn, udpSM, _, err := c.dialTransport(connectCtx)

	c.m.Lock()
	if c.closed || c.connecting != attempt {
		c.m.Unlock()
		if udpSM != nil {
			udpSM.Close()
		}
		if conn != nil {
			_ = conn.CloseWithError(closeErrCodeOK, "superseded")
		}
		if pktConn != nil {
			_ = pktConn.Close()
		}
		attempt.finish(coreErrs.ClosedError{})
		return
	}
	if err != nil {
		c.connecting = nil
		c.m.Unlock()
		attempt.finish(err)
		return
	}
	c.closeExistingLocked()
	c.pktConn = pktConn
	c.conn = conn
	c.udpSM = udpSM
	c.connecting = nil
	c.m.Unlock()
	attempt.finish(nil)
}

// ensureConnected returns an active QUIC connection snapshot without holding
// c.m during the QUIC/H3 handshake. Concurrent callers coalesce onto a single
// in-flight handshake and honor their own ctx.Done() promptly without aborting
// the shared handshake for other callers.
func (c *clientImpl) ensureConnected(ctx context.Context) (quic.Connection, *udpSessionManager, error) {
	for {
		c.m.Lock()
		if err := ctx.Err(); err != nil {
			c.m.Unlock()
			return nil, nil, err
		}
		if c.closed {
			c.m.Unlock()
			return nil, nil, coreErrs.ClosedError{}
		}
		if c.active() {
			conn, udpSM := c.conn, c.udpSM
			c.m.Unlock()
			return conn, udpSM, nil
		}
		attempt := c.connecting
		if attempt == nil {
			c.closeExistingLocked()
			timeout := defaultConnectTimeout
			if dl, ok := ctx.Deadline(); ok {
				if rem := time.Until(dl); rem > timeout {
					timeout = rem
				}
			}
			connectCtx, cancel := context.WithTimeout(context.Background(), timeout)
			attempt = &connectAttempt{
				done:   make(chan struct{}),
				cancel: cancel,
			}
			c.connecting = attempt
			go c.runConnectAttempt(connectCtx, attempt)
		}
		c.m.Unlock()

		select {
		case <-attempt.done:
			if attempt.err != nil {
				if errors.Is(attempt.err, errConnectReset) {
					continue
				}
				return nil, nil, attempt.err
			}
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
}

func buildQUICConfig(cfg *Config) *quic.Config {
	initialPacketSize := cfg.QUICConfig.InitialPacketSize
	if initialPacketSize == 0 && cfg.ObfsPassword != "" {
		// Salamander adds an 8-byte header on top of QUIC UDP payloads; clamp
		// default initial packets so encapsulated frames stay under a 1280-byte
		// WireGuard MTU when Path MTU Discovery or probes hit low-MTU paths.
		initialPacketSize = defaultObfsInitialPacketSize
	}
	return &quic.Config{
		InitialStreamReceiveWindow:     cfg.QUICConfig.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         cfg.QUICConfig.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: cfg.QUICConfig.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     cfg.QUICConfig.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 cfg.QUICConfig.MaxIdleTimeout,
		KeepAlivePeriod:                cfg.QUICConfig.KeepAlivePeriod,
		InitialPacketSize:              initialPacketSize,
		DisablePathMTUDiscovery:        cfg.QUICConfig.DisablePathMTUDiscovery,
		EnableDatagrams:                true,
	}
}

func quicRemoteAddr(pktConn net.PacketConn, fallback net.Addr) net.Addr {
	type remoteAddrConn interface {
		RemoteAddr() net.Addr
	}
	if c, ok := pktConn.(remoteAddrConn); ok {
		if addr := c.RemoteAddr(); addr != nil {
			return addr
		}
	}
	return fallback
}

func (c *clientImpl) active() bool {
	if c.conn == nil {
		return false
	}
	select {
	case <-c.conn.Context().Done():
		return false
	default:
		return true
	}
}

func (c *clientImpl) Close() error {
	c.m.Lock()
	if c.closed {
		c.m.Unlock()
		return nil
	}
	c.closed = true
	att := c.connecting
	c.connecting = nil
	udpSM := c.udpSM
	if udpSM != nil && !udpSM.closeWhenIdle(c.closeExistingWhenDrained) {
		c.m.Unlock()
		if att != nil {
			att.cancel()
			att.finish(coreErrs.ClosedError{})
		}
		return nil
	}
	c.closeExistingLocked()
	c.m.Unlock()
	if att != nil {
		att.cancel()
		att.finish(coreErrs.ClosedError{})
	}
	return nil
}

// ResetTransport tears down the active QUIC connection and UDP socket (and
// cancels any in-flight handshake) without permanently closing the client.
// The next TCP/UDP dial will immediately establish a fresh tunnel over a new
// underlay socket.
func (c *clientImpl) ResetTransport() {
	c.m.Lock()
	if c.closed {
		c.m.Unlock()
		return
	}
	att := c.connecting
	c.connecting = nil
	c.closeExistingLocked()
	c.m.Unlock()
	if att != nil {
		att.cancel()
		att.finish(errConnectReset)
	}
}

// closeExistingWhenDrained is the udpSessionManager drain callback. It can
// fire from call stacks that already hold c.m (e.g.
// handleIfConnectionClosed -> closeExistingLocked -> udpSM.Close ->
// closeCleanup invoking onIdle), so it must not take c.m synchronously or it
// self-deadlocks; decoupling with a goroutine lets the holder release first.
func (c *clientImpl) closeExistingWhenDrained() {
	go c.closeExisting()
}

func (c *clientImpl) closeExisting() {
	c.m.Lock()
	defer c.m.Unlock()
	c.closeExistingLocked()
}

// openStream wraps the stream with QStream, which handles Close() properly.
func (c *clientImpl) openStream(conn quic.Connection) (*utils.QStream, error) {
	stream, err := conn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &utils.QStream{Stream: stream}, nil
}

func (c *clientImpl) TCP(addr string, ctx context.Context) (netproxy.Conn, error) {
	connSnapshot, _, err := c.ensureConnected(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := c.openStream(connSnapshot)
	if err != nil {
		c.recordStreamError(err, connSnapshot)
		return nil, err
	}
	var dialDeadline time.Time
	if deadline, ok := ctx.Deadline(); ok {
		dialDeadline = deadline
		_ = stream.SetDeadline(deadline)
		if !c.config.FastOpen {
			defer func() { _ = stream.SetDeadline(time.Time{}) }()
		}
	}
	// Send request
	err = protocol.WriteTCPRequest(stream, addr)
	if err != nil {
		_ = stream.Close()
		c.recordStreamError(err, connSnapshot)
		return nil, err
	}
	if c.config.FastOpen {
		// Don't wait for the response when fast open is enabled.
		// Return the connection immediately, defer the response handling
		// to the first Read() call. Keep the dial deadline armed until
		// the response is consumed, independently of caller deadlines.
		return &tcpConn{
			Orig:             stream,
			PseudoLocalAddr:  connSnapshot.LocalAddr(),
			PseudoRemoteAddr: connSnapshot.RemoteAddr(),
			Established:      false,
			dialDeadline:     dialDeadline,
			onResponse: func(respErr error) {
				if respErr == nil {
					c.recordStreamSuccess(connSnapshot)
				} else {
					c.recordStreamError(respErr, connSnapshot)
				}
			},
		}, nil
	}
	// Read response
	ok, msg, err := protocol.ReadTCPResponse(stream)
	if err != nil {
		_ = stream.Close()
		c.recordStreamError(err, connSnapshot)
		return nil, err
	}
	c.recordStreamSuccess(connSnapshot)
	if !ok {
		_ = stream.Close()
		return nil, coreErrs.DialError{Message: "from remote: " + msg}
	}
	return &tcpConn{
		Orig:             stream,
		PseudoLocalAddr:  connSnapshot.LocalAddr(),
		PseudoRemoteAddr: connSnapshot.RemoteAddr(),
		Established:      true,
	}, nil
}

func (c *clientImpl) UDP(addr string, ctx context.Context) (netproxy.Conn, error) {
	connSnapshot, udpSMSnapshot, err := c.ensureConnected(ctx)
	if err != nil {
		return nil, err
	}

	// Local input validation: a malformed target address must surface as a
	// dial error without ever reaching the tunnel-fatal classification (and
	// without tearing down the shared connection).
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, err
	}
	if udpSMSnapshot == nil {
		return nil, coreErrs.DialError{Message: "UDP not enabled"}
	}
	replyAddr, _ := netproxy.UDPReplyAddrFromContext(ctx, addr)
	conn, err := udpSMSnapshot.openUDP(addr, replyAddr)
	c.handleIfConnectionClosed(err, connSnapshot)
	return conn, err
}

func isStreamTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (c *clientImpl) recordStreamSuccess(originConn quic.Connection) {
	if !c.hasStreamTimeouts.Load() {
		return
	}
	c.m.Lock()
	if c.conn == originConn {
		c.consecutiveStreamTimeouts = 0
		c.firstStreamTimeoutAt = time.Time{}
		c.hasStreamTimeouts.Store(false)
	}
	c.m.Unlock()
}

func (c *clientImpl) recordStreamError(err error, originConn quic.Connection) {
	c.handleIfConnectionClosed(err, originConn)
	if !isStreamTimeoutError(err) {
		return
	}
	now := time.Now()
	c.m.Lock()
	defer c.m.Unlock()
	if c.conn != originConn || c.conn == nil {
		return
	}
	if c.consecutiveStreamTimeouts == 0 {
		c.firstStreamTimeoutAt = now
		c.hasStreamTimeouts.Store(true)
	}
	c.consecutiveStreamTimeouts++
	if (c.consecutiveStreamTimeouts >= blackholeMinConsecutive && now.Sub(c.firstStreamTimeoutAt) >= blackholeMinElapsed) ||
		c.consecutiveStreamTimeouts >= blackholeHardConsecutive {
		// Multiple consecutive streams received no server response header on
		// this QUIC connection while zero streams succeeded in between: the
		// UDP 4-tuple is almost certainly silently blackholed (e.g. WAN IP or
		// NAT mapping change). Tear it down now rather than waiting up to 60s
		// for QUIC MaxIdleTimeout.
		c.closeExistingLocked()
	}
}

// wrapIfConnectionClosed checks if the error returned by quic-go
// indicates that the QUIC connection has been permanently closed,
// and if so, wraps the error with coreErrs.ClosedError.
// PITFALL: sometimes quic-go has "internal errors" that are not net.Error,
// but we still need to treat them as ClosedError.
func (c *clientImpl) handleIfConnectionClosed(err error, originConn quic.Connection) {
	if !tunnelFatalError(err) {
		return
	}
	// Hold the mutex to avoid racing with connect() which may have
	// already replaced c.conn/c.pktConn with new instances.
	c.m.Lock()
	defer c.m.Unlock()
	// Only close if the connection is still the one that errored.
	// If connect() already ran, c.conn is a new instance and must not
	// be closed — doing so would kill the fresh QUIC session.
	if c.conn == originConn {
		c.closeExistingLocked()
	}
}

// tunnelFatalError reports whether err means the shared QUIC tunnel itself is
// dead and should be torn down. Stream-, caller- and input-scoped errors must
// return false: tearing the tunnel down for them kills healthy streams and
// forces a full re-handshake for everyone.
func tunnelFatalError(err error) bool {
	if err == nil {
		return false
	}

	// Stream-scoped failures must not tear down the shared tunnel: a RESET
	// on one stream (quic.StreamError), a refused stream-limit probe, or a
	// temporary/datagram-backpressure error only affects that attempt,
	// while other streams on the connection stay healthy.
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) {
		return false
	}
	if outbounderrors.IsStreamExhausted(err) || outbounderrors.IsTemporaryError(err) {
		return false
	}

	var closedErr coreErrs.ClosedError
	if errors.As(err, &closedErr) {
		return true
	}
	// A server FIN without a response (protocol.ReadTCPResponse surfaces it
	// as io.EOF) is a per-stream condition, not a tunnel death.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return false
	}
	// Caller-scoped abort: the dial context died, the tunnel did not.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	// Local input validation (e.g. a malformed target address) must not
	// kill the shared connection.
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Temporary() { // nolint:staticcheck
		return false
	}
	return true
}

type tcpConn struct {
	Orig             *utils.QStream
	PseudoLocalAddr  net.Addr
	PseudoRemoteAddr net.Addr
	Established      bool

	// deadlineMu serializes caller deadline changes with handshake cleanup.
	// Until the response is consumed, the dial deadline caps both directions.
	deadlineMu    sync.Mutex
	dialDeadline  time.Time
	readDeadline  time.Time
	writeDeadline time.Time

	// Fast-open mode defers the response read to the first Read. The once
	// guarantees exactly one ReadTCPResponse even if callers race the first
	// reads, so every reader observes the same handshake outcome.
	establishOnce sync.Once
	respErr       error
	onResponse    func(error)
}

func (c *tcpConn) readFastOpenResponse() error {
	c.establishOnce.Do(func() {
		defer func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			if !c.dialDeadline.IsZero() {
				c.dialDeadline = time.Time{}
				_ = c.Orig.SetReadDeadline(c.readDeadline)
				_ = c.Orig.SetWriteDeadline(c.writeDeadline)
			}
		}()
		ok, msg, err := protocol.ReadTCPResponse(c.Orig)
		if err != nil {
			c.respErr = err
			if c.onResponse != nil {
				c.onResponse(err)
			}
			return
		}
		if c.onResponse != nil {
			c.onResponse(nil)
		}
		if !ok {
			c.respErr = coreErrs.DialError{Message: "from remote: " + msg}
		}
	})
	return c.respErr
}

func (c *tcpConn) Read(b []byte) (n int, err error) {
	if !c.Established {
		// Read response
		if err = c.readFastOpenResponse(); err != nil {
			return 0, err
		}
	}
	return c.Orig.Read(b)
}

func (c *tcpConn) Write(b []byte) (n int, err error) {
	return c.Orig.Write(b)
}

func (c *tcpConn) Close() error {
	return c.Orig.Close()
}

func (c *tcpConn) CloseWrite() error {
	// quic-go's default close only closes the write side
	// for more info, see comments in utils.QStream struct
	return c.Orig.Stream.Close()
}

func (c *tcpConn) CloseRead() error {
	c.Orig.Stream.CancelRead(0)
	return nil
}

func (c *tcpConn) LocalAddr() net.Addr {
	return c.PseudoLocalAddr
}

func (c *tcpConn) RemoteAddr() net.Addr {
	return c.PseudoRemoteAddr
}

// handshakeDeadline returns the earlier nonzero deadline. Caller deadlines
// cannot extend or disable the dial timeout while the response is pending.
func (c *tcpConn) handshakeDeadline(t time.Time) time.Time {
	if !c.dialDeadline.IsZero() && (t.IsZero() || c.dialDeadline.Before(t)) {
		return c.dialDeadline
	}
	return t
}

func (c *tcpConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline, c.writeDeadline = t, t
	return c.Orig.SetDeadline(c.handshakeDeadline(t))
}

func (c *tcpConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline = t
	return c.Orig.SetReadDeadline(c.handshakeDeadline(t))
}

func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.writeDeadline = t
	return c.Orig.SetWriteDeadline(c.handshakeDeadline(t))
}

type udpIOImpl struct {
	Conn quic.Connection
}

func (io *udpIOImpl) ReceiveMessage() (*protocol.UDPMessage, error) {
	for {
		buf, err := io.Conn.ReceiveDatagram(context.Background())
		if err != nil {
			if !outbounderrors.IsTemporaryError(err) {
				return nil, err
			}
			// Some temporary errors (notably stateless reset) are delivered
			// after the datagram queue is already closed, so Receive returns
			// immediately from then on. Exit via the connection context
			// instead of spinning in a tight loop.
			if ctxErr := io.Conn.Context().Err(); ctxErr != nil {
				return nil, ctxErr
			}
			continue
		}
		udpMsg, err := protocol.ParseUDPMessage(buf)
		if err != nil {
			// Invalid message - return the pooled buffer before waiting for
			// the next datagram.
			io.Conn.ReleaseDatagram(buf)
			continue
		}
		// Attach the buffer release so the consumer can return storage to
		// the quic-go pool once it is done with Data (which aliases buf).
		udpMsg.Release = func() { io.Conn.ReleaseDatagram(buf) }
		return udpMsg, nil
	}
}

func (io *udpIOImpl) SendMessage(ctx context.Context, buf []byte, msg *protocol.UDPMessage) error {
	msgN := msg.Serialize(buf)
	if msgN < 0 {
		return &quic.DatagramTooLargeError{MaxDataLen: int64(len(buf))}
	}
	return io.Conn.SendDatagramContext(ctx, buf[:msgN])
}

func (io *udpIOImpl) DatagramSendQueueLen() int {
	if conn, ok := io.Conn.(interface{ DatagramSendQueueLen() int }); ok {
		return conn.DatagramSendQueueLen()
	}
	return -1
}

func (io *udpIOImpl) DatagramSendObservation() (uint64, string) {
	if conn, ok := io.Conn.(interface{ DatagramSendObservation() (uint64, string) }); ok {
		return conn.DatagramSendObservation()
	}
	return 0, ""
}
