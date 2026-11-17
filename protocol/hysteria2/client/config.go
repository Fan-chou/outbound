package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"github.com/daeuniverse/outbound/protocol/hysteria2/errors"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/pmtud"
)

const (
	// Initial windows start small so idle/low-traffic connections keep a low
	// memory footprint; quic-go's BDP auto-tuning doubles them up to the Max
	// values below when the measured RTTxbandwidth actually needs it. Keeping
	// the connection receive window at least 8x the per-stream window ensures
	// 1-2 stalled streams cannot exhaust the shared connection flow-control
	// budget and starve concurrent active streams (dae#1166).
	defaultStreamReceiveWindow    = 4 * 1024 * 1024   // 4MB initial
	defaultMaxStreamReceiveWindow = 16 * 1024 * 1024  // 16MB ceiling
	defaultConnReceiveWindow      = 32 * 1024 * 1024  // 32MB initial (stream x8)
	defaultMaxConnReceiveWindow   = 128 * 1024 * 1024 // 128MB ceiling (stream x8)
	minConnToStreamWindowRatio    = 8
	maxAutoConnReceiveWindow      = 512 * 1024 * 1024 // cap auto-scaled conn window well below 1 GiB
	defaultObfsInitialPacketSize  = 1200              // fit 8B Salamander overhead inside 1280 WireGuard MTU
	defaultMaxIdleTimeout         = 60 * time.Second  // 30→60: tolerate loss bursts of up to 12 keepalives (at 5s interval) instead of 3 (at 10s)
	defaultKeepAlivePeriod        = 5 * time.Second   // 10→5: more frequent keepalives to maintain NAT binding on lossy links
)

type Config struct {
	ConnFactory     ConnFactory
	ServerAddr      net.Addr
	Auth            string
	TLSConfig       TLSConfig
	QUICConfig      QUICConfig
	BandwidthConfig BandwidthConfig
	UDPHopInterval  time.Duration
	FastOpen        bool
	ObfsPassword    string

	filled bool // whether the fields have been verified and filled
}

// verifyAndFill fills the fields that are not set by the user with default values when possible,
// and returns an error if the user has not set a required field or has set an invalid value.
func (c *Config) verifyAndFill() error {
	if c.filled {
		return nil
	}
	if c.ConnFactory == nil {
		return errors.ConfigError{Field: "ConnFactory", Reason: "must be set"}
	}
	if c.ServerAddr == nil {
		return errors.ConfigError{Field: "ServerAddr", Reason: "must be set"}
	}
	if c.QUICConfig.InitialStreamReceiveWindow != 0 && c.QUICConfig.InitialStreamReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.InitialStreamReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.MaxStreamReceiveWindow != 0 && c.QUICConfig.MaxStreamReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.MaxStreamReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.InitialConnectionReceiveWindow != 0 && c.QUICConfig.InitialConnectionReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.InitialConnectionReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.MaxConnectionReceiveWindow != 0 && c.QUICConfig.MaxConnectionReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.MaxConnectionReceiveWindow", Reason: "must be at least 16384"}
	}

	// Fill stream windows first so un-overridden connection windows maintain at
	// least the minimum connection-to-stream ratio.
	if c.QUICConfig.InitialStreamReceiveWindow == 0 {
		c.QUICConfig.InitialStreamReceiveWindow = defaultStreamReceiveWindow
		if c.QUICConfig.MaxStreamReceiveWindow != 0 && c.QUICConfig.InitialStreamReceiveWindow > c.QUICConfig.MaxStreamReceiveWindow {
			c.QUICConfig.InitialStreamReceiveWindow = c.QUICConfig.MaxStreamReceiveWindow
		}
	}
	if c.QUICConfig.MaxStreamReceiveWindow == 0 {
		c.QUICConfig.MaxStreamReceiveWindow = defaultMaxStreamReceiveWindow
		if c.QUICConfig.MaxStreamReceiveWindow < c.QUICConfig.InitialStreamReceiveWindow {
			c.QUICConfig.MaxStreamReceiveWindow = c.QUICConfig.InitialStreamReceiveWindow
		}
	} else if c.QUICConfig.InitialStreamReceiveWindow > c.QUICConfig.MaxStreamReceiveWindow {
		return errors.ConfigError{Field: "QUICConfig.MaxStreamReceiveWindow", Reason: "must be at least InitialStreamReceiveWindow"}
	}

	if c.QUICConfig.InitialConnectionReceiveWindow == 0 {
		c.QUICConfig.InitialConnectionReceiveWindow = autoConnReceiveWindow(defaultConnReceiveWindow, c.QUICConfig.InitialStreamReceiveWindow)
		if c.QUICConfig.MaxConnectionReceiveWindow != 0 && c.QUICConfig.InitialConnectionReceiveWindow > c.QUICConfig.MaxConnectionReceiveWindow {
			c.QUICConfig.InitialConnectionReceiveWindow = c.QUICConfig.MaxConnectionReceiveWindow
		}
	}
	if c.QUICConfig.MaxConnectionReceiveWindow == 0 {
		maxConn := autoConnReceiveWindow(defaultMaxConnReceiveWindow, c.QUICConfig.MaxStreamReceiveWindow)
		if maxConn < c.QUICConfig.InitialConnectionReceiveWindow {
			maxConn = c.QUICConfig.InitialConnectionReceiveWindow
		}
		c.QUICConfig.MaxConnectionReceiveWindow = maxConn
	} else if c.QUICConfig.InitialConnectionReceiveWindow > c.QUICConfig.MaxConnectionReceiveWindow {
		return errors.ConfigError{Field: "QUICConfig.MaxConnectionReceiveWindow", Reason: "must be at least InitialConnectionReceiveWindow"}
	}
	if c.QUICConfig.InitialPacketSize == 0 && c.ObfsPassword != "" {
		c.QUICConfig.InitialPacketSize = defaultObfsInitialPacketSize
	}
	if c.QUICConfig.MaxIdleTimeout == 0 {
		c.QUICConfig.MaxIdleTimeout = defaultMaxIdleTimeout
	} else if c.QUICConfig.MaxIdleTimeout < 4*time.Second || c.QUICConfig.MaxIdleTimeout > 120*time.Second {
		return errors.ConfigError{Field: "QUICConfig.MaxIdleTimeout", Reason: "must be between 4s and 120s"}
	}
	if c.QUICConfig.KeepAlivePeriod == 0 {
		c.QUICConfig.KeepAlivePeriod = defaultKeepAlivePeriod
	} else if c.QUICConfig.KeepAlivePeriod < 2*time.Second || c.QUICConfig.KeepAlivePeriod > 60*time.Second {
		return errors.ConfigError{Field: "QUICConfig.KeepAlivePeriod", Reason: "must be between 2s and 60s"}
	}
	c.QUICConfig.DisablePathMTUDiscovery = c.QUICConfig.DisablePathMTUDiscovery || pmtud.DisablePathMTUDiscovery

	c.filled = true
	return nil
}

func autoConnReceiveWindow(baseDefault, streamWindow uint64) uint64 {
	if streamWindow > maxAutoConnReceiveWindow/minConnToStreamWindowRatio {
		return max(baseDefault, maxAutoConnReceiveWindow)
	}
	scaled := streamWindow * minConnToStreamWindowRatio
	if scaled > maxAutoConnReceiveWindow {
		scaled = maxAutoConnReceiveWindow
	}
	return max(baseDefault, scaled)
}

type ConnFactory interface {
	New(context.Context) (net.PacketConn, error)
}

type UdpConnFactory struct {
	NewFunc func(ctx context.Context) (net.PacketConn, error)
}

func (f *UdpConnFactory) New(ctx context.Context) (net.PacketConn, error) {
	return f.NewFunc(ctx)
}

// TLSConfig contains the TLS configuration fields that we want to expose to the user.
type TLSConfig struct {
	ServerName                     string
	InsecureSkipVerify             bool
	VerifyPeerCertificate          func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	RootCAs                        *x509.CertPool
	EncryptedClientHelloConfigList []byte
}

func (c TLSConfig) toTLSConfig() *tls.Config {
	return &tls.Config{
		ServerName:                     c.ServerName,
		InsecureSkipVerify:             c.InsecureSkipVerify,
		VerifyPeerCertificate:          c.VerifyPeerCertificate,
		RootCAs:                        c.RootCAs,
		EncryptedClientHelloConfigList: c.EncryptedClientHelloConfigList,
	}
}

// QUICConfig contains the QUIC configuration fields that we want to expose to the user.
type QUICConfig struct {
	InitialStreamReceiveWindow     uint64
	MaxStreamReceiveWindow         uint64
	InitialConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow     uint64
	MaxIdleTimeout                 time.Duration
	KeepAlivePeriod                time.Duration
	InitialPacketSize              uint16
	DisablePathMTUDiscovery        bool // The server may still override this to true on unsupported platforms.
}

// BandwidthConfig describes the maximum bandwidth that the server can use, in bytes per second.
type BandwidthConfig struct {
	MaxTx uint64
	MaxRx uint64
}

// ObfsPassword, when non-empty, enables Salamander packet obfuscation with
// this pre-shared key (must match the server-side obfs password).
type ObfsPassword string
