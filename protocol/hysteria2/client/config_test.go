package client

import (
	"context"
	"net"
	"testing"

	"github.com/olicesx/quic-go/quicvarint"
)

func baseTestClientConfig() *Config {
	return &Config{
		ConnFactory: &UdpConnFactory{
			NewFunc: func(context.Context) (net.PacketConn, error) {
				return &packetConnWithRemoteAddr{}, nil
			},
		},
		ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443},
	}
}

func TestVerifyAndFillWindowUpperBounds(t *testing.T) {
	for _, field := range []string{"initial_stream", "max_stream", "initial_connection", "max_connection"} {
		t.Run(field, func(t *testing.T) {
			for _, value := range []uint64{quicvarint.Max, quicvarint.Max + 1, ^uint64(0)} {
				cfg := baseTestClientConfig()
				switch field {
				case "initial_stream":
					cfg.QUICConfig.InitialStreamReceiveWindow = value
				case "max_stream":
					cfg.QUICConfig.MaxStreamReceiveWindow = value
				case "initial_connection":
					cfg.QUICConfig.InitialConnectionReceiveWindow = value
				case "max_connection":
					cfg.QUICConfig.MaxConnectionReceiveWindow = value
				}
				_, err := NewClient(cfg)
				if (err != nil) != (value > quicvarint.Max) {
					t.Fatalf("NewClient with %s=%d: error=%v", field, value, err)
				}
			}
		})
	}
}

func TestVerifyAndFillDefaultWindowRatio(t *testing.T) {
	cfg := baseTestClientConfig()
	if err := cfg.verifyAndFill(); err != nil {
		t.Fatalf("verifyAndFill() error = %v", err)
	}
	if cfg.QUICConfig.InitialStreamReceiveWindow != 4*1024*1024 {
		t.Fatalf("InitialStreamReceiveWindow = %d, want 4 MiB", cfg.QUICConfig.InitialStreamReceiveWindow)
	}
	if cfg.QUICConfig.MaxStreamReceiveWindow != 16*1024*1024 {
		t.Fatalf("MaxStreamReceiveWindow = %d, want 16 MiB", cfg.QUICConfig.MaxStreamReceiveWindow)
	}
	if cfg.QUICConfig.InitialConnectionReceiveWindow != 32*1024*1024 {
		t.Fatalf("InitialConnectionReceiveWindow = %d, want 32 MiB", cfg.QUICConfig.InitialConnectionReceiveWindow)
	}
	if cfg.QUICConfig.MaxConnectionReceiveWindow != 128*1024*1024 {
		t.Fatalf("MaxConnectionReceiveWindow = %d, want 128 MiB", cfg.QUICConfig.MaxConnectionReceiveWindow)
	}
	if cfg.QUICConfig.InitialConnectionReceiveWindow < cfg.QUICConfig.InitialStreamReceiveWindow*8 {
		t.Fatal("initial connection window is less than 8x initial stream window")
	}
	if cfg.QUICConfig.MaxConnectionReceiveWindow < cfg.QUICConfig.MaxStreamReceiveWindow*8 {
		t.Fatal("max connection window is less than 8x max stream window")
	}
}

func TestVerifyAndFillScalesUnsetConnectionWindowsAndCapsBelow1GiB(t *testing.T) {
	t.Run("scales unset conn windows to 8x stream", func(t *testing.T) {
		cfg := baseTestClientConfig()
		cfg.QUICConfig.InitialStreamReceiveWindow = 16 * 1024 * 1024
		cfg.QUICConfig.MaxStreamReceiveWindow = 32 * 1024 * 1024
		if err := cfg.verifyAndFill(); err != nil {
			t.Fatalf("verifyAndFill() error = %v", err)
		}
		if got, want := cfg.QUICConfig.InitialConnectionReceiveWindow, uint64(128*1024*1024); got != want {
			t.Fatalf("InitialConnectionReceiveWindow = %d, want %d", got, want)
		}
		if got, want := cfg.QUICConfig.MaxConnectionReceiveWindow, uint64(256*1024*1024); got != want {
			t.Fatalf("MaxConnectionReceiveWindow = %d, want %d", got, want)
		}
	})

	t.Run("caps auto-scaled conn windows well below 1 GiB", func(t *testing.T) {
		cfg := baseTestClientConfig()
		cfg.QUICConfig.MaxStreamReceiveWindow = 256 * 1024 * 1024
		if err := cfg.verifyAndFill(); err != nil {
			t.Fatalf("verifyAndFill() error = %v", err)
		}
		if cfg.QUICConfig.MaxConnectionReceiveWindow >= 1024*1024*1024 {
			t.Fatalf("MaxConnectionReceiveWindow = %d, must remain below 1 GiB", cfg.QUICConfig.MaxConnectionReceiveWindow)
		}
		if got, want := cfg.QUICConfig.MaxConnectionReceiveWindow, uint64(maxAutoConnReceiveWindow); got != want {
			t.Fatalf("MaxConnectionReceiveWindow = %d, want %d", got, want)
		}
	})

	t.Run("clamps unset initial stream window when max stream is smaller than default initial", func(t *testing.T) {
		cfg := baseTestClientConfig()
		cfg.QUICConfig.MaxStreamReceiveWindow = 1 * 1024 * 1024
		if err := cfg.verifyAndFill(); err != nil {
			t.Fatalf("verifyAndFill() error = %v", err)
		}
		if got, want := cfg.QUICConfig.InitialStreamReceiveWindow, uint64(1*1024*1024); got != want {
			t.Fatalf("InitialStreamReceiveWindow = %d, want %d", got, want)
		}
	})

	t.Run("preserves explicit conn window overrides", func(t *testing.T) {
		cfg := baseTestClientConfig()
		cfg.QUICConfig.InitialStreamReceiveWindow = 2 * 1024 * 1024
		cfg.QUICConfig.MaxStreamReceiveWindow = 8 * 1024 * 1024
		cfg.QUICConfig.InitialConnectionReceiveWindow = 8 * 1024 * 1024
		cfg.QUICConfig.MaxConnectionReceiveWindow = 24 * 1024 * 1024
		if err := cfg.verifyAndFill(); err != nil {
			t.Fatalf("verifyAndFill() error = %v", err)
		}
		if got, want := cfg.QUICConfig.InitialConnectionReceiveWindow, uint64(8*1024*1024); got != want {
			t.Fatalf("InitialConnectionReceiveWindow = %d, want %d", got, want)
		}
		if got, want := cfg.QUICConfig.MaxConnectionReceiveWindow, uint64(24*1024*1024); got != want {
			t.Fatalf("MaxConnectionReceiveWindow = %d, want %d", got, want)
		}
	})

	t.Run("rejects initial greater than max", func(t *testing.T) {
		cfg := baseTestClientConfig()
		cfg.QUICConfig.InitialStreamReceiveWindow = 16 * 1024 * 1024
		cfg.QUICConfig.MaxStreamReceiveWindow = 8 * 1024 * 1024
		if err := cfg.verifyAndFill(); err == nil {
			t.Fatal("expected ConfigError when InitialStreamReceiveWindow > MaxStreamReceiveWindow")
		}
	})

	t.Run("salamander obfs clamps default InitialPacketSize to 1200", func(t *testing.T) {
		cfg := baseTestClientConfig()
		cfg.ObfsPassword = "psk"
		if err := cfg.verifyAndFill(); err != nil {
			t.Fatalf("verifyAndFill() error = %v", err)
		}
		if got, want := cfg.QUICConfig.InitialPacketSize, uint16(1200); got != want {
			t.Fatalf("InitialPacketSize = %d, want %d", got, want)
		}
	})

	t.Run("salamander obfs preserves explicit InitialPacketSize", func(t *testing.T) {
		cfg := baseTestClientConfig()
		cfg.ObfsPassword = "psk"
		cfg.QUICConfig.InitialPacketSize = 1280
		if err := cfg.verifyAndFill(); err != nil {
			t.Fatalf("verifyAndFill() error = %v", err)
		}
		if got, want := cfg.QUICConfig.InitialPacketSize, uint16(1280); got != want {
			t.Fatalf("InitialPacketSize = %d, want %d", got, want)
		}
	})
}
