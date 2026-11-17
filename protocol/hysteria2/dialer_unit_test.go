package hysteria2

import (
	"crypto/tls"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
)

func TestBuildClientConfigPropagatesFeature1QUICOptions(t *testing.T) {
	header := protocol.Header{
		ProxyAddress: "127.0.0.1:443",
		TlsConfig:    &tls.Config{ServerName: "example.com"},
		User:         "user",
		Password:     "pass",
		IsClient:     true,
		Feature1: &Feature1{
			ObfsPassword:            "obfs-secret",
			InitStreamReceiveWindow: 2 * 1024 * 1024,
			MaxStreamReceiveWindow:  8 * 1024 * 1024,
			InitConnReceiveWindow:   16 * 1024 * 1024,
			MaxConnReceiveWindow:    64 * 1024 * 1024,
			DisablePathMTUDiscovery: true,
		},
	}
	cfg, _, err := buildClientConfig(direct.SymmetricDirect, header)
	if err != nil {
		t.Fatalf("buildClientConfig() error = %v", err)
	}
	if cfg.ObfsPassword != "obfs-secret" {
		t.Fatalf("ObfsPassword = %q, want obfs-secret", cfg.ObfsPassword)
	}
	if cfg.QUICConfig.InitialStreamReceiveWindow != 2*1024*1024 {
		t.Fatalf("InitialStreamReceiveWindow = %d, want 2 MiB", cfg.QUICConfig.InitialStreamReceiveWindow)
	}
	if cfg.QUICConfig.MaxStreamReceiveWindow != 8*1024*1024 {
		t.Fatalf("MaxStreamReceiveWindow = %d, want 8 MiB", cfg.QUICConfig.MaxStreamReceiveWindow)
	}
	if cfg.QUICConfig.InitialConnectionReceiveWindow != 16*1024*1024 {
		t.Fatalf("InitialConnectionReceiveWindow = %d, want 16 MiB", cfg.QUICConfig.InitialConnectionReceiveWindow)
	}
	if cfg.QUICConfig.MaxConnectionReceiveWindow != 64*1024*1024 {
		t.Fatalf("MaxConnectionReceiveWindow = %d, want 64 MiB", cfg.QUICConfig.MaxConnectionReceiveWindow)
	}
	if !cfg.QUICConfig.DisablePathMTUDiscovery {
		t.Fatal("DisablePathMTUDiscovery = false, want true")
	}
}
