package anytls

import (
	"crypto/tls"
	"fmt"
	"github.com/daeuniverse/outbound/protocol/infra/bench"
	"io"
	"net"
	"net/http/httptest"
	"runtime"
	"testing"
)

func BenchmarkWaitingSessionMemory(b *testing.B) {
	const count = 256
	for n := 0; n < b.N; n++ {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		sessions := make([]*session, count)
		payload := make([]byte, 32768)
		for i := range sessions {
			s := newSession(bench.NewNetDiscardConn(), uint64(i))
			sessions[i] = s
			st, err := s.newStream("127.0.0.1:80")
			if err != nil {
				b.Fatal(err)
			}
			if _, err = st.Write(payload); err != nil {
				b.Fatal(err)
			}
		}
		runtime.GC()
		runtime.GC()
		runtime.ReadMemStats(&after)
		b.ReportMetric(float64(int64(after.HeapAlloc)-int64(before.HeapAlloc))/count, "retained-B/session")
		runtime.KeepAlive(sessions)
		for _, s := range sessions {
			_ = s.Close()
		}
	}
}

func BenchmarkRelayChunkSize(b *testing.B) {
	for _, size := range []int{8192, 32768} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			s := newSession(bench.NewNetDiscardConn(), 0)
			defer s.Close()
			st, err := s.newStream("127.0.0.1:80")
			if err != nil {
				b.Fatal(err)
			}
			payload := make([]byte, size)
			b.SetBytes(1 << 20)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for n := 0; n < 1<<20; n += size {
					if _, err := st.Write(payload); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

func BenchmarkRelayTLSChunkSize(b *testing.B) {
	certServer := httptest.NewTLSServer(nil)
	certs := certServer.TLS.Certificates
	certServer.Close()
	for _, size := range []int{8192, 32768} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			a, z := net.Pipe()
			server := tls.Server(z, &tls.Config{Certificates: certs})
			done := make(chan struct{})
			go func() { defer close(done); _, _ = io.Copy(io.Discard, server) }()
			client := tls.Client(a, &tls.Config{InsecureSkipVerify: true}) // in-memory benchmark certificate
			if err := client.Handshake(); err != nil {
				b.Fatal(err)
			}
			defer func() { _ = a.Close(); _ = z.Close(); <-done }()
			s := newSession(client, 0)
			st, err := s.newStream("127.0.0.1:80")
			if err != nil {
				b.Fatal(err)
			}
			payload := make([]byte, size)
			b.SetBytes(1 << 20)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for n := 0; n < 1<<20; n += size {
					if _, err := st.Write(payload); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
