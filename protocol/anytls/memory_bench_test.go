package anytls

import (
	"github.com/daeuniverse/outbound/protocol/infra/bench"
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
