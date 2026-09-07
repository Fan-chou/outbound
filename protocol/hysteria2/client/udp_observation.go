package client

import (
	"expvar"
	"sync/atomic"
	"time"
)

// demuxWaitObservation samples one operation in 64. Buckets are disjoint and
// describe local waiting, not end-to-end latency or successful delivery.
// The snapshot is served by the existing localhost diagnostics listener.
type demuxWaitObservation struct {
	operations atomic.Uint64
	buckets    [7]atomic.Uint64
}

func (o *demuxWaitObservation) start() time.Time {
	if o.operations.Add(1)%64 != 0 {
		return time.Time{}
	}
	return time.Now()
}

func (o *demuxWaitObservation) finish(start time.Time) {
	if start.IsZero() {
		return
	}
	elapsed := time.Since(start)
	limits := [...]time.Duration{time.Millisecond, 5 * time.Millisecond, 20 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond, time.Second}
	i := 0
	for i < len(limits) && elapsed > limits[i] {
		i++
	}
	o.buckets[i].Add(1)
}

func (o *demuxWaitObservation) snapshot() map[string]any {
	counts := make([]uint64, len(o.buckets))
	for i := range counts {
		counts[i] = o.buckets[i].Load()
	}
	return map[string]any{"operations": o.operations.Load(), "sample_every": 64, "bucket_upper_ms": []string{"1", "5", "20", "50", "100", "1000", "+Inf"}, "samples": counts}
}

var demuxDispatchWait demuxWaitObservation
var udpOriginalPackets, udpFragmentedPackets, udpFragmentAttempts atomic.Uint64

func init() {
	expvar.Publish("hy2_udp", expvar.Func(func() any {
		return map[string]any{
			"demux_dispatch_wait": demuxDispatchWait.snapshot(), "original_packets": udpOriginalPackets.Load(), "fragmented_packets": udpFragmentedPackets.Load(), "fragment_attempts": udpFragmentAttempts.Load(),
		}
	}))
}
