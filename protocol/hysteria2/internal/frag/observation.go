package frag

import (
	"expvar"
	"sync/atomic"
)

// Counts are process-wide. Evicted/expired count incomplete packets;
// resource_rejected counts incoming fragments, not inferred network loss.
var reassemblyCompleted, reassemblyEvicted, reassemblyExpired, reassemblyRejected atomic.Uint64

func init() {
	expvar.Publish("hy2_reassembly", expvar.Func(func() any {
		return map[string]uint64{
			"completed_packets":           reassemblyCompleted.Load(),
			"evicted_packets":             reassemblyEvicted.Load(),
			"expired_packets":             reassemblyExpired.Load(),
			"resource_rejected_fragments": reassemblyRejected.Load(),
		}
	}))
}
