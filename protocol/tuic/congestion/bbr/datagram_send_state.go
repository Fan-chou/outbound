package bbr

import "time"

// DatagramSendState is an optional diagnostic snapshot, collected by the QUIC
// connection loop only for a sampled slow DATAGRAM. No live state escapes.
func (b *bbrSender) DatagramSendState() map[string]any {
	return map[string]any{
		"algorithm":                  "bbr",
		"mode":                       b.mode,
		"pacing_bytes_per_second":    b.bandwidthForPacer(),
		"bandwidth_bytes_per_second": b.bandwidthEstimate() / BytesPerSecond,
		"pacing_budget_bytes":        b.pacer.Budget(time.Now()),
		"max_datagram_size":          b.maxDatagramSize,
		"pacing_gain":                b.pacingGain,
		"app_limited":                b.lastSampleIsAppLimited,
	}
}
