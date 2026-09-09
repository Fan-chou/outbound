package bbr

import (
	"testing"

	"github.com/olicesx/quic-go/congestion"
)

func TestPacerFollowsBandwidthProbeGain(t *testing.T) {
	b := NewBbrSender(DefaultClock{}, 1200)
	b.isAtFullBandwidth = true
	b.congestionWindowGain = 2
	b.maxBandwidth.Update(Bandwidth(1000000)*BytesPerSecond, 1)
	for _, tc := range []struct {
		name string
		gain float64
		want congestion.ByteCount
	}{
		{"probe", 1.25, 1250000},
		{"drain", 0.75, 750000},
		{"cruise", 1, 1000000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b.pacingGain = tc.gain
			b.calculatePacingRate(0)
			if got := b.bandwidthForPacer(); got != tc.want {
				t.Fatalf("pacer rate=%d bytes/s, want %d for %s", got, tc.want, tc.name)
			}
		})
	}
}
