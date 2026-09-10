package bbr

import (
	"testing"
	"time"

	"github.com/olicesx/quic-go/congestion"
)

func TestProbeRTTWindowTracksMeasuredBDP(t *testing.T) {
	b := NewBbrSender(DefaultClock{}, 1200)
	b.minRtt = 160 * time.Millisecond
	b.maxBandwidth.Update(Bandwidth(250000)*BytesPerSecond, 1)
	b.congestionWindow = 80000
	b.mode = bbrModeProbeRtt
	if got := b.GetCongestionWindow(); got != 20000 {
		t.Fatalf("probe cwnd=%d, want half measured BDP (20000)", got)
	}
	// Probe RTT still drains below the 40000-byte BDP.
	if b.CanSend(20000) {
		t.Fatal("probe allowed sending at its window limit")
	}
	if !b.CanSend(19999) {
		t.Fatal("probe blocked below its window limit")
	}
	// Both window enforcement and the exit timer use the same target.
	now := time.Now()
	b.bytesInFlight = 19500
	b.maybeEnterOrExitProbeRtt(now, false, false)
	if b.exitProbeRttAt.IsZero() {
		t.Fatal("probe did not arm exit timer after draining")
	}
	b.maybeEnterOrExitProbeRtt(now.Add(probeRttTime+time.Millisecond), true, false)
	if b.mode == bbrModeProbeRtt {
		t.Fatal("probe did not exit after a round and timer")
	}
}

func TestProbeRTTWindowBounds(t *testing.T) {
	for _, tc := range []struct {
		name         string
		rate         uint64
		window, want congestion.ByteCount
	}{
		{"unmeasured", 0, 80000, 4800},
		{"small path", 1000, 80000, 4800},
		{"existing window", 250000, 10000, 10000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBbrSender(DefaultClock{}, 1200)
			b.minRtt = 160 * time.Millisecond
			b.maxBandwidth.Update(Bandwidth(tc.rate)*BytesPerSecond, 1)
			b.congestionWindow = tc.window
			if got := b.probeRttCongestionWindow(); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}
