package bbr

import (
	"github.com/olicesx/quic-go/congestion"
	"testing"
	"time"
)

func TestExplicitApplicationLimitedBoundary(t *testing.T) {
	b := NewBbrSender(DefaultClock{}, 1200)
	b.SetRTTStatsProvider(applicationLimitedRTT{})
	b.SetApplicationLimited(false)
	if !b.explicitApplicationLimited || b.sampler.IsAppLimited() {
		t.Fatal("enabling reports must not mark supply idle")
	}
	now := time.Unix(1, 0)
	b.sampler.OnPacketSent(now, 1, 1200, 0, true)
	b.SetApplicationLimited(true)
	b.sampler.OnPacketSent(now.Add(time.Millisecond), 2, 1200, 1200, true)
	b.sampler.OnPacketSent(now.Add(2*time.Millisecond), 3, 1200, 2400, true)
	// An ACK must be able to end the reported idle epoch even below cwnd.
	b.OnCongestionEventEx(3600, now.Add(160*time.Millisecond), []congestion.AckedPacketInfo{{PacketNumber: 2, BytesAcked: 1200}}, nil)
	if b.sampler.IsAppLimited() {
		t.Fatal("idle boundary did not end after ACK of later data")
	}
	if b.sampler.EndOfAppLimitedPhase() != 1 {
		t.Fatal("idle boundary advanced without a supply notification")
	}
	b.SetApplicationLimited(true)
	if !b.sampler.IsAppLimited() || b.sampler.EndOfAppLimitedPhase() != 3 {
		t.Fatal("next idle epoch was not recorded")
	}
}

type applicationLimitedRTT struct{}

func (applicationLimitedRTT) MinRTT() time.Duration                             { return 160 * time.Millisecond }
func (applicationLimitedRTT) LatestRTT() time.Duration                          { return 160 * time.Millisecond }
func (applicationLimitedRTT) SmoothedRTT() time.Duration                        { return 160 * time.Millisecond }
func (applicationLimitedRTT) MeanDeviation() time.Duration                      { return 0 }
func (applicationLimitedRTT) MaxAckDelay() time.Duration                        { return 0 }
func (applicationLimitedRTT) PTO(bool) time.Duration                            { return time.Second }
func (applicationLimitedRTT) UpdateRTT(time.Duration, time.Duration) {}
func (applicationLimitedRTT) SetMaxAckDelay(time.Duration)                      {}
func (applicationLimitedRTT) SetInitialRTT(time.Duration)                       {}
