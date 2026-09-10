package frag

import (
	"sync/atomic"
	"testing"
)

func TestDefraggerEvictsOldestMissingFragments(t *testing.T) {
	d := NewDefragger()
	defer d.Close()
	if d.config.MaxPacketIDs != 256 {
		t.Fatalf("default slots=%d", d.config.MaxPacketIDs)
	}
	var released [300]atomic.Int32
	for i := range released {
		m := fragmentMessage(1, uint16(i+1), 0, 2, "old")
		m.Release = func() { released[i].Add(1) }
		d.Feed(m)
	}
	if len(d.packets) != 256 {
		t.Fatalf("pending=%d", len(d.packets))
	}
	for i := range released {
		want := int32(0)
		if i < 44 {
			want = 1
		}
		if released[i].Load() != want {
			t.Fatalf("fragment %d releases=%d want=%d", i, released[i].Load(), want)
		}
	}
	// Even at capacity, an already admitted packet can complete.
	if got := d.Feed(fragmentMessage(1, 300, 1, 2, "tail")); got == nil || string(got.Data) != "oldtail" {
		t.Fatal("existing packet could not complete at capacity")
	}
	// New complete traffic is admitted despite all the other missing fragments.
	d.Feed(fragmentMessage(1, 301, 0, 2, "new"))
	if got := d.Feed(fragmentMessage(1, 301, 1, 2, "tail")); got == nil || string(got.Data) != "newtail" {
		t.Fatal("missing fragments blocked complete new traffic")
	}
	d.Close()
	for i := range released {
		if released[i].Load() != 1 {
			t.Fatalf("fragment %d final releases=%d", i, released[i].Load())
		}
	}
	if d.memoryBytes != 0 {
		t.Fatalf("retained bytes=%d", d.memoryBytes)
	}
}

func TestDefraggerDefaultAllowsHundredPendingPackets(t *testing.T) {
	d := NewDefragger()
	defer d.Close()
	// 1000 packets/s with a 100ms gap between fragments needs 100 slots.
	for i := 0; i < 100; i++ {
		d.Feed(fragmentMessage(1, uint16(i+1), 0, 2, "a"))
	}
	for i := 99; i >= 0; i-- {
		if got := d.Feed(fragmentMessage(1, uint16(i+1), 1, 2, "b")); got == nil || string(got.Data) != "ab" {
			t.Fatalf("reordered packet %d lost", i)
		}
	}
	if len(d.packets) != 0 || d.memoryBytes != 0 {
		t.Fatal("completed packets retained")
	}
}
