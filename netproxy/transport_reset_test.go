package netproxy

import (
	"context"
	"testing"
)

type testResetDialer struct {
	next   Dialer
	resets int
}

func (d *testResetDialer) DialContext(context.Context, string, string) (Conn, error) { return nil, nil }
func (d *testResetDialer) UnwrapDialer() Dialer                                      { return d.next }
func (d *testResetDialer) ResetTransport()                                           { d.resets++ }

func TestResetTransportWalksChainAndStopsOnCycles(t *testing.T) {
	inner := &testResetDialer{}
	outer := &testResetDialer{next: inner}
	if !ResetTransport(outer) {
		t.Fatal("ResetTransport returned false, want true")
	}
	if outer.resets != 1 || inner.resets != 1 {
		t.Fatalf("resets = (%d, %d), want (1, 1)", outer.resets, inner.resets)
	}

	// Self-cycle must terminate without looping.
	cycle := &testResetDialer{}
	cycle.next = cycle
	if !ResetTransport(cycle) {
		t.Fatal("ResetTransport on cycle returned false, want true")
	}
	if cycle.resets != 1 {
		t.Fatalf("cycle resets = %d, want 1", cycle.resets)
	}

	if ResetTransport(nil) {
		t.Fatal("ResetTransport(nil) = true, want false")
	}
}
