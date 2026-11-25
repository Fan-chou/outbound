package netproxy

import (
	"context"
	"testing"
)

type testPinDialer struct {
	next Dialer
	pins bool
}

func (d *testPinDialer) DialContext(context.Context, string, string) (Conn, error) { return nil, nil }
func (d *testPinDialer) UnwrapDialer() Dialer                                      { return d.next }
func (d *testPinDialer) PinsUDPSessionTarget() bool                                { return d.pins }

type testNonPinWrapperDialer struct {
	next Dialer
}

func (d *testNonPinWrapperDialer) DialContext(context.Context, string, string) (Conn, error) {
	return nil, nil
}
func (d *testNonPinWrapperDialer) UnwrapDialer() Dialer { return d.next }

func TestPinsUDPSessionTargetDoesNotLeakThroughOuterProtocol(t *testing.T) {
	if PinsUDPSessionTarget(nil) {
		t.Fatal("PinsUDPSessionTarget(nil) = true, want false")
	}
	pin := &testPinDialer{pins: true}
	if !PinsUDPSessionTarget(pin) {
		t.Fatal("PinsUDPSessionTarget(pin) = false, want true")
	}
	outerNonPin := &testNonPinWrapperDialer{next: pin}
	if PinsUDPSessionTarget(outerNonPin) {
		t.Fatal("PinsUDPSessionTarget leaked through non-pinning outer wrapper")
	}
	explicitFalse := &testPinDialer{next: pin, pins: false}
	if PinsUDPSessionTarget(explicitFalse) {
		t.Fatal("PinsUDPSessionTarget returned true when outer explicitly false")
	}
}
