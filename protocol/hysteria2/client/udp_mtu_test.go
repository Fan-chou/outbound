package client

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/frag"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
	"github.com/olicesx/quic-go"
)

func TestUDPConnMaxUnfragmentedPayloadAndFastFrag(t *testing.T) {
	const outerLimit = 1360
	var attempts atomic.Int32
	u := &udpConn{
		ID:             1,
		D:              &frag.Defragger{},
		SendBuf:        make([]byte, protocol.MaxUDPSize),
		target:         "1.1.1.1:443",
		targetBytes:    []byte("1.1.1.1:443"),
		writeAddrStr:   "1.1.1.1:443",
		writeAddrBytes: []byte("1.1.1.1:443"),
		maxDatagramLen: func() int { return outerLimit },
		SendFunc: func(_ context.Context, buf []byte, msg *protocol.UDPMessage) error {
			attempts.Add(1)
			n := msg.Serialize(buf)
			if n > outerLimit {
				return &quic.DatagramTooLargeError{MaxDataLen: outerLimit}
			}
			return nil
		},
	}

	maxPayload := u.MaxUnfragmentedPayload("1.1.1.1:443")
	if maxPayload <= 1300 || maxPayload >= outerLimit {
		t.Fatalf("MaxUnfragmentedPayload = %d, want between 1300 and %d", maxPayload, outerLimit)
	}

	// Oversized payload should fragment immediately without a wasted first SendFunc error.
	oversized := make([]byte, maxPayload+80)
	if _, err := u.WriteTo(oversized, "1.1.1.1:443"); err != nil {
		t.Fatalf("WriteTo oversized err = %v", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("SendFunc calls for 2-fragment packet = %d, want 2 (no wasted initial attempt)", got)
	}
}
