package anytls

import (
	"bytes"
	"testing"
)

func TestWriteFrameEncodingUnchanged(t *testing.T) {
	rec := &recordingConn{}
	sess := newSession(rec, 0)
	sess.sendPadding = false

	frame := newFrame(cmdPSH, 7)
	frame.data = []byte("hello-anytls")
	if _, err := writeFrame(sess, frame); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.writes) != 1 {
		t.Fatalf("writes = %d, want 1", len(rec.writes))
	}
	got := rec.writes[0]
	want := make([]byte, headerOverHeadSize+len(frame.data))
	encodeFrame(want, frame)
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded frame mismatch\ngot  %x\nwant %x", got, want)
	}
}
