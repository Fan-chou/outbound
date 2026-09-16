package grpc

import (
	"bytes"
	"fmt"
	proto "github.com/daeuniverse/outbound/pkg/gun_proto"
	"io"
	"sync"
	"testing"
	"time"
)

type delayedPayloadTun struct {
	*stubTun
	entered  chan struct{}
	release  chan struct{}
	observed chan []byte
}

func (s *delayedPayloadTun) Send(h *proto.Hunk) error {
	close(s.entered)
	<-s.release
	s.observed <- append([]byte(nil), h.Data...)
	return io.EOF
}
func TestTimedOutWriteOwnsItsPendingPayload(t *testing.T) {
	s := &delayedPayloadTun{stubTun: newStubTun(make(chan *proto.Hunk)), entered: make(chan struct{}), release: make(chan struct{}), observed: make(chan []byte, 1)}
	c := NewClientConn(s, func() {})
	defer c.Close()
	payload := bytes.Repeat([]byte{0x5a}, 1024)
	result := make(chan error, 1)
	go func() { _, err := c.Write(payload); result <- err }()
	<-s.entered
	_ = c.SetWriteDeadline(time.Now())
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("wanted deadline")
		}
	case <-time.After(time.Second):
		close(s.release)
		t.Fatal("deadline did not release Write")
	}
	for i := range payload {
		payload[i] = 0xff
	}
	close(s.release)
	select {
	case got := <-s.observed:
		if !bytes.Equal(got, bytes.Repeat([]byte{0x5a}, 1024)) {
			t.Fatal("pending send used caller buffer after return")
		}
	case <-time.After(time.Second):
		t.Fatal("send did not finish")
	}
}

type identifiedSendTun struct {
	*stubTun
	id int
}

func (s *identifiedSendTun) Send(*proto.Hunk) error { return fmt.Errorf("sender-%d", s.id) }
func TestConcurrentConnectionsKeepTheirSendResults(t *testing.T) {
	var wg sync.WaitGroup
	for id := 0; id < 32; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			s := &identifiedSendTun{stubTun: newStubTun(make(chan *proto.Hunk)), id: id}
			c := NewClientConn(s, func() {})
			defer c.Close()
			for i := 0; i < 200; i++ {
				n, err := c.Write([]byte("payload"))
				if n != 0 || err == nil || err.Error() != fmt.Sprintf("sender-%d", id) {
					t.Errorf("wrong send result on %d: %d,%v", id, n, err)
					return
				}
			}
		}(id)
	}
	wg.Wait()
}
