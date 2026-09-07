//go:build linux

package direct

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestConnectedUDPWriteMsgPreservesGSOSegments(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn := &directPacketConn{UDPConn: client}
	oob := make([]byte, unix.CmsgSpace(2))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = unix.IPPROTO_UDP
	header.Type = unix.UDP_SEGMENT
	header.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], 1200)
	payload := append(bytes.Repeat([]byte{1}, 1200), bytes.Repeat([]byte{2}, 100)...)
	n, _, err := conn.WriteMsgUDP(payload, oob, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("written=%d", n)
	}
	server.SetReadDeadline(time.Now().Add(time.Second))
	for i, want := range [][]byte{payload[:1200], payload[1200:]} {
		buf := make([]byte, 2048)
		n, _, err := server.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("segment %d length=%d, want=%d", i, n, len(want))
		}
	}
}
