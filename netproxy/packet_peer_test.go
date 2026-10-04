package netproxy

import (
	"net/netip"
	"testing"
)

type peerReaderTestConn struct{ fakePacketConnForLifecycle }

func (*peerReaderTestConn) ReadFromWithPeer(p []byte) (int, netip.AddrPort, netip.AddrPort, error) {
	return copy(p, "x"), netip.MustParseAddrPort("28.0.0.1:443"), netip.MustParseAddrPort("192.0.2.1:443"), nil
}

func TestReadFromWithPeerKeepsNATAndPeerSeparate(t *testing.T) {
	buf := make([]byte, 1)
	n, from, peer, err := ReadFromWithPeer(&peerReaderTestConn{}, buf)
	if err != nil || n != 1 || buf[0] != 'x' || from.String() != "28.0.0.1:443" || peer.String() != "192.0.2.1:443" {
		t.Fatalf("read=(%d,%v,%v,%v)", n, from, peer, err)
	}
	n, from, peer, err = ReadFromWithPeer(&fakePacketConnForLifecycle{}, buf)
	if err != nil || n != 0 || from != peer {
		t.Fatalf("fallback=(%d,%v,%v,%v)", n, from, peer, err)
	}
}
