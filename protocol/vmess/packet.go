package vmess

import (
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

func (c *Conn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	if !c.metadata.IsPacketAddr() {
		// Fixed target: read the datagram straight into the caller's
		// buffer instead of bouncing through a pooled MaxUDPSize copy.
		n, err = c.read(p)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		tgt, err := c.dialTargetAddrPort()
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		return n, tgt, nil
	}
	// The caller's capacity covers payload only. Allow room for the largest
	// packet address, bounded by the VMess chunk's 16-bit length field.
	frameSize := 0xffff
	if len(p) < frameSize-19 {
		frameSize = len(p) + 19
	}
	buf := pool.Get(frameSize)
	defer pool.Put(buf)
	n, err = c.read(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if n == 0 {
		return 0, netip.AddrPort{}, fmt.Errorf("not enough data to read for PacketAddr")
	}
	addrTyp, address, err := ExtractPacketAddr(buf[:n])
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	addrLen := PacketAddrLength(addrTyp)
	if n-addrLen > len(p) {
		return 0, netip.AddrPort{}, netproxy.DatagramDropped(io.ErrShortBuffer)
	}
	return copy(p, buf[addrLen:n]), address, nil
}

func (c *Conn) WriteTo(p []byte, addr string) (n int, err error) {
	if c.metadata.IsPacketAddr() {
		// VMess packet addr does not support domain.
		address, err := c.writeTargetAddrPort(addr)
		if err != nil {
			return 0, err
		}
		packetAddrLen := UDPAddrToPacketAddrLength(address)
		buf := pool.Get(packetAddrLen + len(p))
		defer pool.Put(buf)

		err = PutPacketAddr(buf, address)
		if err != nil {
			return 0, err
		}
		copy(buf[packetAddrLen:], p)
		return c.write(buf)
	}

	return c.write(p)
}

func (c *Conn) writeTargetAddrPort(addr string) (*net.UDPAddr, error) {
	if addr == c.dialTgt {
		target, err := c.dialTargetAddrPort()
		if err != nil {
			return nil, err
		}
		return net.UDPAddrFromAddrPort(target), nil
	}
	if cached, ok := c.writeCache.Load(addr); ok {
		return net.UDPAddrFromAddrPort(cached), nil
	}
	target, err := resolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	addrPort := unmapAddrPort(target.AddrPort())
	c.writeCache.Store(addr, addrPort)
	return target, nil
}
