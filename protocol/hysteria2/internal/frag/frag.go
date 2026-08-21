package frag

import (
	"errors"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

var (
	// ErrNilMessage is returned when fragmentation is asked to process no
	// message.
	ErrNilMessage = errors.New("cannot fragment a nil UDP message")
	// ErrMaxSizeTooSmall is returned when maxSize cannot hold a UDPMessage
	// header plus at least one payload byte. Passing that value into the
	// fragment loop divides by zero or slices with a negative length.
	ErrMaxSizeTooSmall = errors.New("max datagram size too small to fragment UDP message")
	// ErrTooManyFragments is returned when a payload would need more than
	// the protocol's uint8 FragCount maximum of 255 pieces.
	ErrTooManyFragments = errors.New("UDP message exceeds maximum fragment count of 255")
)

func FragUDPMessage(m *protocol.UDPMessage, maxSize int) ([]protocol.UDPMessage, error) {
	if m == nil {
		return nil, ErrNilMessage
	}
	if maxSize <= m.HeaderSize() {
		return nil, ErrMaxSizeTooSmall
	}
	if m.Size() <= maxSize {
		return []protocol.UDPMessage{*m}, nil
	}

	fullPayload := m.Data
	maxPayloadSize := maxSize - m.HeaderSize()
	n := (len(fullPayload)-1)/maxPayloadSize + 1
	if n > 255 {
		return nil, ErrTooManyFragments
	}
	fragCount := uint8(n)
	off := 0
	fragID := uint8(0)
	frags := make([]protocol.UDPMessage, fragCount)
	for off < len(fullPayload) {
		payloadSize := len(fullPayload) - off
		if payloadSize > maxPayloadSize {
			payloadSize = maxPayloadSize
		}
		frag := *m
		frag.FragID = fragID
		frag.FragCount = fragCount
		frag.Data = fullPayload[off : off+payloadSize]
		frags[fragID] = frag
		off += payloadSize
		fragID++
	}
	return frags, nil
}

const (
	// DefaultFragmentTTL bounds how long an incomplete packet may retain a
	// pooled transport buffer without receiving another fragment.
	DefaultFragmentTTL = 5 * time.Second
	// DefaultMaxPacketIDs bounds the number of interleaved packets retained by
	// one UDP session.
	DefaultMaxPacketIDs = 64
	// DefaultMaxPacketSize bounds the reassembled payload size. It is larger
	// than the local 4 KiB send buffer so it does not reject valid UDP payloads
	// from peers that use a larger datagram limit.
	DefaultMaxPacketSize = 64 * 1024
	// DefaultMaxMemory bounds the payload bytes retained by incomplete packets
	// in one UDP session. The assembled output is owned by the caller and is not
	// retained by the Defragger after completion.
	DefaultMaxMemory = 4 * 1024 * 1024
)

// DefraggerConfig controls resource limits for one UDP session's reassembly
// state. Zero or negative values use the corresponding safe default.
type DefraggerConfig struct {
	FragmentTTL    time.Duration
	MaxPacketIDs   int
	MaxPacketSize  int
	MaxMemoryBytes int
}

// Defragger handles reassembly of UDP messages whose fragments may arrive
// interleaved and out of order. It is safe to call Feed and Close from
// different goroutines; the UDP session normally serializes them with its
// receive lock as well.
type Defragger struct {
	mu sync.Mutex

	packets     map[uint16]*fragmentState
	memoryBytes int
	config      DefraggerConfig
	initialized bool
	closed      bool

	timer           *time.Timer
	timerGeneration uint64
}

type fragmentState struct {
	fragCount uint8
	sessionID uint32
	addr      string
	frags     []*protocol.UDPMessage
	count     int
	size      int
	deadline  time.Time
}

// NewDefragger creates a Defragger with the supplied limits. Omitting the
// config preserves the defaults used by the zero value.
func NewDefragger(config ...DefraggerConfig) *Defragger {
	d := &Defragger{}
	if len(config) > 0 {
		d.config = config[0]
	}
	d.mu.Lock()
	d.initLocked()
	d.mu.Unlock()
	return d
}

func (d *Defragger) initLocked() {
	if d.initialized {
		return
	}
	if d.config.FragmentTTL <= 0 {
		d.config.FragmentTTL = DefaultFragmentTTL
	}
	if d.config.MaxPacketIDs <= 0 {
		d.config.MaxPacketIDs = DefaultMaxPacketIDs
	}
	if d.config.MaxPacketSize <= 0 {
		d.config.MaxPacketSize = DefaultMaxPacketSize
	}
	if d.config.MaxMemoryBytes <= 0 {
		d.config.MaxMemoryBytes = DefaultMaxMemory
	}
	d.packets = make(map[uint16]*fragmentState)
	d.initialized = true
}

func (d *Defragger) Feed(m *protocol.UDPMessage) *protocol.UDPMessage {
	if m == nil {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.initLocked()
	d.expireLocked(time.Now())
	defer d.scheduleTimerLocked()

	if d.closed {
		releaseMessage(m)
		return nil
	}

	// FragCount zero is not a valid wire representation. A non-fragmented
	// message must use fragment ID zero, and every fragmented message must
	// carry an in-range fragment ID.
	if m.FragCount == 0 || m.FragID >= m.FragCount {
		releaseMessage(m)
		return nil
	}
	if len(m.Data) > d.config.MaxPacketSize {
		releaseMessage(m)
		return nil
	}
	if m.FragCount == 1 {
		return m
	}

	state, ok := d.packets[m.PacketID]
	if !ok {
		// Reject rather than evicting an in-flight packet. This prevents a
		// peer from keeping the session permanently busy by rotating IDs and
		// makes the resource ceiling deterministic.
		if len(d.packets) >= d.config.MaxPacketIDs || !d.fitsMemory(len(m.Data)) {
			releaseMessage(m)
			return nil
		}
		state = &fragmentState{
			fragCount: m.FragCount,
			sessionID: m.SessionID,
			addr:      m.Addr,
			frags:     make([]*protocol.UDPMessage, int(m.FragCount)),
			deadline:  time.Now().Add(d.config.FragmentTTL),
		}
		d.packets[m.PacketID] = state
	} else {
		// A PacketID identifies one logical packet. Mixing its fragment
		// count, session or address would make the assembled payload
		// ambiguous, so reject the new fragment but preserve the valid state.
		if state.fragCount != m.FragCount || state.sessionID != m.SessionID || state.addr != m.Addr {
			releaseMessage(m)
			return nil
		}
		if state.frags[m.FragID] != nil {
			// Duplicate fragments must not retain a pooled datagram buffer.
			releaseMessage(m)
			return nil
		}
		if state.size > d.config.MaxPacketSize-len(m.Data) {
			d.dropStateLocked(m.PacketID, state)
			releaseMessage(m)
			return nil
		}
		if !d.fitsMemory(len(m.Data)) {
			releaseMessage(m)
			return nil
		}
	}

	state.frags[m.FragID] = m
	state.count++
	state.size += len(m.Data)
	d.memoryBytes += len(m.Data)
	if state.count != len(state.frags) {
		return nil
	}

	// Assemble before releasing the pooled fragment buffers. The returned
	// message owns the new data slice and deliberately has no Release callback.
	data := make([]byte, state.size)
	off := 0
	for _, frag := range state.frags {
		off += copy(data[off:], frag.Data)
	}
	d.removeStateLocked(m.PacketID, state)
	for _, frag := range state.frags {
		releaseMessage(frag)
	}
	m.Data = data
	m.FragID = 0
	m.FragCount = 1
	m.Release = nil
	return m
}

func (d *Defragger) fitsMemory(additional int) bool {
	return additional >= 0 && additional <= d.config.MaxMemoryBytes &&
		d.memoryBytes <= d.config.MaxMemoryBytes-additional
}

func (d *Defragger) expireLocked(now time.Time) {
	for packetID, state := range d.packets {
		if now.Before(state.deadline) {
			continue
		}
		d.dropStateLocked(packetID, state)
	}
}

func (d *Defragger) dropStateLocked(packetID uint16, state *fragmentState) {
	if current, ok := d.packets[packetID]; !ok || current != state {
		return
	}
	d.removeStateLocked(packetID, state)
	for _, frag := range state.frags {
		releaseMessage(frag)
	}
}

func (d *Defragger) removeStateLocked(packetID uint16, state *fragmentState) {
	delete(d.packets, packetID)
	d.memoryBytes -= state.size
	if d.memoryBytes < 0 {
		d.memoryBytes = 0
	}
}

func (d *Defragger) scheduleTimerLocked() {
	d.timerGeneration++
	generation := d.timerGeneration
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	if d.closed || len(d.packets) == 0 {
		return
	}

	deadline := time.Time{}
	for _, state := range d.packets {
		if deadline.IsZero() || state.deadline.Before(deadline) {
			deadline = state.deadline
		}
	}
	delay := time.Until(deadline)
	if delay < 0 {
		delay = 0
	}
	d.timer = time.AfterFunc(delay, func() {
		d.expireTimer(generation)
	})
}

func (d *Defragger) expireTimer(generation uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || generation != d.timerGeneration {
		return
	}
	d.timer = nil
	d.expireLocked(time.Now())
	d.scheduleTimerLocked()
}

func releaseMessage(m *protocol.UDPMessage) {
	if m != nil && m.Release != nil {
		m.Release()
	}
}

// Close releases every incomplete fragment and prevents future Feed calls
// from retaining buffers. It is idempotent and stops the expiry timer.
func (d *Defragger) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.initLocked()
	if d.closed {
		return
	}
	d.closed = true
	d.timerGeneration++
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	for packetID, state := range d.packets {
		d.removeStateLocked(packetID, state)
		for _, frag := range state.frags {
			releaseMessage(frag)
		}
	}
	d.packets = nil
	d.memoryBytes = 0
}
