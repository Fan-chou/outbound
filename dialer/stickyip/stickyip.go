/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Package stickyip provides sticky IP caching for proxy server connections.
// Within a health check cycle, the same resolved IP is reused to ensure
// connection stability when a proxy domain resolves to multiple IPs.
package stickyip

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

const (
	// CacheTTL is how long to cache a successful proxy IP.
	// This should be at least the health check interval to ensure
	// all connections in a cycle use the same IP.
	CacheTTL = 5 * time.Minute

	// cacheCleanupInterval bounds how long expired entries can remain in the map
	// without a direct lookup on the same proxy address.
	cacheCleanupInterval = time.Minute
)

// ProxyIpCache manages sticky IP resolution for proxy server domains.
// It separately caches IPs that work for TCP and UDP since some proxies
// may have different availability per protocol.
type ProxyIpCache struct {
	sync.RWMutex
	cache         map[string]*proxyIpEntry
	nextCleanupAt time.Time
}

type proxyIpEntry struct {
	// tcp4Addr is the IPv4:port that works for TCP connections.
	tcp4Addr string
	// tcp6Addr is the IPv6:port that works for TCP connections.
	tcp6Addr string
	// udp4Addr is the IPv4:port that works for UDP connections.
	udp4Addr string
	// udp6Addr is the IPv6:port that works for UDP connections.
	udp6Addr string
	// stale*Addr preserve the last confirmed working IP across check cycles
	// for fallback if DNS resolution fails in a subsequent cycle (StickyIP#8).
	staleTcp4Addr string
	staleTcp6Addr string
	staleUdp4Addr string
	staleUdp6Addr string
	// expiresAt is when this cache entry expires.
	expiresAt time.Time
	// checkCycle is the health check cycle number this entry belongs to.
	checkCycle uint64
}

func (e *proxyIpEntry) getActive(key string) string {
	switch key {
	case "tcp4":
		return e.tcp4Addr
	case "tcp6":
		return e.tcp6Addr
	case "udp4":
		return e.udp4Addr
	case "udp6":
		return e.udp6Addr
	default:
		return ""
	}
}

func (e *proxyIpEntry) setActive(key, addr string) {
	switch key {
	case "tcp4":
		e.tcp4Addr = addr
	case "tcp6":
		e.tcp6Addr = addr
	case "udp4":
		e.udp4Addr = addr
	case "udp6":
		e.udp6Addr = addr
	}
}

func (e *proxyIpEntry) getStale(key string) string {
	switch key {
	case "tcp4":
		return e.staleTcp4Addr
	case "tcp6":
		return e.staleTcp6Addr
	case "udp4":
		return e.staleUdp4Addr
	case "udp6":
		return e.staleUdp6Addr
	default:
		return ""
	}
}

func (e *proxyIpEntry) setStale(key, addr string) {
	switch key {
	case "tcp4":
		e.staleTcp4Addr = addr
	case "tcp6":
		e.staleTcp6Addr = addr
	case "udp4":
		e.staleUdp4Addr = addr
	case "udp6":
		e.staleUdp6Addr = addr
	}
}

func (e *proxyIpEntry) demoteActiveToStale() {
	if e.tcp4Addr != "" {
		e.staleTcp4Addr = e.tcp4Addr
		e.tcp4Addr = ""
	}
	if e.tcp6Addr != "" {
		e.staleTcp6Addr = e.tcp6Addr
		e.tcp6Addr = ""
	}
	if e.udp4Addr != "" {
		e.staleUdp4Addr = e.udp4Addr
		e.udp4Addr = ""
	}
	if e.udp6Addr != "" {
		e.staleUdp6Addr = e.udp6Addr
		e.udp6Addr = ""
	}
}

func (e *proxyIpEntry) hasAny() bool {
	return e.tcp4Addr != "" || e.tcp6Addr != "" || e.udp4Addr != "" || e.udp6Addr != "" ||
		e.staleTcp4Addr != "" || e.staleTcp6Addr != "" || e.staleUdp4Addr != "" || e.staleUdp6Addr != ""
}

// cacheKey generates a cache key from network (tcp/udp) and IP version (4/6).
func cacheKey(network, ipVersion string) string {
	return network + ipVersion
}

// NewProxyIpCache creates a new proxy IP cache.
func NewProxyIpCache() *ProxyIpCache {
	return &ProxyIpCache{
		cache: make(map[string]*proxyIpEntry),
	}
}

func (c *ProxyIpCache) maybeCleanupExpiredLocked(now time.Time) {
	if !c.nextCleanupAt.IsZero() && now.Before(c.nextCleanupAt) {
		return
	}
	c.cleanupExpiredLocked(now)
	c.nextCleanupAt = now.Add(cacheCleanupInterval)
}

func (c *ProxyIpCache) cleanupExpiredLocked(now time.Time) {
	for addr, entry := range c.cache {
		if now.After(entry.expiresAt) {
			delete(c.cache, addr)
		}
	}
}

func (c *ProxyIpCache) deleteIfExpired(proxyAddr string, now time.Time) {
	c.Lock()
	defer c.Unlock()
	entry, ok := c.cache[proxyAddr]
	if !ok {
		return
	}
	if now.After(entry.expiresAt) {
		delete(c.cache, proxyAddr)
	}
}

// Set stores a successful proxy IP address for a specific protocol and IP version with cycle tracking.
// network should be "tcp" or "udp", ipVersion should be "4" or "6".
// This ensures we only cache IPs that actually work for the specific protocol and address family.
func (c *ProxyIpCache) Set(originalAddr, actualAddr string, network string, ipVersion string, cycle uint64) {
	if c == nil {
		return
	}

	now := time.Now()

	c.Lock()
	defer c.Unlock()
	c.maybeCleanupExpiredLocked(now)

	// Get or create entry.
	entry, exists := c.cache[originalAddr]
	if !exists {
		entry = &proxyIpEntry{}
		c.cache[originalAddr] = entry
	}

	// Refresh metadata on every successful set so long-lived entries do not
	// become permanently expired or stuck on an old cycle. If this entry still
	// held active addresses from an earlier cycle, demote them to stale first so
	// other protocols/families in the entry are not mistaken for current-cycle hits.
	if exists && entry.checkCycle != cycle {
		entry.demoteActiveToStale()
	}
	entry.expiresAt = now.Add(CacheTTL)
	entry.checkCycle = cycle

	// Update the appropriate address based on network type and IP version.
	key := cacheKey(network, ipVersion)
	entry.setActive(key, actualAddr)
	entry.setStale(key, actualAddr)

	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"original_addr": originalAddr,
			"actual_addr":   actualAddr,
			"network":       network,
			"ip_version":    ipVersion,
			"cycle":         cycle,
		}).Debug("[StickyIP] Cached proxy IP")
	}
}

// GetWithCycleAndIpVersion returns the cached IP for the specified network and IP version if it belongs to the current check cycle.
// network should be "tcp" or "udp", ipVersion should be "4" or "6".
func (c *ProxyIpCache) GetWithCycleAndIpVersion(proxyAddr string, network string, ipVersion string, currentCycle uint64) string {
	// This lookup runs on every proxy dial; build the debug entries only when
	// debug logging is actually enabled (the Set path already does this).
	debugLogs := logger.IsLevelEnabled(logrus.DebugLevel)
	if c == nil {
		if debugLogs {
			logger.WithField("proxy_addr", proxyAddr).Debug("[StickyIP] Cache is nil")
		}
		return proxyAddr
	}

	now := time.Now()

	c.RLock()
	entry, ok := c.cache[proxyAddr]
	if !ok {
		c.RUnlock()
		if debugLogs {
			logger.WithField("proxy_addr", proxyAddr).Debug("[StickyIP] No cache entry found")
		}
		return proxyAddr
	}

	expiredAt := entry.expiresAt
	if now.After(expiredAt) {
		c.RUnlock()
		c.deleteIfExpired(proxyAddr, now)
		if debugLogs {
			logger.WithFields(logrus.Fields{
				"proxy_addr": proxyAddr,
				"expired_at": expiredAt,
			}).Debug("[StickyIP] Cache entry expired")
		}
		return proxyAddr
	}

	// Only use cached IP if it's from the current cycle.
	if entry.checkCycle != currentCycle {
		entryCycle := entry.checkCycle
		c.RUnlock()
		if debugLogs {
			logger.WithFields(logrus.Fields{
				"proxy_addr":    proxyAddr,
				"entry_cycle":   entryCycle,
				"current_cycle": currentCycle,
			}).Debug("[StickyIP] Cycle mismatch - cache not from current cycle")
		}
		return proxyAddr
	}

	// Return the protocol and IP version specific cached address.
	key := cacheKey(network, ipVersion)
	cachedAddr := entry.getActive(key)
	c.RUnlock()

	if cachedAddr == "" {
		if debugLogs {
			logger.WithFields(logrus.Fields{
				"proxy_addr": proxyAddr,
				"network":    network,
				"ip_version": ipVersion,
			}).Debug("[StickyIP] No cached IP for this network type and IP version")
		}
		return proxyAddr
	}

	if debugLogs {
		logger.WithFields(logrus.Fields{
			"proxy_addr":  proxyAddr,
			"cached_addr": cachedAddr,
			"network":     network,
			"ip_version":  ipVersion,
		}).Debug("[StickyIP] Cache hit - returning cached IP")
	}
	return cachedAddr
}

// GetWithCycle returns the cached IP for the specified network (backward compatibility).
// Deprecated: Use GetWithCycleAndIpVersion for proper IP version separation.
func (c *ProxyIpCache) GetWithCycle(proxyAddr string, network string, currentCycle uint64) string {
	// Try IPv4 first, then IPv6 for backward compatibility
	if addr := c.GetWithCycleAndIpVersion(proxyAddr, network, "4", currentCycle); addr != proxyAddr {
		return addr
	}
	return c.GetWithCycleAndIpVersion(proxyAddr, network, "6", currentCycle)
}

// Invalidate removes all cached entries for a proxy address.
func (c *ProxyIpCache) Invalidate(proxyAddr string) {
	if c == nil {
		return
	}
	c.Lock()
	defer c.Unlock()
	delete(c.cache, proxyAddr)
}

// InvalidateProtocolAndIpVersion removes the cached entry for a specific protocol and IP version.
// This allows fine-grained invalidation when a specific protocol + address family combination fails.
func (c *ProxyIpCache) InvalidateProtocolAndIpVersion(proxyAddr, network, ipVersion string) {
	if c == nil {
		return
	}
	c.Lock()
	defer c.Unlock()
	entry, exists := c.cache[proxyAddr]
	if !exists {
		return
	}

	key := cacheKey(network, ipVersion)
	entry.setActive(key, "")
	entry.setStale(key, "")

	// If all addresses (active and stale) are empty now, remove the entry entirely.
	if !entry.hasAny() {
		delete(c.cache, proxyAddr)
	} else {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"network":    network,
			"ip_version": ipVersion,
		}).Debug("[StickyIP] Invalidated cache for protocol+IP version")
	}
}

// InvalidateProtocol removes the cached entries for a specific protocol (both IPv4 and IPv6).
// This is kept for backward compatibility but invalidates both IP versions.
func (c *ProxyIpCache) InvalidateProtocol(proxyAddr, network string) {
	c.InvalidateProtocolAndIpVersion(proxyAddr, network, "4")
	c.InvalidateProtocolAndIpVersion(proxyAddr, network, "6")
}

// InvalidateCycle is retained for source compatibility.
// Deprecated: a bare dialer-local cycle is not globally unique, so this method
// intentionally does nothing. Invalidation must include the proxy address.
func (c *ProxyIpCache) InvalidateCycle(cycle uint64) { _ = cycle }

func (c *ProxyIpCache) invalidateProxyCycle(proxyAddr string, cycle uint64) {
	if c == nil {
		return
	}
	now := time.Now()
	c.Lock()
	defer c.Unlock()
	entry := c.cache[proxyAddr]
	if entry == nil || entry.checkCycle != cycle {
		return
	}
	if now.After(entry.expiresAt) {
		delete(c.cache, proxyAddr)
		return
	}
	// Preserve the last confirmed working IP as stale fallback in case DNS
	// re-resolution fails on the next check cycle (StickyIP#8).
	entry.demoteActiveToStale()
	if !entry.hasAny() {
		delete(c.cache, proxyAddr)
	}
}

func (c *ProxyIpCache) getStaleCandidates(proxyAddr, targetAddr, baseNetwork, requestedIPVersion string) []dialCandidate {
	if c == nil {
		return nil
	}
	now := time.Now()
	c.RLock()
	entry, ok := c.cache[proxyAddr]
	if !ok {
		c.RUnlock()
		return nil
	}
	if now.After(entry.expiresAt) {
		c.RUnlock()
		c.deleteIfExpired(proxyAddr, now)
		return nil
	}
	var versions []string
	switch requestedIPVersion {
	case "4", "6":
		versions = []string{requestedIPVersion}
	default:
		versions = []string{"4", "6"}
	}
	var out []dialCandidate
	for _, ver := range versions {
		if staleAddr := entry.getStale(cacheKey(baseNetwork, ver)); staleAddr != "" {
			out = append(out, dialCandidate{
				targetAddr: rewriteAddrPort(staleAddr, targetAddr),
				ipVersion:  ver,
			})
		}
	}
	c.RUnlock()
	return out
}

// StickyIpDialer wraps a dialer to provide sticky IP caching for proxy servers.
type StickyIpDialer struct {
	dialer     netproxy.Dialer
	cache      *ProxyIpCache
	checkCycle atomic.Uint64
	proxyAddr  string // Original proxy address (domain:port, IP:port, or port-union variant)
	proxyHost  string
	proxyPort  string
}

type ipLookupDialer interface {
	LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error)
}

// NewStickyIpDialer creates a new sticky IP dialer wrapper.
func NewStickyIpDialer(dialer netproxy.Dialer, proxyAddr string, cache *ProxyIpCache) *StickyIpDialer {
	if cache == nil {
		cache = NewProxyIpCache()
	}
	proxyHost, proxyPort, _ := SplitHostPort(proxyAddr)
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithField("proxy_addr", proxyAddr).Debug("[StickyIP] NewStickyIpDialer created")
	}
	return &StickyIpDialer{
		dialer:    dialer,
		cache:     cache,
		proxyAddr: proxyAddr,
		proxyHost: proxyHost,
		proxyPort: proxyPort,
	}
}

// IncrementCheckCycle advances the health check cycle.
func (d *StickyIpDialer) IncrementCheckCycle() {
	oldCycle := d.checkCycle.Load()
	newCycle := d.checkCycle.Add(1)
	logger.WithFields(logrus.Fields{
		"old_cycle":  oldCycle,
		"new_cycle":  newCycle,
		"proxy_addr": d.proxyAddr,
	}).Debug("[StickyIP] Check cycle incremented")
	// Cycle values are local to this dialer, so only invalidate its proxy.
	if newCycle > 0 {
		d.cache.invalidateProxyCycle(d.proxyAddr, newCycle-1)
	}
}

// InvalidateProtocolCache invalidates the cached IP for a specific protocol.
// This is called when a connection fails (e.g., connection refused) to allow
// immediate retry with a different IP.
func (d *StickyIpDialer) InvalidateProtocolCache(proxyAddr, protocol string) {
	d.cache.InvalidateProtocol(proxyAddr, protocol)
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"protocol":   protocol,
		}).Debug("[StickyIP] Protocol cache invalidated due to connection failure")
	}
}

// InvalidateProtocolAndIpVersionCache invalidates the cached IP for a specific protocol and IP version.
// This provides fine-grained cache invalidation when a specific combination fails.
func (d *StickyIpDialer) InvalidateProtocolAndIpVersionCache(proxyAddr, protocol, ipVersion string) {
	d.cache.InvalidateProtocolAndIpVersion(proxyAddr, protocol, ipVersion)
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"protocol":   protocol,
			"ip_version": ipVersion,
		}).Debug("[StickyIP] Protocol+IP version cache invalidated due to connection failure")
	}
}

// GetCachedProxyAddr returns the cached IP for the proxy address and network type.
// network should be "tcp" or "udp".
func (d *StickyIpDialer) GetCachedProxyAddr(network string) string {
	if d == nil {
		return ""
	}
	return d.cache.GetWithCycle(d.proxyAddr, network, d.checkCycle.Load())
}

// GetCachedProxyAddrWithIpVersion returns the cached IP for the proxy address, network type and IP version.
// network should be "tcp" or "udp", ipVersion should be "4" or "6".
func (d *StickyIpDialer) GetCachedProxyAddrWithIpVersion(network, ipVersion string) string {
	if d == nil {
		return ""
	}
	return d.cache.GetWithCycleAndIpVersion(d.proxyAddr, network, ipVersion, d.checkCycle.Load())
}

// DialContext implements sticky IP caching by intercepting dial calls.
// It resolves all IPs for the target, tries the cached IP first, then falls back.
//
// UDP connections are validated only by successful dial completion and PacketConn
// support. stickyip must not read from the returned business UDP connection:
// many proxy protocols manage application-visible session state on that conn, so
// speculative SetReadDeadline/ReadFrom probes can consume packets or terminate
// a flow before dae attaches its own read loop.
func (d *StickyIpDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	// Extract the base network type (tcp/udp) and requested IP family from magic network if present.
	baseNetwork, requestedIPVersion := d.getNetworkPreference(network)

	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr":   d.proxyAddr,
			"target":       addr,
			"network":      network,
			"base_network": baseNetwork,
			"ip_version":   requestedIPVersion,
			"is_proxy":     d.isProxyAddress(addr),
		}).Debug("[StickyIP] DialContext called")
	}

	// Check if we should use a cached proxy IP for this connection
	if d.isProxyAddress(addr) {
		cachedAddr := d.GetCachedProxyAddr(baseNetwork)
		if requestedIPVersion != "" {
			cachedAddr = d.GetCachedProxyAddrWithIpVersion(baseNetwork, requestedIPVersion)
		}
		// Only use cached IP if it's different from proxy address (i.e., it's a resolved IP)
		// GetCachedProxyAddr returns proxyAddr when cache is empty/expired, so we need to check
		if cachedAddr != "" && cachedAddr != d.proxyAddr {
			targetAddr := rewriteAddrPort(cachedAddr, addr)
			// Try with cached IP first
			cachedCtx, cancel := dialAttemptContext(ctx, 2)
			conn, err := d.dialer.DialContext(cachedCtx, network, targetAddr)
			cancel()
			if err == nil {
				if baseNetwork == "udp" {
					_, ok := conn.(netproxy.PacketConn)
					if !ok {
						_ = conn.Close()
						logCacheFailure(d.proxyAddr, targetAddr, network, fmt.Errorf("not a packet connection"))
						d.cache.InvalidateProtocol(d.proxyAddr, baseNetwork)
					} else {
						logCacheHit(d.proxyAddr, targetAddr, network)
						return conn, nil
					}
				} else {
					logCacheHit(d.proxyAddr, targetAddr, network)
					return conn, nil
				}
			} else {
				// Log cache miss/failure
				logCacheFailure(d.proxyAddr, targetAddr, network, err)
				if isCanceledOrClosed(err) {
					return nil, err
				}
				// Cached IP failed, invalidate this protocol's cache
				d.cache.InvalidateProtocol(d.proxyAddr, baseNetwork)
			}
		}
		// No cached IP, or cached IP failed - resolve and try all IPs
		if logger.IsLevelEnabled(logrus.DebugLevel) {
			logger.WithFields(logrus.Fields{
				"proxy_addr":  d.proxyAddr,
				"target":      addr,
				"network":     network,
				"cached_addr": cachedAddr,
			}).Debug("[StickyIP] No valid cached IP - resolving proxy domain")
		}
		return d.dialWithIpResolution(ctx, network, addr, baseNetwork, requestedIPVersion)
	}

	// Not the proxy address, just pass through
	if logger.IsLevelEnabled(logrus.TraceLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": d.proxyAddr,
			"target":     addr,
			"network":    network,
		}).Trace("[StickyIP] Pass-through (not proxy address)")
	}
	return d.dialer.DialContext(ctx, network, addr)
}

// getNetworkPreference extracts the base network type (tcp/udp) and requested IP family from magic network.
func (d *StickyIpDialer) getNetworkPreference(network string) (baseNetwork string, ipVersion string) {
	// Parse magic network to get base type
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		// Default to treating as-is
		return network, ""
	}
	return magicNetwork.Network, magicNetwork.IPVersion
}

func (d *StickyIpDialer) lookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error) {
	if resolver, ok := d.dialer.(ipLookupDialer); ok {
		return resolver.LookupIPAddr(ctx, network, host)
	}
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

const (
	// Preserve a small reserve for each fallback attempt without shrinking the
	// first attempt so aggressively that a merely slow-but-working IP is never
	// given a fair chance to connect.
	stickyFallbackReservePerAttempt = 750 * time.Millisecond
	// stickyRaceHeadStartDelay gives the preferred candidate a Happy-Eyeballs
	// style exclusive window before concurrently racing remaining candidates.
	stickyRaceHeadStartDelay = 250 * time.Millisecond
)

type dialCandidate struct {
	targetAddr string
	ipVersion  string
}

func dialAttemptContext(ctx context.Context, attemptsRemaining int) (context.Context, context.CancelFunc) {
	if attemptsRemaining < 1 {
		attemptsRemaining = 1
	}
	if ctx == nil {
		return netproxy.NewDialTimeoutContext()
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return context.WithDeadline(ctx, deadline)
		}
		if attemptsRemaining == 1 {
			return context.WithDeadline(ctx, deadline)
		}

		reserve := time.Duration(attemptsRemaining-1) * stickyFallbackReservePerAttempt
		if maxReserve := remaining / 2; reserve > maxReserve {
			reserve = maxReserve
		}
		slice := remaining - reserve
		if slice <= 0 {
			slice = remaining / 2
			if slice <= 0 {
				slice = remaining
			}
		}
		return context.WithTimeout(ctx, slice)
	}
	return netproxy.NewDialTimeoutContextFrom(ctx)
}

// isProxyAddress checks if the given address matches the proxy address.
func (d *StickyIpDialer) isProxyAddress(addr string) bool {
	addrHost, addrPort, err := SplitHostPort(addr)
	if err != nil {
		return addr == d.proxyAddr
	}
	if addrHost != d.proxyHost {
		return false
	}
	return matchPortSpec(addrPort, d.proxyPort)
}

func matchPortSpec(port, spec string) bool {
	if port == spec || spec == "" {
		return true
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if part == port {
			return true
		}
		startStr, endStr, ok := strings.Cut(part, "-")
		if !ok {
			continue
		}
		start, errStart := strconv.Atoi(strings.TrimSpace(startStr))
		end, errEnd := strconv.Atoi(strings.TrimSpace(endStr))
		target, errTarget := strconv.Atoi(port)
		if errStart != nil || errEnd != nil || errTarget != nil {
			continue
		}
		if target >= start && target <= end {
			return true
		}
	}
	return false
}

// dialWithIpResolution resolves the address to IPs and tries each one.
// The first successful IP is cached for subsequent connections.
func (d *StickyIpDialer) dialWithIpResolution(ctx context.Context, network, addr, baseNetwork, requestedIPVersion string) (netproxy.Conn, error) {
	host, port, err := SplitHostPort(addr)
	if err != nil {
		// Not in host:port format, try directly
		logResolutionError(d.proxyAddr, "invalid address format", err)
		return d.dialer.DialContext(ctx, network, addr)
	}

	// If already an IP address, dial directly
	if ip := net.ParseIP(host); ip != nil {
		logDirectDial(d.proxyAddr, addr, network)
		return d.dialer.DialContext(ctx, network, addr)
	}

	// Resolve to get all IPs
	ips, err := d.lookupIPAddr(ctx, network, host)
	if err != nil || len(ips) == 0 {
		if isCanceledOrClosed(err) {
			return nil, err
		}
		if staleCandidates := d.cache.getStaleCandidates(d.proxyAddr, addr, baseNetwork, requestedIPVersion); len(staleCandidates) > 0 {
			logResolutionFallbackStale(d.proxyAddr, host, err, len(staleCandidates))
			conn, staleErr := d.dialCandidates(ctx, network, baseNetwork, staleCandidates)
			if staleErr == nil {
				return conn, nil
			}
			if isCanceledOrClosed(staleErr) {
				return nil, staleErr
			}
			for _, cand := range staleCandidates {
				d.cache.InvalidateProtocolAndIpVersion(d.proxyAddr, baseNetwork, cand.ipVersion)
			}
			logAllIPsFailed(d.proxyAddr, staleErr)
			return nil, &net.OpError{Op: "dial", Err: staleErr}
		}
		// No stale confirmed IP available; fall back to original address.
		logResolutionError(d.proxyAddr, host, err)
		return d.dialer.DialContext(ctx, network, addr)
	}
	ips = filterIPAddrsByVersion(ips, requestedIPVersion)
	if len(ips) == 0 {
		return nil, fmt.Errorf("no usable proxy IPs for %s%s", baseNetwork, requestedIPVersion)
	}

	// Log all resolved IPs
	logResolvedIPs(d.proxyAddr, ips, port, network)

	candidates := make([]dialCandidate, 0, len(ips))
	for _, ipAddr := range ips {
		if ipAddr.IP == nil {
			continue
		}
		ipVersion := "4"
		if ipAddr.IP.To4() == nil {
			ipVersion = "6"
		}
		candidates = append(candidates, dialCandidate{
			targetAddr: net.JoinHostPort(ipAddr.IP.String(), port),
			ipVersion:  ipVersion,
		})
	}
	if len(candidates) == 0 {
		logAllIPsFailed(d.proxyAddr, errNoUsableProxyIPs)
		return nil, &net.OpError{Op: "dial", Err: errNoUsableProxyIPs}
	}

	conn, dialErr := d.dialCandidates(ctx, network, baseNetwork, candidates)
	if dialErr != nil {
		if isCanceledOrClosed(dialErr) {
			return nil, dialErr
		}
		logAllIPsFailed(d.proxyAddr, dialErr)
		return nil, &net.OpError{Op: "dial", Err: dialErr}
	}
	return conn, nil
}

func (d *StickyIpDialer) dialCandidate(ctx context.Context, network, baseNetwork string, cand dialCandidate) (netproxy.Conn, error) {
	logTryingIP(d.proxyAddr, cand.targetAddr, network)
	conn, err := d.dialer.DialContext(ctx, network, cand.targetAddr)
	if err != nil {
		if !isCanceledOrClosed(err) {
			logIPFailure(d.proxyAddr, cand.targetAddr, err)
		}
		return nil, err
	}
	if conn == nil {
		return nil, errNoUsableProxyIPs
	}
	if baseNetwork == "udp" {
		if _, ok := conn.(netproxy.PacketConn); !ok {
			_ = conn.Close()
			pktErr := fmt.Errorf("not a packet connection")
			logIPFailure(d.proxyAddr, cand.targetAddr, pktErr)
			return nil, pktErr
		}
	}
	return conn, nil
}

func (d *StickyIpDialer) recordSuccessfulCandidate(baseNetwork string, cand dialCandidate) {
	cycle := d.checkCycle.Load()
	d.cache.Set(d.proxyAddr, cand.targetAddr, baseNetwork, cand.ipVersion, cycle)
	logIPSuccess(d.proxyAddr, cand.targetAddr, baseNetwork, cand.ipVersion, cycle)
}

// dialCandidates dials candidates using a staggered race: candidate[0] gets a
// ~250ms head-start window before remaining candidates are launched concurrently.
// The first successful connection wins, is cached, and all remaining dials are canceled.
func (d *StickyIpDialer) dialCandidates(ctx context.Context, network, baseNetwork string, candidates []dialCandidate) (netproxy.Conn, error) {
	if len(candidates) == 0 {
		return nil, errNoUsableProxyIPs
	}
	if len(candidates) == 1 {
		attemptCtx, cancel := dialAttemptContext(ctx, 1)
		conn, err := d.dialCandidate(attemptCtx, network, baseNetwork, candidates[0])
		cancel()
		if err != nil {
			return nil, err
		}
		d.recordSuccessfulCandidate(baseNetwork, candidates[0])
		return conn, nil
	}

	var parentCtx context.Context
	var parentCancel context.CancelFunc
	if ctx == nil {
		parentCtx, parentCancel = netproxy.NewDialTimeoutContext()
	} else if _, hasDeadline := ctx.Deadline(); hasDeadline {
		parentCtx, parentCancel = context.WithCancel(ctx)
	} else {
		parentCtx, parentCancel = netproxy.NewDialTimeoutContextFrom(ctx)
	}
	defer parentCancel()

	raceCtx, raceCancel := context.WithCancel(parentCtx)
	defer raceCancel()

	headStart := stickyRaceHeadStartDelay
	if deadline, ok := raceCtx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			headStart = 0
		} else if remaining/2 < headStart {
			headStart = remaining / 2
		}
	}

	type raceWin struct {
		cand dialCandidate
		conn netproxy.Conn
	}
	var (
		outcomeMu   sync.Mutex
		outcomeDone bool
	)
	winCh := make(chan raceWin, 1)
	errCh := make(chan error, len(candidates))

	launch := func(cand dialCandidate) {
		go func() {
			conn, err := d.dialCandidate(raceCtx, network, baseNetwork, cand)
			if err == nil {
				outcomeMu.Lock()
				if outcomeDone {
					outcomeMu.Unlock()
					_ = conn.Close()
					return
				}
				outcomeDone = true
				outcomeMu.Unlock()
				raceCancel()
				winCh <- raceWin{cand: cand, conn: conn}
				return
			}
			errCh <- err
		}()
	}

	launched := 1
	launch(candidates[0])

	var headStartTimer *time.Timer
	var headStartCh <-chan time.Time
	launchRest := func() {
		if headStartTimer != nil {
			headStartTimer.Stop()
			headStartCh = nil
		}
		for i := launched; i < len(candidates); i++ {
			launch(candidates[i])
		}
		launched = len(candidates)
	}
	if headStart > 0 {
		headStartTimer = time.NewTimer(headStart)
		defer headStartTimer.Stop()
		headStartCh = headStartTimer.C
	} else {
		launchRest()
	}

	remaining := len(candidates)
	var lastErr error
	for remaining > 0 {
		// Prioritize an already-completed winner before reacting to errors or timeouts.
		select {
		case win := <-winCh:
			d.recordSuccessfulCandidate(baseNetwork, win.cand)
			return win.conn, nil
		default:
		}

		select {
		case win := <-winCh:
			d.recordSuccessfulCandidate(baseNetwork, win.cand)
			return win.conn, nil
		case err := <-errCh:
			remaining--
			lastErr = err
			if isCanceledOrClosed(err) {
				outcomeMu.Lock()
				alreadyDone := outcomeDone
				if !alreadyDone {
					outcomeDone = true
				}
				outcomeMu.Unlock()
				if alreadyDone {
					win := <-winCh
					d.recordSuccessfulCandidate(baseNetwork, win.cand)
					return win.conn, nil
				}
				raceCancel()
				return nil, err
			}
			if launched < len(candidates) {
				launchRest()
			}
		case <-headStartCh:
			select {
			case win := <-winCh:
				d.recordSuccessfulCandidate(baseNetwork, win.cand)
				return win.conn, nil
			default:
				launchRest()
			}
		case <-raceCtx.Done():
			outcomeMu.Lock()
			alreadyDone := outcomeDone
			if !alreadyDone {
				outcomeDone = true
			}
			outcomeMu.Unlock()
			if alreadyDone {
				win := <-winCh
				d.recordSuccessfulCandidate(baseNetwork, win.cand)
				return win.conn, nil
			}
			if stderrors.Is(raceCtx.Err(), context.Canceled) || lastErr == nil {
				return nil, raceCtx.Err()
			}
			return nil, lastErr
		}
	}

	if lastErr == nil {
		lastErr = errNoUsableProxyIPs
	}
	return nil, lastErr
}

func filterIPAddrsByVersion(ips []net.IPAddr, ipVersion string) []net.IPAddr {
	if ipVersion == "" {
		return ips
	}
	filtered := make([]net.IPAddr, 0, len(ips))
	for _, ipAddr := range ips {
		switch ipVersion {
		case "4":
			if ipAddr.IP.To4() != nil {
				filtered = append(filtered, ipAddr)
			}
		case "6":
			if ipAddr.IP.To4() == nil {
				filtered = append(filtered, ipAddr)
			}
		}
	}
	return filtered
}

// SplitHostPort splits host:port strings and also accepts proxy port-union strings like
// example.com:443,8443-8450. IPv6 literals must use brackets, e.g. [2001:db8::1]:443.
func SplitHostPort(addr string) (host, port string, err error) {
	if strings.HasPrefix(addr, "[") {
		end := strings.LastIndexByte(addr, ']')
		if end == -1 || end+1 >= len(addr) || addr[end+1] != ':' {
			return "", "", &net.AddrError{Err: "missing port in address", Addr: addr}
		}
		host = addr[1:end]
		port = addr[end+2:]
		if port == "" {
			return "", "", &net.AddrError{Err: "missing port in address", Addr: addr}
		}
		return host, port, nil
	}

	colon := strings.LastIndexByte(addr, ':')
	if colon == -1 || colon == len(addr)-1 {
		return "", "", &net.AddrError{Err: "missing port in address", Addr: addr}
	}
	return addr[:colon], addr[colon+1:], nil
}

func rewriteAddrPort(cachedAddr, targetAddr string) string {
	cachedHost, _, err := SplitHostPort(cachedAddr)
	if err != nil {
		return cachedAddr
	}
	_, targetPort, err := SplitHostPort(targetAddr)
	if err != nil {
		return cachedAddr
	}
	return net.JoinHostPort(cachedHost, targetPort)
}

// Logging functions for debugging sticky IP caching

var logger = logrus.StandardLogger()

var errNoUsableProxyIPs = stderrors.New("no usable proxy IP addresses")

func logCacheHit(proxyAddr, cachedAddr, network string) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"cached_ip":  cachedAddr,
			"network":    network,
		}).Debug("[StickyIP] Cache hit - using cached proxy IP")
	}
}

func logCacheFailure(proxyAddr, cachedAddr, network string, err error) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"cached_ip":  cachedAddr,
			"network":    network,
			"error":      err.Error(),
		}).Debug("[StickyIP] Cached IP failed - invalidating and re-resolving")
	}
}

func logResolutionError(proxyAddr, host string, err error) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		fields := logrus.Fields{
			"proxy_addr": proxyAddr,
			"host":       host,
		}
		if err != nil {
			fields["error"] = err.Error()
		}
		logger.WithFields(fields).Debug("[StickyIP] DNS resolution failed (will use original domain)")
	}
}

func logResolutionFallbackStale(proxyAddr, host string, err error, count int) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		fields := logrus.Fields{
			"proxy_addr":       proxyAddr,
			"host":             host,
			"stale_candidates": count,
		}
		if err != nil {
			fields["error"] = err.Error()
		}
		logger.WithFields(fields).Debug("[StickyIP] DNS resolution failed (retrying last confirmed proxy IP)")
	}
}

func logDirectDial(proxyAddr, addr, network string) {
	if logger.IsLevelEnabled(logrus.TraceLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"target":     addr,
			"network":    network,
		}).Trace("[StickyIP] Direct dial (already an IP)")
	}
}

func logResolvedIPs(proxyAddr string, ips []net.IPAddr, port, network string) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		ipList := make([]string, 0, len(ips))
		for _, ip := range ips {
			if ip.IP != nil {
				ipList = append(ipList, ip.IP.String())
			}
		}
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"ips":        ipList,
			"port":       port,
			"network":    network,
			"count":      len(ipList),
		}).Debug("[StickyIP] Resolved proxy domain to IPs")
	}
}

func logTryingIP(proxyAddr, targetAddr, network string) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"target":     targetAddr,
			"network":    network,
		}).Debug("[StickyIP] Trying proxy IP")
	}
}

func logIPSuccess(proxyAddr, targetAddr, network, ipVersion string, cycle uint64) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr":  proxyAddr,
			"selected_ip": targetAddr,
			"network":     network,
			"ip_version":  ipVersion,
			"cycle":       cycle,
		}).Debug("[StickyIP] Successfully connected to proxy IP")
	}
}

func logIPFailure(proxyAddr, targetAddr string, err error) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"target":     targetAddr,
			"error":      err.Error(),
		}).Debug("[StickyIP] Failed to connect to proxy IP (will try next)")
	}
}

func isCanceledOrClosed(err error) bool {
	if err == nil {
		return false
	}
	if stderrors.Is(err, context.Canceled) || stderrors.Is(err, net.ErrClosed) {
		return true
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "context canceled") ||
		strings.Contains(errStr, "operation was canceled") ||
		strings.Contains(errStr, "use of closed network connection")
}

// logAllIPsFailed reports that every resolved proxy IP failed for one dial
// attempt.
//
// This is a per-connection decision ("this node is unusable, hand the failure
// back so the caller switches nodes"), not a fault the operator has to act on:
// an unreachable proxy node is the normal state that the health check and the
// dialer group exist to handle. It used to be logged at error level, which
// turned a routine node outage into an error line per dial attempt and buried
// the errors that do need action.
//
// Nothing is dropped by logging it at debug level: the failure is still
// returned to the caller as the dial error, and the consumer escalates it -
// dae logs "Marking dialer as unavailable due to persistent proxy IP failures"
// at warn level once its own failure threshold is reached, and reports the
// per-attempt cause at debug level ("Connectivity Check Failed"). The fields
// below are unchanged, so a debug-level log still names the address and cause.
func logAllIPsFailed(proxyAddr string, lastErr error) {
	if isCanceledOrClosed(lastErr) {
		return
	}
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		fields := logrus.Fields{
			"proxy_addr": proxyAddr,
		}
		if lastErr != nil {
			fields["error"] = lastErr.Error()
		}
		logger.WithFields(fields).Debug("[StickyIP] All proxy IPs failed")
	}
}
