// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// entry holds a per-IP rate limiter and the last time it was accessed.
type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// rateLimiter implements per-IP token-bucket rate limiting with automatic
// eviction of stale entries.
type rateLimiter struct {
	mu       sync.Mutex
	entries  map[string]*entry
	rate     rate.Limit
	burst    int
	stopCh   chan struct{}
	staleAge time.Duration
	interval time.Duration
}

// newRateLimiter creates a per-IP rate limiter that evicts idle entries.
// The cleanup goroutine runs every cleanupInterval and removes entries
// that have not been seen for longer than staleAge.
func newRateLimiter(r float64, burst int, staleAge, cleanupInterval time.Duration) *rateLimiter {
	rl := &rateLimiter{
		entries:  make(map[string]*entry),
		rate:     rate.Limit(r),
		burst:    burst,
		stopCh:   make(chan struct{}),
		staleAge: staleAge,
		interval: cleanupInterval,
	}
	go rl.cleanup()
	return rl
}

// Allow reports whether a request from the given IP should be permitted.
// A new limiter is created on the first request from an unseen IP.
func (rl *rateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	e, ok := rl.entries[ip]
	if !ok {
		e = &entry{
			limiter: rate.NewLimiter(rl.rate, rl.burst),
		}
		rl.entries[ip] = e
	}
	e.lastSeen = time.Now()
	return e.limiter.Allow()
}

// Stop halts the background cleanup goroutine.
func (rl *rateLimiter) Stop() {
	close(rl.stopCh)
}

// cleanup periodically evicts entries that have been idle longer than staleAge.
func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(rl.interval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, e := range rl.entries {
				if now.Sub(e.lastSeen) > rl.staleAge {
					delete(rl.entries, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}
