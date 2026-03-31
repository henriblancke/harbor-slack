package main

import (
	"sync"
	"time"
)

// dedupCache tracks recently notified digests to prevent duplicate notifications
// when Harbor sends multiple webhooks for the same digest (retries, re-scans).
// Each pod maintains its own cache — cross-pod duplicates are accepted as a
// trade-off for not requiring external infrastructure.
type dedupCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	ttl     time.Duration
}

func newDedupCache(ttl time.Duration) *dedupCache {
	return &dedupCache{
		entries: make(map[string]time.Time),
		ttl:     ttl,
	}
}

// seen returns true if the key was already notified within the TTL window.
// If not seen before, it records the key and returns false.
func (c *dedupCache) seen(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Evict expired entries opportunistically
	for k, t := range c.entries {
		if now.Sub(t) > c.ttl {
			delete(c.entries, k)
		}
	}

	if t, ok := c.entries[key]; ok && now.Sub(t) <= c.ttl {
		return true
	}

	c.entries[key] = now
	return false
}
