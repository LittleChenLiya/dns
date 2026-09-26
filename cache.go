package dns

import (
	"strings"
	"sync"
	"time"
)

// Cache is a pure in-memory cache for DNS response messages. It never
// performs any network queries itself; callers Insert responses they have
// already received and Get them back later with the TTLs decremented by
// the elapsed time.
//
// Records are grouped into RRsets by (name, type, class). The shortest
// TTL inside a group becomes the common lifetime of the whole group, and
// when a group expires it is removed as a whole, so a partially expired
// RRset is never returned. OPT records are meta records and are never
// stored as regular cached records.
//
// The cache key contains the normalized (lower-cased) question plus the
// DO and CD flags, since both influence the response a server sends.
//
// Only successful (NOERROR), non-truncated, single-question responses
// that carry at least one cacheable answer record are stored. Negative
// responses (NXDOMAIN, NODATA, errors) are not cached.
//
// The insertion time is tracked with a monotonic clock that can be
// injected with SetClock (mainly for tests), so wall-clock adjustments
// can never make a TTL grow.
//
// The zero value is not ready for use; create a Cache with NewCache.
// A Cache is safe for concurrent use.
type Cache struct {
	mu    sync.Mutex
	now   func() time.Duration
	items map[cacheKey]*cacheEntry
}

// cacheKey identifies a cached response. The question name is stored
// lower-cased so lookups are case-insensitive.
type cacheKey struct {
	name  string
	qtype uint16
	class uint16
	do    bool
	cd    bool
}

// rrsetKey identifies a group of RRs that share name, type and class.
type rrsetKey struct {
	name  string
	typ   uint16
	class uint16
}

// cacheEntry is a stored response together with the monotonic timestamp
// of its insertion and the common (minimum) TTL of each RRset group.
type cacheEntry struct {
	msg      *Msg
	inserted time.Duration
	groups   map[rrsetKey]uint32
}

// NewCache returns an empty Cache that tracks elapsed time with the
// process monotonic clock, immune to wall-clock adjustments.
func NewCache() *Cache {
	start := time.Now()
	return &Cache{
		now:   func() time.Duration { return time.Since(start) },
		items: make(map[cacheKey]*cacheEntry),
	}
}

// SetClock injects a custom monotonic clock. The returned duration is
// expected to never decrease; if it does, elapsed time is clamped to
// zero so TTLs can never grow. It is intended for tests and
// demonstrations that use a fake clock.
func (c *Cache) SetClock(now func() time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// cacheKeyFor builds the cache key for a message's question and flags.
func cacheKeyFor(m *Msg) cacheKey {
	q := m.Question[0]
	key := cacheKey{
		name:  strings.ToLower(q.Name),
		qtype: q.Qtype,
		class: q.Qclass,
		cd:    m.CheckingDisabled,
	}
	if opt := m.IsEdns0(); opt != nil {
		key.do = opt.Do()
	}
	return key
}

// rrsetKeyFor returns the group key of an RR, with a normalized name.
func rrsetKeyFor(rr RR) rrsetKey {
	h := rr.Header()
	return rrsetKey{name: strings.ToLower(h.Name), typ: h.Rrtype, class: h.Class}
}

// Insert stores resp in the cache and reports whether it was stored.
//
// resp is only stored when it is a successful (NOERROR), non-truncated
// response to a single question that contains at least one answer record
// with a non-zero TTL. Negative responses, truncated responses and
// records with a zero TTL are never cached. OPT records are stripped
// before storing. The message is deep-copied, so later changes to resp
// by the caller do not affect the cache. Inserting a response for a key
// that is already present replaces the previous entry.
func (c *Cache) Insert(resp *Msg) bool {
	if resp == nil || resp.Truncated || resp.Rcode != RcodeSuccess || len(resp.Question) != 1 {
		return false
	}

	stored := resp.Copy()

	// OPT records are meta records, never cached as regular records.
	extra := stored.Extra[:0]
	for _, rr := range stored.Extra {
		if rr.Header().Rrtype != TypeOPT {
			extra = append(extra, rr)
		}
	}
	stored.Extra = extra

	// Group the records and compute the common (minimum) TTL per group.
	groups := make(map[rrsetKey]uint32)
	for _, section := range [][]RR{stored.Answer, stored.Ns, stored.Extra} {
		for _, rr := range section {
			k := rrsetKeyFor(rr)
			if ttl, ok := groups[k]; !ok || rr.Header().Ttl < ttl {
				groups[k] = rr.Header().Ttl
			}
		}
	}

	// Groups whose common TTL is zero are not cacheable at all; drop the
	// whole group so a partial RRset is never stored or returned.
	zero := make(map[rrsetKey]bool)
	for k, ttl := range groups {
		if ttl == 0 {
			zero[k] = true
			delete(groups, k)
		}
	}
	if len(zero) > 0 {
		filter := func(section []RR) []RR {
			kept := section[:0]
			for _, rr := range section {
				if !zero[rrsetKeyFor(rr)] {
					kept = append(kept, rr)
				}
			}
			return kept
		}
		stored.Answer = filter(stored.Answer)
		stored.Ns = filter(stored.Ns)
		stored.Extra = filter(stored.Extra)
	}

	// No negative caching: without answer records there is nothing to
	// serve from the cache.
	if len(stored.Answer) == 0 {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[cacheKeyFor(resp)] = &cacheEntry{
		msg:      stored,
		inserted: c.now(),
		groups:   groups,
	}
	return true
}

// Get returns a cached response for req, or nil when nothing usable is
// stored. The returned message is an independent copy with its Id set to
// req's Id and every TTL set to the remaining lifetime of its RRset
// group (the group's common TTL minus the elapsed time). Groups whose
// lifetime has fully elapsed are removed from the cache as a whole and
// never returned partially. A failed lookup does not modify the cache.
func (c *Cache) Get(req *Msg) *Msg {
	if req == nil || len(req.Question) == 0 {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKeyFor(req)
	e, ok := c.items[key]
	if !ok {
		return nil
	}

	elapsed := c.now() - e.inserted
	if elapsed < 0 {
		// A clock must never make a TTL grow.
		elapsed = 0
	}
	elapsedSec := uint32(elapsed / time.Second)

	// Expire whole groups whose common lifetime has elapsed.
	expired := make(map[rrsetKey]bool)
	for k, ttl := range e.groups {
		if elapsedSec >= ttl {
			expired[k] = true
			delete(e.groups, k)
		}
	}
	if len(expired) > 0 {
		filter := func(section []RR) []RR {
			kept := section[:0]
			for _, rr := range section {
				if !expired[rrsetKeyFor(rr)] {
					kept = append(kept, rr)
				}
			}
			return kept
		}
		e.msg.Answer = filter(e.msg.Answer)
		e.msg.Ns = filter(e.msg.Ns)
		e.msg.Extra = filter(e.msg.Extra)
	}

	if len(e.msg.Answer) == 0 {
		delete(c.items, key)
		return nil
	}

	reply := e.msg.Copy()
	reply.Id = req.Id
	for _, section := range [][]RR{reply.Answer, reply.Ns, reply.Extra} {
		for _, rr := range section {
			// Every record in a group shares the group's common
			// remaining lifetime.
			rr.Header().Ttl = e.groups[rrsetKeyFor(rr)] - elapsedSec
		}
	}
	return reply
}

// Len returns the number of cached responses.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}
