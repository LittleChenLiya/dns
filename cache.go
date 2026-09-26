package dns

import (
	"strings"
	"sync"
	"time"
)

// Clock returns the current time as a monotonic duration. It is used by
// Cache to age cached responses. The duration must be monotonic: wall
// clock adjustments must never make it run backwards, as that would
// allow cached TTLs to grow.
type Clock func() time.Duration

// Cache is a pure in-memory cache for DNS responses. It stores received
// messages and serves them with TTLs decremented by the elapsed time.
// It never performs any network queries itself.
//
// Responses are keyed by the normalized question (lower-cased, fully
// qualified name, qtype and qclass) plus the DO and CD flags, as those
// flags influence the response a server returns.
//
// Resource records are handled in RRsets: records sharing the same
// owner name, type and class form a group whose common lifetime is the
// shortest TTL in the group. When a group expires it is removed in its
// entirety, so a partially expired RRset is never served. OPT records
// are not treated as regular cache records and are never stored.
//
// Only successful (NOERROR), non-truncated responses to a single
// question are cached. Negative responses are not cached. Records with
// a TTL of zero are dropped on insertion.
//
// The zero value is not usable; use NewCache or NewCacheWithClock.
// Cache is safe for concurrent use.
type Cache struct {
	mu      sync.Mutex
	now     Clock
	entries map[cacheKey]*cacheEntry
}

type cacheKey struct {
	name   string
	qtype  uint16
	qclass uint16
	do     bool
	cd     bool
}

type cacheEntry struct {
	inserted time.Duration
	msg      *Msg
}

// NewCache returns a Cache using the process monotonic clock, so wall
// clock adjustments cannot extend the lifetime of cached entries.
func NewCache() *Cache {
	start := time.Now()
	return NewCacheWithClock(func() time.Duration { return time.Since(start) })
}

// NewCacheWithClock returns a Cache using clock as its time source. A
// nil clock falls back to the process monotonic clock. Tests can inject
// a fake clock to control the passage of time.
func NewCacheWithClock(clock Clock) *Cache {
	if clock == nil {
		return NewCache()
	}
	return &Cache{now: clock, entries: make(map[cacheKey]*cacheEntry)}
}

func cacheKeyFor(m *Msg) cacheKey {
	q := m.Question[0]
	do := false
	if opt := m.IsEdns0(); opt != nil {
		do = opt.Do()
	}
	return cacheKey{
		name:   strings.ToLower(Fqdn(q.Name)),
		qtype:  q.Qtype,
		qclass: q.Qclass,
		do:     do,
		cd:     m.CheckingDisabled,
	}
}

// Insert adds resp to the cache. The message is deep-copied, so later
// modifications of resp by the caller do not affect the cache.
//
// Responses that are not successful, are truncated, or do not hold
// exactly one question are silently rejected and leave the cache
// untouched.
func (c *Cache) Insert(resp *Msg) {
	if resp == nil || !resp.Response || resp.Rcode != RcodeSuccess ||
		resp.Truncated || len(resp.Question) != 1 {
		return
	}
	m := resp.Copy()
	m.Id = 0
	m.Answer = insertFilter(m.Answer)
	m.Ns = insertFilter(m.Ns)
	m.Extra = insertFilter(m.Extra)
	if len(m.Answer) == 0 && len(m.Ns) == 0 && len(m.Extra) == 0 {
		return
	}
	key := cacheKeyFor(resp)
	c.mu.Lock()
	c.entries[key] = &cacheEntry{inserted: c.now(), msg: m}
	c.mu.Unlock()
}

// Get returns a cached response for req, or nil when nothing usable is
// stored. The returned message is an independent copy with its Id set
// to req's Id and all TTLs decremented by the time the entry has spent
// in the cache; modifying it does not affect the cache. RRsets whose
// common lifetime has elapsed are removed from the cache as a whole.
//
// A failed lookup never changes the state of the cache.
func (c *Cache) Get(req *Msg) *Msg {
	if req == nil || len(req.Question) != 1 {
		return nil
	}
	key := cacheKeyFor(req)
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil
	}
	elapsed := now - e.inserted
	if elapsed < 0 {
		elapsed = 0
	}
	secs := uint32(elapsed / time.Second)

	e.msg.Answer = dropExpired(e.msg.Answer, secs)
	e.msg.Ns = dropExpired(e.msg.Ns, secs)
	e.msg.Extra = dropExpired(e.msg.Extra, secs)
	if len(e.msg.Answer) == 0 && len(e.msg.Ns) == 0 && len(e.msg.Extra) == 0 {
		delete(c.entries, key)
		return nil
	}

	m := e.msg.Copy()
	age(m.Answer, secs)
	age(m.Ns, secs)
	age(m.Extra, secs)
	m.Id = req.Id
	return m
}

// rrsetKey identifies an RRset: owner name (canonicalized), type and class.
type rrsetKey struct {
	name  string
	typ   uint16
	class uint16
}

func rrsetKeyOf(rr RR) rrsetKey {
	h := rr.Header()
	return rrsetKey{strings.ToLower(h.Name), h.Rrtype, h.Class}
}

// minTTLs returns the shortest TTL per RRset in rrs. OPT records are
// skipped; they are not regular cache records.
func minTTLs(rrs []RR) map[rrsetKey]uint32 {
	ttl := make(map[rrsetKey]uint32)
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype == TypeOPT {
			continue
		}
		k := rrsetKeyOf(rr)
		if v, ok := ttl[k]; !ok || h.Ttl < v {
			ttl[k] = h.Ttl
		}
	}
	return ttl
}

// insertFilter drops OPT records and RRsets whose shortest TTL is zero,
// as those expire the moment they are cached. Surviving records have
// their TTL clamped to the shortest TTL of their RRset, which is the
// common lifetime of the group.
func insertFilter(rrs []RR) []RR {
	ttl := minTTLs(rrs)
	out := make([]RR, 0, len(rrs))
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype == TypeOPT {
			continue
		}
		min := ttl[rrsetKeyOf(rr)]
		if min == 0 {
			continue
		}
		h.Ttl = min
		out = append(out, rr)
	}
	return out
}

// dropExpired removes every RRset whose common lifetime (the shortest
// TTL in the set) has fully elapsed after secs seconds.
func dropExpired(rrs []RR, secs uint32) []RR {
	ttl := minTTLs(rrs)
	out := make([]RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr.Header().Rrtype == TypeOPT {
			out = append(out, rr)
			continue
		}
		if ttl[rrsetKeyOf(rr)] <= secs {
			continue
		}
		out = append(out, rr)
	}
	return out
}

// age decrements the TTL of every record by secs. It must only be
// called on records that survived dropExpired for the same secs, so the
// subtraction can never underflow.
func age(rrs []RR, secs uint32) {
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype == TypeOPT {
			continue
		}
		h.Ttl -= secs
	}
}
