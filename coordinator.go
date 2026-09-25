package dns

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// A QueryCoordinator coordinates DNS queries against a fixed set of upstream
// exchangers. It provides two pieces of functionality on top of an ordinary
// client exchange:
//
//   - Singleflight: concurrent queries for the same standardized Qname,
//     Qtype, Qclass and upstream share a single in-flight Exchange. Each
//     caller keeps its own [context.Context]; one caller being cancelled does
//     not disturb the others. The underlying query is only cancelled once the
//     last waiter has left.
//   - Caching: successful responses are positively cached for the smallest TTL
//     of the RRsets that make up the Answer chain that proves the answer to
//     the question. Name errors are negatively cached, using the smaller of
//     the SOA TTL and the SOA MINIMUM field; a name error without a SOA in the
//     authority section is not cached. Failures, truncated responses and
//     cancellations are never cached.
//
// Every message handed back to a caller is an independent deep copy, and the
// message Id is restored to the Id of that caller's request. Mutating a
// returned message therefore never affects another caller or the cache.
//
// The zero value is not ready for use; create one with
// [NewQueryCoordinator].
type QueryCoordinator struct {
	// Exchange performs the upstream query. If nil, [DefaultExchanger] is used,
	// which exchanges over the network using a default [Client]. It may be
	// replaced to inject a custom transport or, in tests, a fake upstream.
	Exchange ExchangerFunc

	// Now returns the current time. If nil, [time.Now] is used. It is exported
	// so callers can inject a controllable clock, which is mainly useful for
	// testing cache expiration.
	Now func() time.Time

	mu      sync.Mutex
	flights map[string]*coordinatorFlight
	cache   map[string]*cacheEntry
	ops     int
}

// An ExchangerFunc performs a single DNS exchange against upstream. The
// address argument is the opaque upstream identifier passed to
// [QueryCoordinator.Query]; it is usually a "host:port" string but may carry
// any configuration that should distinguish two upstreams, since it is part of
// the coalescing key.
//
// Implementations should honour ctx: it is cancelled when the last waiter for
// a shared query leaves. A returned message must not be reused by the
// implementation after it is returned: the coordinator takes ownership and
// shares it (by deep copies) with every waiter.
type ExchangerFunc func(ctx context.Context, m *Msg, address string) (*Msg, error)

// DefaultExchanger exchanges m with address using the default [Client], which
// uses UDP. It is the default [QueryCoordinator.Exchange] implementation.
func DefaultExchanger(ctx context.Context, m *Msg, address string) (*Msg, error) {
	client := &Client{}
	r, _, err := client.ExchangeContext(ctx, m, address)
	return r, err
}

// NewQueryCoordinator returns a QueryCoordinator that uses
// [DefaultExchanger] and the wall clock.
func NewQueryCoordinator() *QueryCoordinator {
	return &QueryCoordinator{Exchange: DefaultExchanger}
}

// A cacheEntry is a stored response together with its absolute expiration
// time.
type cacheEntry struct {
	msg       *Msg
	expiresAt time.Time
}

// A coordinatorFlight represents a single upstream exchange shared by every
// waiter that asked for the same key while it was in flight.
type coordinatorFlight struct {
	// ctx drives the shared Exchange. It is derived from the background
	// context, not from any individual caller, and is cancelled only when the
	// last waiter leaves.
	ctx    context.Context
	cancel context.CancelFunc

	done chan struct{}

	// waiters is the number of callers currently attached to the flight,
	// including the leader that started it.
	waiters int

	// aborted is set once the last waiter has left; the flight result must
	// then be discarded.
	aborted bool

	msg *Msg
	err error
}

// Query answers m against address, serving the answer from the cache or by
// joining a single in-flight exchange when possible. The returned message is a
// deep copy with its Id set to m.Id; it is safe for the caller to mutate.
//
// A nil or context-cancelled waiter receives its own context error without
// affecting other waiters on the same exchange. The message must carry at
// least one question.
func (c *QueryCoordinator) Query(ctx context.Context, m *Msg, address string) (*Msg, error) {
	if c == nil {
		return nil, errors.New("dns: QueryCoordinator: nil coordinator")
	}
	if m == nil {
		return nil, errors.New("dns: QueryCoordinator: nil message")
	}
	if len(m.Question) == 0 {
		return nil, errors.New("dns: QueryCoordinator: message has no question")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	key := cacheKey(m.Question[0], address)
	requestID := m.Id

	c.mu.Lock()
	if reply, ok := c.cachedLocked(key); ok {
		reply.Id = requestID
		c.mu.Unlock()
		return reply, nil
	}

	f := c.flights[key]
	if f == nil {
		if c.flights == nil {
			c.flights = make(map[string]*coordinatorFlight)
		}
		fctx, cancel := context.WithCancel(context.Background())
		f = &coordinatorFlight{
			ctx:     fctx,
			cancel:  cancel,
			done:    make(chan struct{}),
			waiters: 1,
		}
		c.flights[key] = f
		// The leader owns the template; copy it so the caller can mutate its
		// message while the exchange is in progress.
		template := m.Copy()
		template.Id = Id()
		c.mu.Unlock()
		go c.runExchange(key, f, template, address)
	} else {
		f.waiters++
		c.mu.Unlock()
	}

	select {
	case <-ctx.Done():
		c.leave(key, f)
		return nil, ctx.Err()
	case <-f.done:
		if f.err != nil {
			return nil, f.err
		}
		reply := f.msg.Copy()
		reply.Id = requestID
		return reply, nil
	}
}

// runExchange performs the shared upstream query, records its outcome and
// wakes every waiter. It is run by the flight leader in its own goroutine.
func (c *QueryCoordinator) runExchange(key string, f *coordinatorFlight, template *Msg, address string) {
	reply, err := c.exchange()(f.ctx, template, address)

	c.mu.Lock()
	if f.aborted {
		// Every waiter has left while the query was running; nothing is left
		// to deliver or cache. Closing done is only defensive.
		c.mu.Unlock()
		close(f.done)
		return
	}
	delete(c.flights, key)

	switch {
	case err != nil:
		// Errors, including context cancellation, are never cached.
		f.err = err
	case reply == nil:
		f.err = errors.New("dns: QueryCoordinator: exchanger returned a nil message")
	case reply.Truncated:
		// Truncated responses are handed back but never cached; the caller is
		// expected to retry over TCP.
		f.msg = reply
	default:
		f.msg = reply
		if ttl := responseTTL(reply); ttl > 0 {
			c.putCacheLocked(key, reply, ttl)
		}
	}
	c.mu.Unlock()
	close(f.done)
}

// leave detaches a waiter from a flight. When the last waiter leaves the
// shared exchange is cancelled and the flight is removed so a later query
// starts fresh.
func (c *QueryCoordinator) leave(key string, f *coordinatorFlight) {
	c.mu.Lock()
	f.waiters--
	if f.waiters == 0 && !f.aborted {
		f.aborted = true
		delete(c.flights, key)
		f.cancel()
	}
	c.mu.Unlock()
}

// cachedLocked returns a fresh deep copy of a live cache entry for key and
// reports whether one was found. Expired entries are evicted.
func (c *QueryCoordinator) cachedLocked(key string) (*Msg, bool) {
	e := c.cache[key]
	if e == nil {
		return nil, false
	}
	if !e.expiresAt.After(c.now()) {
		delete(c.cache, key)
		return nil, false
	}
	return e.msg.Copy(), true
}

// putCacheLocked stores msg for ttl and opportunistically evicts expired
// entries so the cache cannot grow without bound for one-off names.
func (c *QueryCoordinator) putCacheLocked(key string, msg *Msg, ttl time.Duration) {
	if c.cache == nil {
		c.cache = make(map[string]*cacheEntry)
	}
	c.cache[key] = &cacheEntry{msg: msg, expiresAt: c.now().Add(ttl)}
	c.ops++
	if c.ops%64 == 0 {
		now := c.now()
		for k, e := range c.cache {
			if !e.expiresAt.After(now) {
				delete(c.cache, k)
			}
		}
	}
}

func (c *QueryCoordinator) exchange() ExchangerFunc {
	if c.Exchange != nil {
		return c.Exchange
	}
	return DefaultExchanger
}

func (c *QueryCoordinator) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// cacheKey builds the coalescing and cache key for a question. Qname matching
// is case-insensitive and independent of a trailing dot, following the DNS
// canonical name rules.
func cacheKey(q Question, address string) string {
	var b strings.Builder
	b.WriteString(CanonicalName(q.Name))
	b.WriteByte('/')
	b.WriteString(Type(q.Qtype).String())
	b.WriteByte('/')
	b.WriteString(Class(q.Qclass).String())
	b.WriteByte('@')
	b.WriteString(address)
	return b.String()
}

// responseTTL decides how long a non-truncated, successful exchange result may
// be cached. A zero duration means "do not cache".
func responseTTL(m *Msg) time.Duration {
	switch m.Rcode {
	case RcodeSuccess:
		if len(m.Question) == 0 {
			return 0
		}
		return answerTTL(m, m.Question[0])
	case RcodeNameError:
		return negativeTTL(m)
	default:
		// SERVFAIL and friends, as well as unexpected rcodes, are not cached.
		return 0
	}
}

// answerTTL returns the smallest TTL of the RRsets forming the Answer chain
// that proves the answer to q. Only the Answer section participates: unrelated
// short-TTL records in the authority or additional sections never shorten the
// lifetime of the answer. If the Answer section does not prove the answer
// (for example an empty answer, or a CNAME chain that does not terminate in
// the requested type), nothing is cached.
func answerTTL(m *Msg, q Question) time.Duration {
	const noTTL = ^uint32(0)

	name := CanonicalName(q.Name)
	minTTL := uint32(noTTL)
	complete := false

	if q.Qtype == TypeANY {
		for _, rr := range m.Answer {
			h := rr.Header()
			if CanonicalName(h.Name) == name {
				complete = true
				if h.Ttl < minTTL {
					minTTL = h.Ttl
				}
			}
		}
		if !complete {
			return 0
		}
		return time.Duration(minTTL) * time.Second
	}

	// Walk the CNAME chain starting at q.Name. Each hop must be present in the
	// Answer section; the walk has to terminate with an RRset of q.Qtype.
	seen := make(map[string]bool)
	for {
		if seen[name] {
			return 0
		}
		seen[name] = true

		matched := false
		var cnameTarget string
		var cnameTTL uint32
		for _, rr := range m.Answer {
			h := rr.Header()
			if CanonicalName(h.Name) != name {
				continue
			}
			switch {
			case h.Rrtype == q.Qtype:
				matched = true
				if h.Ttl < minTTL {
					minTTL = h.Ttl
				}
			case q.Qtype != TypeCNAME && h.Rrtype == TypeCNAME:
				if cn, ok := rr.(*CNAME); ok {
					cnameTarget = CanonicalName(cn.Target)
					cnameTTL = h.Ttl
				}
			}
		}

		if matched {
			complete = true
			break
		}
		if cnameTarget == "" {
			break
		}
		// The CNAME only counts towards the TTL once the chain completes.
		if cnameTTL < minTTL {
			minTTL = cnameTTL
		}
		name = cnameTarget
	}

	if !complete {
		return 0
	}
	return time.Duration(minTTL) * time.Second
}

// negativeTTL returns the negative caching TTL from the SOA in the authority
// section: the smaller of the SOA record TTL and its MINIMUM field, per
// RFC 2308 sections 5 and 4. It reports false when no SOA is present, in which
// case the response must not be negatively cached.
func negativeTTL(m *Msg) time.Duration {
	for _, rr := range m.Ns {
		soa, ok := rr.(*SOA)
		if !ok {
			continue
		}
		ttl := soa.Hdr.Ttl
		if soa.Minttl < ttl {
			ttl = soa.Minttl
		}
		return time.Duration(ttl) * time.Second
	}
	return 0
}
