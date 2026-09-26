package dns

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeClock is a manually advanced monotonic clock for cache tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Duration
}

func (f *fakeClock) Now() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now += d
}

func newTestCache() (*Cache, *fakeClock) {
	fc := &fakeClock{}
	c := NewCache()
	c.SetClock(fc.Now)
	return c, fc
}

func cacheTestQuestion(name string, qtype uint16) *Msg {
	m := new(Msg)
	m.SetQuestion(name, qtype)
	return m
}

func cacheAResponse(t *testing.T, name string, ttls ...uint32) *Msg {
	t.Helper()
	req := cacheTestQuestion(name, TypeA)
	resp := new(Msg)
	resp.SetReply(req)
	resp.Rcode = RcodeSuccess
	for i, ttl := range ttls {
		resp.Answer = append(resp.Answer, &A{
			Hdr: RR_Header{Name: name, Rrtype: TypeA, Class: ClassINET, Ttl: ttl},
			A:   []byte{192, 0, 2, byte(i + 1)},
		})
	}
	return resp
}

func cacheTTLs(m *Msg) []uint32 {
	var ttls []uint32
	for _, rr := range m.Answer {
		ttls = append(ttls, rr.Header().Ttl)
	}
	return ttls
}

// Two A records with TTL 10 and 20 share the group's common lifetime of
// 10: after 9 seconds both report TTL 1, after 10 seconds the whole
// group is gone.
func TestCacheGroupCommonLifetime(t *testing.T) {
	c, fc := newTestCache()
	resp := cacheAResponse(t, "example.com.", 10, 20)
	if !c.Insert(resp) {
		t.Fatal("insert failed")
	}

	fc.Advance(9 * time.Second)
	req := cacheTestQuestion("example.com.", TypeA)
	got := c.Get(req)
	if got == nil {
		t.Fatal("expected hit after 9s")
	}
	if len(got.Answer) != 2 {
		t.Fatalf("expected the whole RRset of 2 records, got %d", len(got.Answer))
	}
	for _, rr := range got.Answer {
		if rr.Header().Ttl != 1 {
			t.Fatalf("expected TTL 1 after 9s, got %d", rr.Header().Ttl)
		}
	}

	fc.Advance(time.Second)
	if got := c.Get(req); got != nil {
		t.Fatalf("expected the whole group to be gone after 10s, got %v", got.Answer)
	}
	if c.Len() != 0 {
		t.Fatalf("expected cache to be empty, got %d entries", c.Len())
	}
}

// A group must expire atomically: a partially expired RRset is never
// returned, while other groups in the same response survive.
func TestCacheGroupExpiresAtomically(t *testing.T) {
	c, fc := newTestCache()
	resp := cacheAResponse(t, "example.com.", 10, 20)
	resp.Ns = append(resp.Ns, &NS{
		Hdr: RR_Header{Name: "example.com.", Rrtype: TypeNS, Class: ClassINET, Ttl: 30},
		Ns:  "ns1.example.com.",
	})
	if !c.Insert(resp) {
		t.Fatal("insert failed")
	}

	fc.Advance(15 * time.Second)
	got := c.Get(cacheTestQuestion("example.com.", TypeA))
	if got != nil {
		t.Fatalf("expected miss once the answer group expired, got %v", got.Answer)
	}
	if c.Len() != 0 {
		t.Fatalf("expected entry to be removed, got %d entries", c.Len())
	}
}

// The DO and CD flags are part of the cache key.
func TestCacheDOCDIsolation(t *testing.T) {
	c, _ := newTestCache()

	plain := cacheAResponse(t, "example.com.", 60)
	if !c.Insert(plain) {
		t.Fatal("insert failed")
	}

	doResp := cacheAResponse(t, "example.com.", 60)
	doResp.SetEdns0(4096, true)
	if !c.Insert(doResp) {
		t.Fatal("insert with DO failed")
	}

	cdResp := cacheAResponse(t, "example.com.", 60)
	cdResp.CheckingDisabled = true
	if !c.Insert(cdResp) {
		t.Fatal("insert with CD failed")
	}

	if c.Len() != 3 {
		t.Fatalf("expected 3 isolated entries, got %d", c.Len())
	}

	if got := c.Get(cacheTestQuestion("example.com.", TypeA)); got == nil {
		t.Error("expected hit for plain query")
	}

	doReq := cacheTestQuestion("example.com.", TypeA)
	doReq.SetEdns0(4096, true)
	if got := c.Get(doReq); got == nil {
		t.Error("expected hit for DO query")
	}

	cdReq := cacheTestQuestion("example.com.", TypeA)
	cdReq.CheckingDisabled = true
	if got := c.Get(cdReq); got == nil {
		t.Error("expected hit for CD query")
	}

	// A DO+CD query matches neither the DO-only nor the CD-only entry.
	docdReq := cacheTestQuestion("example.com.", TypeA)
	docdReq.SetEdns0(4096, true)
	docdReq.CheckingDisabled = true
	if got := c.Get(docdReq); got != nil {
		t.Error("expected miss for DO+CD query")
	}
}

// Question names are matched case-insensitively.
func TestCacheCaseInsensitive(t *testing.T) {
	c, _ := newTestCache()
	if !c.Insert(cacheAResponse(t, "ExAmPlE.cOm.", 60)) {
		t.Fatal("insert failed")
	}
	if got := c.Get(cacheTestQuestion("eXaMpLe.CoM.", TypeA)); got == nil {
		t.Fatal("expected hit for differently-cased query")
	}
	if got := c.Get(cacheTestQuestion("example.com.", TypeA)); got == nil {
		t.Fatal("expected hit for lower-cased query")
	}
}

// The returned message carries the current request's Id.
func TestCacheRequestIDRewritten(t *testing.T) {
	c, _ := newTestCache()
	resp := cacheAResponse(t, "example.com.", 60)
	resp.Id = 1234
	if !c.Insert(resp) {
		t.Fatal("insert failed")
	}

	req := cacheTestQuestion("example.com.", TypeA)
	req.Id = 4321
	got := c.Get(req)
	if got == nil {
		t.Fatal("expected hit")
	}
	if got.Id != 4321 {
		t.Fatalf("expected Id 4321, got %d", got.Id)
	}
}

// The caller cannot pollute the cache, neither by mutating the inserted
// message nor by mutating a returned message.
func TestCacheIsolationFromCaller(t *testing.T) {
	c, _ := newTestCache()
	resp := cacheAResponse(t, "example.com.", 60)
	if !c.Insert(resp) {
		t.Fatal("insert failed")
	}

	// Mutating the inserted message must not change the cache.
	resp.Answer[0].Header().Ttl = 1
	resp.Answer = resp.Answer[:0]

	req := cacheTestQuestion("example.com.", TypeA)
	got := c.Get(req)
	if got == nil {
		t.Fatal("expected hit after mutating inserted message")
	}
	if len(got.Answer) != 1 || got.Answer[0].Header().Ttl != 60 {
		t.Fatalf("cache polluted by caller mutation: %v", got.Answer)
	}

	// Mutating the returned message must not change the cache either.
	got.Answer[0].Header().Ttl = 1
	got.Answer[0].(*A).A = []byte{10, 0, 0, 1}
	got.Answer = got.Answer[:0]

	again := c.Get(req)
	if again == nil {
		t.Fatal("expected hit after mutating returned message")
	}
	if len(again.Answer) != 1 {
		t.Fatalf("cache polluted by returned message mutation: %v", again.Answer)
	}
	if again.Answer[0].Header().Ttl != 60 {
		t.Fatalf("expected TTL 60, got %d", again.Answer[0].Header().Ttl)
	}
	if ip := again.Answer[0].(*A).A.String(); ip != "192.0.2.1" {
		t.Fatalf("expected 192.0.2.1, got %s", ip)
	}
}

// Records with TTL 0 are never cached.
func TestCacheTTLZeroNotCached(t *testing.T) {
	c, _ := newTestCache()
	if c.Insert(cacheAResponse(t, "example.com.", 0)) {
		t.Fatal("expected TTL 0 response to be rejected")
	}
	if got := c.Get(cacheTestQuestion("example.com.", TypeA)); got != nil {
		t.Fatal("expected miss for TTL 0 response")
	}

	// A zero TTL inside a group poisons the whole group: it is dropped
	// entirely instead of being stored partially.
	resp := cacheAResponse(t, "example.com.", 0, 60)
	if c.Insert(resp) {
		t.Fatal("expected response with a zero-TTL group to be rejected")
	}
	if got := c.Get(cacheTestQuestion("example.com.", TypeA)); got != nil {
		t.Fatal("expected miss when the answer group contains a TTL 0 record")
	}
}

// Truncated and negative responses are never cached.
func TestCacheRejectsTruncatedAndNegative(t *testing.T) {
	c, _ := newTestCache()

	tc := cacheAResponse(t, "example.com.", 60)
	tc.Truncated = true
	if c.Insert(tc) {
		t.Fatal("expected truncated response to be rejected")
	}

	nx := cacheAResponse(t, "nx.example.com.", 60)
	nx.Rcode = RcodeNameError
	nx.Answer = nil
	if c.Insert(nx) {
		t.Fatal("expected NXDOMAIN response to be rejected")
	}

	nodata := cacheAResponse(t, "nodata.example.com.", 60)
	nodata.Answer = nil
	if c.Insert(nodata) {
		t.Fatal("expected NODATA response to be rejected")
	}

	multi := cacheAResponse(t, "multi.example.com.", 60)
	multi.Question = append(multi.Question, Question{Name: "other.example.com.", Qtype: TypeA, Qclass: ClassINET})
	if c.Insert(multi) {
		t.Fatal("expected multi-question response to be rejected")
	}

	if c.Len() != 0 {
		t.Fatalf("expected empty cache, got %d entries", c.Len())
	}
}

// OPT records are never cached as regular records.
func TestCacheOPTNotStored(t *testing.T) {
	c, _ := newTestCache()
	resp := cacheAResponse(t, "example.com.", 60)
	resp.SetEdns0(4096, false)
	if !c.Insert(resp) {
		t.Fatal("insert failed")
	}

	req := cacheTestQuestion("example.com.", TypeA)
	req.SetEdns0(4096, false)
	got := c.Get(req)
	if got == nil {
		t.Fatal("expected hit")
	}
	for _, rr := range got.Extra {
		if rr.Header().Rrtype == TypeOPT {
			t.Fatal("OPT record leaked into cached response")
		}
	}
}

// A failed lookup must not change the existing cache.
func TestCacheFailedLookupKeepsCache(t *testing.T) {
	c, fc := newTestCache()
	if !c.Insert(cacheAResponse(t, "example.com.", 60)) {
		t.Fatal("insert failed")
	}

	// Misses for other names, types and flag combinations.
	for _, req := range []*Msg{
		cacheTestQuestion("other.example.com.", TypeA),
		cacheTestQuestion("example.com.", TypeAAAA),
		func() *Msg { m := cacheTestQuestion("example.com.", TypeA); m.CheckingDisabled = true; return m }(),
	} {
		if got := c.Get(req); got != nil {
			t.Fatalf("expected miss for %v", req.Question)
		}
	}

	fc.Advance(10 * time.Second)
	got := c.Get(cacheTestQuestion("example.com.", TypeA))
	if got == nil {
		t.Fatal("existing entry vanished after failed lookups")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl != 50 {
		t.Fatalf("expected TTL 50, got %d", ttl)
	}
}

// A backwards-running clock must never make a TTL grow.
func TestCacheClockBackwards(t *testing.T) {
	c, fc := newTestCache()
	if !c.Insert(cacheAResponse(t, "example.com.", 60)) {
		t.Fatal("insert failed")
	}
	fc.Advance(10 * time.Second)
	fc.Advance(-20 * time.Second) // wall-clock style jump backwards
	got := c.Get(cacheTestQuestion("example.com.", TypeA))
	if got == nil {
		t.Fatal("expected hit")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl > 60 {
		t.Fatalf("TTL grew to %d", ttl)
	}
}

// The same response is served to concurrent readers independently.
func TestCacheConcurrent(t *testing.T) {
	c, _ := newTestCache()
	if !c.Insert(cacheAResponse(t, "example.com.", 60)) {
		t.Fatal("insert failed")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id uint16) {
			defer wg.Done()
			req := cacheTestQuestion("example.com.", TypeA)
			req.Id = id
			for j := 0; j < 100; j++ {
				got := c.Get(req)
				if got == nil || got.Id != id {
					t.Error("bad concurrent get")
					return
				}
				got.Answer[0].Header().Ttl = 0
			}
		}(uint16(i))
	}
	wg.Wait()
}

// ExampleCache demonstrates the cache with an injected fake clock.
func ExampleCache() {
	var now time.Duration
	c := NewCache()
	c.SetClock(func() time.Duration { return now })

	req := new(Msg)
	req.SetQuestion("example.com.", TypeA)

	resp := new(Msg)
	resp.SetReply(req)
	resp.Answer = []RR{&A{
		Hdr: RR_Header{Name: "example.com.", Rrtype: TypeA, Class: ClassINET, Ttl: 10},
		A:   []byte{192, 0, 2, 1},
	}}
	c.Insert(resp)

	now += 9 * time.Second
	if m := c.Get(req); m != nil {
		fmt.Println("after 9s:", m.Answer[0].Header().Ttl)
	}
	now += time.Second
	if m := c.Get(req); m == nil {
		fmt.Println("after 10s: expired")
	}
	// Output:
	// after 9s: 1
	// after 10s: expired
}
