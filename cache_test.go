package dns

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeClock is a manually advanced Clock for tests and demos.
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

func cacheTestResponse(name string, ttls ...uint32) *Msg {
	m := new(Msg)
	m.SetQuestion(name, TypeA)
	m.Response = true
	m.Rcode = RcodeSuccess
	for i, ttl := range ttls {
		m.Answer = append(m.Answer, &A{
			Hdr: RR_Header{Name: name, Rrtype: TypeA, Class: ClassINET, Ttl: ttl},
			A:   net.ParseIP(fmt.Sprintf("192.0.2.%d", i+1)),
		})
	}
	return m
}

func TestCacheRRsetAgesAndExpiresTogether(t *testing.T) {
	clock := &fakeClock{}
	c := NewCacheWithClock(clock.Now)

	c.Insert(cacheTestResponse("example.com.", 10, 20))

	clock.Advance(9 * time.Second)
	req := new(Msg)
	req.SetQuestion("example.com.", TypeA)
	m := c.Get(req)
	if m == nil {
		t.Fatal("expected cache hit after 9s")
	}
	if len(m.Answer) != 2 {
		t.Fatalf("expected whole RRset of 2 records, got %d", len(m.Answer))
	}
	for _, rr := range m.Answer {
		if ttl := rr.Header().Ttl; ttl != 1 {
			t.Errorf("expected TTL 1 after 9s, got %d", ttl)
		}
	}

	clock.Advance(time.Second) // 10s total: the group is gone as a whole
	if m := c.Get(req); m != nil {
		t.Fatalf("expected expired RRset to be removed, got %v", m.Answer)
	}
}

func TestCacheDOCDIsolation(t *testing.T) {
	clock := &fakeClock{}
	c := NewCacheWithClock(clock.Now)

	plain := new(Msg)
	plain.SetQuestion("example.com.", TypeA)

	do := new(Msg)
	do.SetQuestion("example.com.", TypeA)
	do.SetEdns0(4096, true)

	cd := new(Msg)
	cd.SetQuestion("example.com.", TypeA)
	cd.CheckingDisabled = true

	resp := cacheTestResponse("example.com.", 60)
	resp.SetEdns0(4096, true)
	c.Insert(resp)

	if m := c.Get(plain); m != nil {
		t.Error("DO entry must not be served for a non-DO query")
	}
	if m := c.Get(cd); m != nil {
		t.Error("DO entry must not be served for a CD-only query")
	}
	if m := c.Get(do); m == nil {
		t.Error("expected hit for the DO query")
	}

	respCD := cacheTestResponse("example.com.", 60)
	respCD.CheckingDisabled = true
	c.Insert(respCD)
	if m := c.Get(plain); m != nil {
		t.Error("CD entry must not be served for a non-CD query")
	}
	if m := c.Get(cd); m == nil {
		t.Error("expected hit for the CD query")
	}
}

func TestCacheNameCaseInsensitive(t *testing.T) {
	clock := &fakeClock{}
	c := NewCacheWithClock(clock.Now)

	c.Insert(cacheTestResponse("ExAmPlE.cOm.", 60))

	req := new(Msg)
	req.SetQuestion("example.COM.", TypeA)
	if m := c.Get(req); m == nil {
		t.Fatal("expected hit regardless of owner name case")
	}
}

func TestCacheRequestIDReplaced(t *testing.T) {
	clock := &fakeClock{}
	c := NewCacheWithClock(clock.Now)

	resp := cacheTestResponse("example.com.", 60)
	resp.Id = 1111
	c.Insert(resp)

	req := new(Msg)
	req.SetQuestion("example.com.", TypeA)
	req.Id = 4242
	m := c.Get(req)
	if m == nil {
		t.Fatal("expected hit")
	}
	if m.Id != 4242 {
		t.Errorf("expected response Id 4242, got %d", m.Id)
	}
}

func TestCacheReturnedMsgIsIndependent(t *testing.T) {
	clock := &fakeClock{}
	c := NewCacheWithClock(clock.Now)

	c.Insert(cacheTestResponse("example.com.", 60))

	req := new(Msg)
	req.SetQuestion("example.com.", TypeA)
	m := c.Get(req)
	if m == nil {
		t.Fatal("expected hit")
	}
	// Mutating the returned message must not pollute the cache.
	m.Answer[0].(*A).A = net.ParseIP("203.0.113.1")
	m.Answer[0].Header().Ttl = 9999
	m.Rcode = RcodeServerFailure

	m2 := c.Get(req)
	if m2 == nil {
		t.Fatal("expected second hit")
	}
	if got := m2.Answer[0].(*A).A.String(); got != "192.0.2.1" {
		t.Errorf("cached record polluted, A = %s", got)
	}
	if ttl := m2.Answer[0].Header().Ttl; ttl != 60 {
		t.Errorf("cached TTL polluted, got %d", ttl)
	}
	if m2.Rcode != RcodeSuccess {
		t.Errorf("cached rcode polluted, got %s", RcodeToString[m2.Rcode])
	}
}

func TestCacheInsertDoesNotLeakCallerChanges(t *testing.T) {
	clock := &fakeClock{}
	c := NewCacheWithClock(clock.Now)

	resp := cacheTestResponse("example.com.", 60)
	c.Insert(resp)
	resp.Answer[0].(*A).A = net.ParseIP("203.0.113.1")

	req := new(Msg)
	req.SetQuestion("example.com.", TypeA)
	m := c.Get(req)
	if m == nil {
		t.Fatal("expected hit")
	}
	if got := m.Answer[0].(*A).A.String(); got != "192.0.2.1" {
		t.Errorf("caller mutation leaked into cache, A = %s", got)
	}
}

func TestCacheTTLZeroNotCached(t *testing.T) {
	clock := &fakeClock{}
	c := NewCacheWithClock(clock.Now)

	c.Insert(cacheTestResponse("zero.example.com.", 0))

	req := new(Msg)
	req.SetQuestion("zero.example.com.", TypeA)
	if m := c.Get(req); m != nil {
		t.Error("TTL 0 response must not be cached")
	}

	// A TTL 0 record inside a mixed RRset expires the whole group at once.
	c.Insert(cacheTestResponse("mixed.example.com.", 0, 60))
	req2 := new(Msg)
	req2.SetQuestion("mixed.example.com.", TypeA)
	if m := c.Get(req2); m != nil {
		t.Error("RRset containing a TTL 0 record must not be cached")
	}
}

func TestCacheRejectsUncacheableResponses(t *testing.T) {
	clock := &fakeClock{}
	c := NewCacheWithClock(clock.Now)

	req := new(Msg)
	req.SetQuestion("example.com.", TypeA)

	truncated := cacheTestResponse("example.com.", 60)
	truncated.Truncated = true
	c.Insert(truncated)
	if m := c.Get(req); m != nil {
		t.Error("truncated response must not be cached")
	}

	failure := cacheTestResponse("example.com.", 60)
	failure.Rcode = RcodeServerFailure
	c.Insert(failure)
	if m := c.Get(req); m != nil {
		t.Error("non-successful response must not be cached")
	}

	nxdomain := cacheTestResponse("example.com.", 60)
	nxdomain.Rcode = RcodeNameError
	c.Insert(nxdomain)
	if m := c.Get(req); m != nil {
		t.Error("negative responses must not be cached")
	}

	twoQuestions := cacheTestResponse("example.com.", 60)
	twoQuestions.Question = append(twoQuestions.Question, Question{"example.org.", TypeA, ClassINET})
	c.Insert(twoQuestions)
	if m := c.Get(req); m != nil {
		t.Error("multi-question response must not be cached")
	}

	notResponse := cacheTestResponse("example.com.", 60)
	notResponse.Response = false
	c.Insert(notResponse)
	if m := c.Get(req); m != nil {
		t.Error("query message must not be cached")
	}
}

func TestCacheFailedQueryDoesNotChangeCache(t *testing.T) {
	clock := &fakeClock{}
	c := NewCacheWithClock(clock.Now)

	c.Insert(cacheTestResponse("example.com.", 60))

	if m := c.Get(nil); m != nil {
		t.Error("nil query must miss")
	}
	if m := c.Get(new(Msg)); m != nil {
		t.Error("query without question must miss")
	}
	other := new(Msg)
	other.SetQuestion("other.example.com.", TypeA)
	if m := c.Get(other); m != nil {
		t.Error("unknown question must miss")
	}
	// A failed insert must not overwrite the existing entry either.
	bad := cacheTestResponse("example.com.", 1)
	bad.Truncated = true
	c.Insert(bad)

	req := new(Msg)
	req.SetQuestion("example.com.", TypeA)
	m := c.Get(req)
	if m == nil {
		t.Fatal("existing entry must survive failed lookups and inserts")
	}
	if ttl := m.Answer[0].Header().Ttl; ttl != 60 {
		t.Errorf("existing entry changed, TTL = %d", ttl)
	}
}

func TestCacheOPTNotStored(t *testing.T) {
	clock := &fakeClock{}
	c := NewCacheWithClock(clock.Now)

	resp := cacheTestResponse("example.com.", 60)
	resp.SetEdns0(4096, true)
	resp.Extra = append(resp.Extra, &TXT{
		Hdr: RR_Header{Name: "example.com.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 60},
		Txt: []string{"hello"},
	})
	c.Insert(resp)

	req := new(Msg)
	req.SetQuestion("example.com.", TypeA)
	req.SetEdns0(4096, true)
	m := c.Get(req)
	if m == nil {
		t.Fatal("expected hit")
	}
	for _, rr := range m.Extra {
		if rr.Header().Rrtype == TypeOPT {
			t.Error("OPT record must not be served from the cache")
		}
	}
	if len(m.Extra) != 1 {
		t.Errorf("expected only the TXT record in Extra, got %d records", len(m.Extra))
	}
}

func TestCacheWallClockCannotExtendTTL(t *testing.T) {
	// NewCache uses the monotonic clock: an entry must expire on schedule
	// regardless of wall clock adjustments.
	c := NewCache()
	c.Insert(cacheTestResponse("example.com.", 1))
	req := new(Msg)
	req.SetQuestion("example.com.", TypeA)
	if m := c.Get(req); m == nil {
		t.Fatal("expected fresh entry to be served")
	}
	time.Sleep(1100 * time.Millisecond)
	if m := c.Get(req); m != nil {
		t.Error("entry must expire after its TTL elapsed")
	}
}

func ExampleCache_fakeClock() {
	// A fake clock lets you control time without sleeping.
	now := time.Duration(0)
	c := NewCacheWithClock(func() time.Duration { return now })

	resp := new(Msg)
	resp.SetQuestion("example.com.", TypeA)
	resp.Response = true
	resp.Answer = []RR{&A{
		Hdr: RR_Header{Name: "example.com.", Rrtype: TypeA, Class: ClassINET, Ttl: 30},
		A:   net.ParseIP("192.0.2.1"),
	}}
	c.Insert(resp)

	now += 10 * time.Second // pretend 10 seconds passed

	req := new(Msg)
	req.SetQuestion("example.com.", TypeA)
	req.Id = 7
	m := c.Get(req)
	fmt.Println(m.Id, m.Answer[0].Header().Ttl)
	// Output: 7 20
}
