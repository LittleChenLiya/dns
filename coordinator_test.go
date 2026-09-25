package dns

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newQuestion(name string, qtype uint16) *Msg {
	m := new(Msg)
	m.SetQuestion(name, qtype)
	return m
}

func newAnswer(q *Msg, rcode int, lines ...string) *Msg {
	m := new(Msg)
	m.SetRcode(q, rcode)
	m.Authoritative = true
	for _, line := range lines {
		rr, err := NewRR(line)
		if err != nil {
			panic(err)
		}
		m.Answer = append(m.Answer, rr)
	}
	return m
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newTestCoordinator(t *testing.T, fn ExchangerFunc) (*QueryCoordinator, *fakeClock) {
	t.Helper()
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	return &QueryCoordinator{Exchange: fn, Now: clock.Now}, clock
}

func waitForInflight(t *testing.T, c *QueryCoordinator, key string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		f := c.flights[key]
		got := 0
		if f != nil {
			got = f.waiters
		}
		c.mu.Unlock()
		if got == n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("flight for %q never reached %d waiters", key, n)
}

// TestCoordinatorSingleflightCancelOne: two callers share one upstream
// exchange; cancelling one leaves the other fully served and the server is hit
// exactly once.
func TestCoordinatorSingleflightCancelOne(t *testing.T) {
	var count atomic.Int32
	barrier := make(chan struct{})
	c, _ := newTestCoordinator(t, func(ctx context.Context, m *Msg, address string) (*Msg, error) {
		count.Add(1)
		select {
		case <-barrier:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return newAnswer(m, RcodeSuccess, "example.com.	300	IN	A	192.0.2.1"), nil
	})

	q1 := newQuestion("example.com.", TypeA)
	q2 := newQuestion("example.com.", TypeA)
	key := cacheKey(q1.Question[0], "upstream")

	type result struct {
		msg *Msg
		err error
	}
	res := make(chan result, 2)
	ctx1, cancel1 := context.WithCancel(context.Background())
	go func() {
		r, err := c.Query(ctx1, q1, "upstream")
		res <- result{r, err}
	}()
	go func() {
		r, err := c.Query(context.Background(), q2, "upstream")
		res <- result{r, err}
	}()

	waitForInflight(t, c, key, 2)

	cancel1()
	select {
	case r := <-res:
		if !errors.Is(r.err, context.Canceled) {
			t.Fatalf("canceled waiter: got err %v, want context.Canceled", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled waiter did not return")
	}

	waitForInflight(t, c, key, 1)
	// The shared upstream context must remain alive while one waiter stays.
	deadline2 := time.Now().Add(time.Second)
	alive := false
	for time.Now().Before(deadline2) {
		c.mu.Lock()
		if f := c.flights[key]; f != nil && f.ctx.Err() == nil {
			alive = true
		}
		c.mu.Unlock()
		if alive {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !alive {
		t.Fatal("shared upstream context was canceled while a waiter remained")
	}
	if got := count.Load(); got != 1 {
		t.Fatalf("server count = %d, want 1", got)
	}

	close(barrier)

	select {
	case r := <-res:
		if r.err != nil {
			t.Fatalf("remaining waiter: %v", r.err)
		}
		if r.msg.Id != q2.Id {
			t.Fatalf("response Id = %d, want request Id %d", r.msg.Id, q2.Id)
		}
		if a, ok := r.msg.Answer[0].(*A); !ok || a.A.String() != "192.0.2.1" {
			t.Fatalf("unexpected answer: %v", r.msg.Answer)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("remaining waiter did not get a response")
	}
	if got := count.Load(); got != 1 {
		t.Fatalf("server count = %d, want 1", got)
	}
}

// TestCoordinatorLastLeaveCancels: the shared exchange is cancelled only once
// the final waiter has left.
func TestCoordinatorLastLeaveCancels(t *testing.T) {
	var count atomic.Int32
	upstreamErr := make(chan error, 1)
	barrier := make(chan struct{})
	c, _ := newTestCoordinator(t, func(ctx context.Context, m *Msg, address string) (*Msg, error) {
		count.Add(1)
		select {
		case <-barrier:
			return newAnswer(m, RcodeSuccess, "example.org. 10 IN A 192.0.2.2"), nil
		case <-ctx.Done():
			upstreamErr <- ctx.Err()
			return nil, ctx.Err()
		}
	})

	key := cacheKey(Question{Name: "example.org.", Qtype: TypeA, Qclass: ClassINET}, "u")
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	go func() { _, _ = c.Query(ctx1, newQuestion("example.org.", TypeA), "u") }()
	go func() { _, _ = c.Query(ctx2, newQuestion("example.org.", TypeA), "u") }()
	waitForInflight(t, c, key, 2)

	cancel1()
	waitForInflight(t, c, key, 1)
	// The upstream context must survive for a while with one waiter left.
	select {
	case err := <-upstreamErr:
		t.Fatalf("upstream canceled after first leave: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	cancel2()
	select {
	case err := <-upstreamErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("upstream err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream was not canceled after last waiter left")
	}
	close(barrier)
}

// TestCoordinatorNegativeCacheExpiry exercises the SOA negative TTL boundary
// with an injected clock: at exactly the TTL the entry has expired and the
// upstream is queried again.
func TestCoordinatorNegativeCacheExpiry(t *testing.T) {
	var count atomic.Int32
	c, clock := newTestCoordinator(t, func(ctx context.Context, m *Msg, address string) (*Msg, error) {
		count.Add(1)
		r := newAnswer(m, RcodeNameError)
		r.Ns = append(r.Ns, mustRR("example.com.	60	IN	SOA	ns.example.com. hostmaster.example.com. 1 3600 900 604800 30"))
		return r, nil
	})

	q := newQuestion("missing.example.com.", TypeA)
	r1, err := c.Query(context.Background(), q, "u")
	if err != nil || r1.Rcode != RcodeNameError {
		t.Fatalf("first query: r=%v err=%v", r1, err)
	}

	clock.Advance(29 * time.Second)
	r2, err := c.Query(context.Background(), newQuestion("missing.example.com.", TypeA), "u")
	if err != nil || r2.Rcode != RcodeNameError {
		t.Fatalf("cached query: r=%v err=%v", r2, err)
	}

	clock.Advance(1 * time.Second)
	r3, err := c.Query(context.Background(), newQuestion("missing.example.com.", TypeA), "u")
	if err != nil || r3.Rcode != RcodeNameError {
		t.Fatalf("post-expiry query: r=%v err=%v", r3, err)
	}
	if got := count.Load(); got != 2 {
		t.Fatalf("server count = %d, want 2 (negative TTL is min(60,30)=30s)", got)
	}
}

// TestCoordinatorNegativeTTLMinBoundary pins both branches of the
// min(SOA TTL, MINIMUM) rule.
func TestCoordinatorNegativeTTLMinBoundary(t *testing.T) {
	cases := []struct {
		soaTTL, minimum uint32
		want            time.Duration
	}{
		{soaTTL: 60, minimum: 30, want: 30 * time.Second},  // MINIMUM smaller
		{soaTTL: 20, minimum: 300, want: 20 * time.Second}, // SOA TTL smaller
	}
	for _, tc := range cases {
		var count atomic.Int32
		c, clock := newTestCoordinator(t, func(ctx context.Context, m *Msg, address string) (*Msg, error) {
			count.Add(1)
			r := newAnswer(m, RcodeNameError)
			line := "example.com.\t" + strconv.Itoa(int(tc.soaTTL)) +
				"\tIN\tSOA\tns host 1 3600 900 604800 " + strconv.Itoa(int(tc.minimum))
			r.Ns = append(r.Ns, mustRR(line))
			return r, nil
		})
		_, _ = c.Query(context.Background(), newQuestion("x.example.com.", TypeA), "u")
		clock.Advance(tc.want)
		_, _ = c.Query(context.Background(), newQuestion("x.example.com.", TypeA), "u")
		if got := count.Load(); got != 2 {
			t.Errorf("soaTTL=%d minimum=%d: server count = %d, want 2 at the expiry boundary", tc.soaTTL, tc.minimum, got)
		}
		// A moment before the boundary the entry is still fresh.
		clock.Advance(-1 * time.Nanosecond)
		_, _ = c.Query(context.Background(), newQuestion("x.example.com.", TypeA), "u")
		if got := count.Load(); got != 2 {
			t.Errorf("soaTTL=%d minimum=%d: server count = %d, entry expired early", tc.soaTTL, tc.minimum, got)
		}
	}
}

// TestCoordinatorNXDOMAINWithoutSOA: a name error without SOA is never cached.
func TestCoordinatorNXDOMAINWithoutSOA(t *testing.T) {
	var count atomic.Int32
	c, _ := newTestCoordinator(t, func(ctx context.Context, m *Msg, address string) (*Msg, error) {
		count.Add(1)
		return newAnswer(m, RcodeNameError), nil
	})
	for i := 0; i < 3; i++ {
		_, _ = c.Query(context.Background(), newQuestion("missing.example.com.", TypeA), "u")
	}
	if got := count.Load(); got != 3 {
		t.Fatalf("server count = %d, want 3 (NXDOMAIN without SOA must not cache)", got)
	}
}

func mustRR(s string) RR {
	rr, err := NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}

// TestCoordinatorQtypeIsolation: different qtypes share neither the in-flight
// query nor the cache.
func TestCoordinatorQtypeIsolation(t *testing.T) {
	var aCount, aaaaCount atomic.Int32
	c, _ := newTestCoordinator(t, func(ctx context.Context, m *Msg, address string) (*Msg, error) {
		switch m.Question[0].Qtype {
		case TypeA:
			aCount.Add(1)
			return newAnswer(m, RcodeSuccess, "host.example.com. 100 IN A 192.0.2.3"), nil
		case TypeAAAA:
			aaaaCount.Add(1)
			return newAnswer(m, RcodeSuccess, "host.example.com. 100 IN AAAA 2001:db8::1"), nil
		}
		return nil, errors.New("unexpected qtype")
	})

	for i := 0; i < 2; i++ {
		a, err := c.Query(context.Background(), newQuestion("host.example.com.", TypeA), "u")
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := a.Answer[0].(*A); !ok {
			t.Fatalf("want A record, got %v", a.Answer[0])
		}
		aaaa, err := c.Query(context.Background(), newQuestion("host.example.com.", TypeAAAA), "u")
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := aaaa.Answer[0].(*AAAA); !ok {
			t.Fatalf("want AAAA record, got %v", aaaa.Answer[0])
		}
	}
	if aCount.Load() != 1 || aaaaCount.Load() != 1 {
		t.Fatalf("counts: A=%d AAAA=%d, want 1 each", aCount.Load(), aaaaCount.Load())
	}
}

// TestCoordinatorClassAndUpstreamIsolation: class and upstream config are part
// of the key as well.
func TestCoordinatorClassAndUpstreamIsolation(t *testing.T) {
	var count atomic.Int32
	c, _ := newTestCoordinator(t, func(ctx context.Context, m *Msg, address string) (*Msg, error) {
		count.Add(1)
		return newAnswer(m, RcodeSuccess, "host.example.com. 100 IN A 192.0.2.3"), nil
	})
	queries := []struct {
		class   uint16
		address string
	}{
		{ClassINET, "192.0.2.1:53"},
		{ClassCHAOS, "192.0.2.1:53"},
		{ClassINET, "192.0.2.2:53"},
	}
	for _, q := range queries {
		m := newQuestion("host.example.com.", TypeA)
		m.Question[0].Qclass = q.class
		if _, err := c.Query(context.Background(), m, q.address); err != nil {
			t.Fatal(err)
		}
	}
	if got := count.Load(); got != 3 {
		t.Fatalf("server count = %d, want 3 (class/upstream must isolate)", got)
	}
}

// TestCoordinatorCaseNormalization: mixed case and a missing trailing dot hit
// the same flight and cache entry.
func TestCoordinatorSingleflightCaseInsensitive(t *testing.T) {
	var count atomic.Int32
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	c, _ := newTestCoordinator(t, func(ctx context.Context, m *Msg, address string) (*Msg, error) {
		count.Add(1)
		started <- struct{}{}
		<-release
		return newAnswer(m, RcodeSuccess, "host.example.com. 300 IN A 192.0.2.4"), nil
	})

	type result struct {
		msg *Msg
		err error
	}
	res := make(chan result, 2)
	go func() {
		r, err := c.Query(context.Background(), newQuestion("HoSt.ExAmPLe.CoM", TypeA), "u")
		res <- result{r, err}
	}()
	<-started
	go func() {
		r, err := c.Query(context.Background(), newQuestion("host.example.com", TypeA), "u")
		res <- result{r, err}
	}()
	release <- struct{}{}

	for i := 0; i < 2; i++ {
		r := <-res
		if r.err != nil {
			t.Fatal(r.err)
		}
	}
	if got := count.Load(); got != 1 {
		t.Fatalf("server count = %d, want 1 for case/fqdn variants", got)
	}

	// A third, differently-cased query must be served from the cache.
	_, err := c.Query(context.Background(), newQuestion("HOST.example.com.", TypeA), "u")
	if err != nil {
		t.Fatal(err)
	}
	if got := count.Load(); got != 1 {
		t.Fatalf("server count = %d, want 1 (cache key must be case-insensitive)", got)
	}
}

// TestCoordinatorDeepCopyAndRequestID: returned messages carry the caller's
// request Id, and mutating one reply (or the cached reply, conceptually) does
// not leak into another caller.
func TestCoordinatorDeepCopyAndRequestID(t *testing.T) {
	var count atomic.Int32
	c, _ := newTestCoordinator(t, func(ctx context.Context, m *Msg, address string) (*Msg, error) {
		count.Add(1)
		return newAnswer(m, RcodeSuccess, "host.example.com. 100 IN A 192.0.2.5"), nil
	})

	q1 := newQuestion("host.example.com.", TypeA)
	q1.Id = 1111
	q2 := newQuestion("host.example.com.", TypeA)
	q2.Id = 2222
	r1, err := c.Query(context.Background(), q1, "u")
	if err != nil {
		t.Fatal(err)
	}
	if r1.Id != 1111 {
		t.Fatalf("first Id = %d, want 1111", r1.Id)
	}
	// Mutate the first response before the second query copies out of the cache.
	r1.Answer[0].(*A).A = []byte{10, 10, 10, 10}
	r1.Extra = append(r1.Extra, mustRR("host.example.com. 1 IN A 127.0.0.1"))

	r2, err := c.Query(context.Background(), q2, "u")
	if err != nil {
		t.Fatal(err)
	}
	if r2.Id != 2222 {
		t.Fatalf("second Id = %d, want 2222", r2.Id)
	}
	if got := r2.Answer[0].(*A).A.String(); got != "192.0.2.5" {
		t.Fatalf("mutation leaked across callers: %v", got)
	}
	if len(r2.Extra) != 0 {
		t.Fatalf("extra mutation leaked: %v", r2.Extra)
	}
}

// TestCoordinatorPositiveTTLMinAnswer: the positive TTL is the minimum of the
// RRsets that prove the answer; an unrelated short-TTL record in the Extra
// section must not shorten the cache lifetime.
func TestCoordinatorPositiveTTL(t *testing.T) {
	var count atomic.Int32
	c, clock := newTestCoordinator(t, func(ctx context.Context, m *Msg, address string) (*Msg, error) {
		count.Add(1)
		r := newAnswer(m, RcodeSuccess,
			"host.example.com.	60	IN	A	192.0.2.6",
			"host.example.com.	60	IN	A	192.0.2.7")
		r.Extra = append(r.Extra, mustRR("other.example.net. 1 IN A 198.51.100.1"))
		r.Ns = append(r.Ns, mustRR("example.com. 2 IN NS ns.example.com."))
		return r, nil
	})

	_, err := c.Query(context.Background(), newQuestion("host.example.com.", TypeA), "u")
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(59 * time.Second)
	_, _ = c.Query(context.Background(), newQuestion("host.example.com.", TypeA), "u")
	if got := count.Load(); got != 1 {
		t.Fatalf("server count = %d at 59s, want 1 (short unrelated TTL must be ignored)", got)
	}
	clock.Advance(1 * time.Second)
	_, _ = c.Query(context.Background(), newQuestion("host.example.com.", TypeA), "u")
	if got := count.Load(); got != 2 {
		t.Fatalf("server count = %d at 60s boundary, want 2", got)
	}
}

// TestCoordinatorCNAMEChainTTL: a complete CNAME chain is cached for the
// minimum TTL over the whole chain, while a dangling chain is not cached.
func TestCoordinatorCNAMEChainTTL(t *testing.T) {
	t.Run("complete", func(t *testing.T) {
		var count atomic.Int32
		c, clock := newTestCoordinator(t, func(ctx context.Context, m *Msg, address string) (*Msg, error) {
			count.Add(1)
			return newAnswer(m, RcodeSuccess,
				"alias.example.com.	100	IN	CNAME	target.example.com.",
				"target.example.com.	30	IN	A	192.0.2.8"), nil
		})
		_, _ = c.Query(context.Background(), newQuestion("alias.example.com.", TypeA), "u")
		clock.Advance(29 * time.Second)
		_, _ = c.Query(context.Background(), newQuestion("alias.example.com.", TypeA), "u")
		if got := count.Load(); got != 1 {
			t.Fatalf("server count = %d at 29s, want 1", got)
		}
		clock.Advance(1 * time.Second)
		_, _ = c.Query(context.Background(), newQuestion("alias.example.com.", TypeA), "u")
		if got := count.Load(); got != 2 {
			t.Fatalf("server count = %d at 30s, want 2 (chain TTL is min(100,30))", got)
		}
	})
	t.Run("dangling", func(t *testing.T) {
		var count atomic.Int32
		c, _ := newTestCoordinator(t, func(ctx context.Context, m *Msg, address string) (*Msg, error) {
			count.Add(1)
			return newAnswer(m, RcodeSuccess,
				"alias.example.com.	100	IN	CNAME	gone.example.com."), nil
		})
		for i := 0; i < 2; i++ {
			_, _ = c.Query(context.Background(), newQuestion("alias.example.com.", TypeA), "u")
		}
		if got := count.Load(); got != 2 {
			t.Fatalf("server count = %d, want 2 (dangling CNAME must not cache)", got)
		}
	})
	t.Run("CNAME query", func(t *testing.T) {
		var count atomic.Int32
		c, clock := newTestCoordinator(t, func(ctx context.Context, m *Msg, address string) (*Msg, error) {
			count.Add(1)
			return newAnswer(m, RcodeSuccess,
				"alias.example.com.	15	IN	CNAME	target.example.com."), nil
		})
		_, _ = c.Query(context.Background(), newQuestion("alias.example.com.", TypeCNAME), "u")
		clock.Advance(14 * time.Second)
		_, _ = c.Query(context.Background(), newQuestion("alias.example.com.", TypeCNAME), "u")
		if got := count.Load(); got != 1 {
			t.Fatalf("server count = %d, want 1 (CNAME answers directly)", got)
		}
		clock.Advance(1 * time.Second)
		_, _ = c.Query(context.Background(), newQuestion("alias.example.com.", TypeCNAME), "u")
		if got := count.Load(); got != 2 {
			t.Fatalf("server count = %d at 15s boundary, want 2", got)
		}
	})
}

// TestCoordinatorNoCacheCases: failures, truncation and context cancellation
// never populate the cache, and a later identical query goes upstream again.
func TestCoordinatorNoCacheCases(t *testing.T) {
	t.Run("failure", func(t *testing.T) {
		var count atomic.Int32
		c, _ := newTestCoordinator(t, func(ctx context.Context, m *Msg, address string) (*Msg, error) {
			count.Add(1)
			return nil, errors.New("upstream down")
		})
		for i := 0; i < 2; i++ {
			if _, err := c.Query(context.Background(), newQuestion("x.example.com.", TypeA), "u"); err == nil {
				t.Fatal("want error")
			}
		}
		if got := count.Load(); got != 2 {
			t.Fatalf("server count = %d, want 2 (failures must not cache)", got)
		}
	})
	t.Run("truncated", func(t *testing.T) {
		var count atomic.Int32
		c, _ := newTestCoordinator(t, func(ctx context.Context, m *Msg, address string) (*Msg, error) {
			count.Add(1)
			r := newAnswer(m, RcodeSuccess, "x.example.com. 100 IN A 192.0.2.9")
			r.Truncated = true
			return r, nil
		})
		for i := 0; i < 2; i++ {
			r, err := c.Query(context.Background(), newQuestion("x.example.com.", TypeA), "u")
			if err != nil || !r.Truncated {
				t.Fatalf("r=%v err=%v, want truncated response", r, err)
			}
		}
		if got := count.Load(); got != 2 {
			t.Fatalf("server count = %d, want 2 (truncated must not cache)", got)
		}
	})
	t.Run("cancellation", func(t *testing.T) {
		var count atomic.Int32
		c, _ := newTestCoordinator(t, func(ctx context.Context, m *Msg, address string) (*Msg, error) {
			count.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		})
		waitForErr := func() {
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			q := newQuestion("x.example.com.", TypeA)
			key := cacheKey(q.Question[0], "u")
			go func() {
				_, err := c.Query(ctx, q, "u")
				done <- err
			}()
			waitForInflight(t, c, key, 1)
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("err = %v, want context.Canceled", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("query did not return after cancel")
			}
		}
		waitForErr()
		waitForErr()
		if got := count.Load(); got != 2 {
			t.Fatalf("server count = %d, want 2 (cancellation must not cache)", got)
		}
	})
	t.Run("empty answer", func(t *testing.T) {
		var count atomic.Int32
		c, _ := newTestCoordinator(t, func(ctx context.Context, m *Msg, address string) (*Msg, error) {
			count.Add(1)
			return newAnswer(m, RcodeSuccess), nil // NOERROR with no answer
		})
		for i := 0; i < 2; i++ {
			if _, err := c.Query(context.Background(), newQuestion("x.example.com.", TypeA), "u"); err != nil {
				t.Fatal(err)
			}
		}
		if got := count.Load(); got != 2 {
			t.Fatalf("server count = %d, want 2 (unproven answer must not positive-cache)", got)
		}
	})
}

func TestCoordinatorBadInput(t *testing.T) {
	c := NewQueryCoordinator()
	if _, err := c.Query(context.Background(), nil, "u"); err == nil {
		t.Fatal("nil message: want error")
	}
	if _, err := c.Query(context.Background(), new(Msg), "u"); err == nil {
		t.Fatal("message without question: want error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Query(ctx, newQuestion("x.", TypeA), "u"); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled ctx: err = %v, want context.Canceled", err)
	}
}
