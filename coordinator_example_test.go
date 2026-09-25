package dns_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

// ExampleQueryCoordinator starts a loopback DNS server, then answers three
// identical queries through a QueryCoordinator: the first two are issued
// concurrently and share a single upstream exchange (singleflight), and the
// third one is served from the positive cache. The printed server-query count
// and TTL therefore make both mechanisms observable.
func ExampleQueryCoordinator() {
	// A loopback authoritative server with one A record (TTL 10s).
	addr, stop, err := startLoopbackServer()
	if err != nil {
		fmt.Println("server error:", err)
		return
	}
	defer stop()

	coordinator := dns.NewQueryCoordinator()

	query := func(id uint16) string {
		m := new(dns.Msg)
		m.SetQuestion("www.example.com.", dns.TypeA)
		m.Id = id
		r, err := coordinator.Query(context.Background(), m, addr)
		if err != nil {
			return "error: " + err.Error()
		}
		return r.Answer[0].String()
	}

	// Two concurrent identical queries: one wire query, two answers.
	var wg sync.WaitGroup
	wg.Add(2)
	answers := make([]string, 2)
	for i := range answers {
		i := i
		go func() {
			defer wg.Done()
			answers[i] = query(uint16(1000 + i))
		}()
	}
	wg.Wait()
	fmt.Println("answer 1:", answers[0])
	fmt.Println("answer 2:", answers[1])

	// Third identical query while the 10s positive TTL is still fresh.
	fmt.Println("answer 3:", query(1002))
	fmt.Printf("upstream queries: %d\n", loopbackQueries.Load())

	// Output:
	// answer 1: www.example.com.	10	IN	A	192.0.2.42
	// answer 2: www.example.com.	10	IN	A	192.0.2.42
	// answer 3: www.example.com.	10	IN	A	192.0.2.42
	// upstream queries: 1
}

var loopbackQueries atomic.Int32

// startLoopbackServer serves a fixed zone on a random loopback UDP port and
// returns the "host:port" address together with a shutdown function.
func startLoopbackServer() (string, func(), error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	mux := new(dns.ServeMux)
	mux.HandleFunc("example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		loopbackQueries.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			if rr, err := dns.NewRR("www.example.com.\t10\tIN\tA\t192.0.2.42"); err == nil {
				m.Answer = append(m.Answer, rr)
			}
		}
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	stop := func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	}
	return pc.LocalAddr().String(), stop, nil
}
