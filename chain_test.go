package dns

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func chainTestCNAME(owner, target string, ttl uint32) *CNAME {
	return &CNAME{
		Hdr:    RR_Header{Name: owner, Rrtype: TypeCNAME, Class: ClassINET, Ttl: ttl},
		Target: target,
	}
}

func chainTestA(owner, ip string, ttl uint32) *A {
	rr, err := NewRR(owner + " 3600 IN A " + ip)
	if err != nil {
		panic(err)
	}
	a := rr.(*A)
	a.Hdr.Ttl = ttl
	return a
}

func chainTestMsg(qname string, qtype uint16, answer ...RR) (*Question, *Msg) {
	q := Question{Name: qname, Qtype: qtype, Qclass: ClassINET}
	m := new(Msg)
	m.SetQuestion(qname, qtype)
	m.Response = true
	m.Answer = answer
	return &q, m
}

func TestFollowCNAMEChain(t *testing.T) {
	q, m := chainTestMsg("a.example.", TypeA,
		chainTestCNAME("a.example.", "b.example.", 300),
		chainTestCNAME("b.example.", "c.example.", 200),
		chainTestA("c.example.", "192.0.2.1", 100),
		chainTestA("c.example.", "192.0.2.2", 400),
	)
	chain, err := FollowCNAMEChain(*q, m, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !chain.Complete {
		t.Fatal("expected complete chain")
	}
	wantChain := []string{"a.example.", "b.example.", "c.example."}
	if !reflect.DeepEqual(chain.Chain, wantChain) {
		t.Errorf("chain = %v, want %v", chain.Chain, wantChain)
	}
	if len(chain.RRset) != 2 {
		t.Fatalf("RRset has %d records, want 2", len(chain.RRset))
	}
	for _, rr := range chain.RRset {
		if rr.Header().Rrtype != TypeA {
			t.Errorf("RRset contains %s, want A records only", TypeToString[rr.Header().Rrtype])
		}
	}
	if chain.LastName != "c.example." {
		t.Errorf("LastName = %q, want %q", chain.LastName, "c.example.")
	}
	if chain.TTL != 100 {
		t.Errorf("TTL = %d, want 100 (minimum of 300, 200, 100, 400)", chain.TTL)
	}
}

func TestFollowCNAMEChainCaseInsensitive(t *testing.T) {
	q, m := chainTestMsg("A.Example.", TypeA,
		chainTestCNAME("a.EXAMPLE.", "B.Example.", 300),
		chainTestA("b.example.", "192.0.2.1", 300),
	)
	chain, err := FollowCNAMEChain(*q, m, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !chain.Complete || len(chain.RRset) != 1 {
		t.Fatalf("chain not completed across case variants: %+v", chain)
	}
}

func TestFollowCNAMEChainLoop(t *testing.T) {
	q, m := chainTestMsg("a.example.", TypeA,
		chainTestCNAME("a.example.", "b.example.", 300),
		chainTestCNAME("b.example.", "a.example.", 300),
	)
	_, err := FollowCNAMEChain(*q, m, 10)
	if !errors.Is(err, ErrCNAMEChainLoop) {
		t.Fatalf("err = %v, want ErrCNAMEChainLoop", err)
	}
}

func TestFollowCNAMEChainSelfLoop(t *testing.T) {
	q, m := chainTestMsg("a.example.", TypeA,
		chainTestCNAME("a.example.", "a.example.", 300),
	)
	_, err := FollowCNAMEChain(*q, m, 10)
	if !errors.Is(err, ErrCNAMEChainLoop) {
		t.Fatalf("err = %v, want ErrCNAMEChainLoop", err)
	}
}

func TestFollowCNAMEChainConflict(t *testing.T) {
	q, m := chainTestMsg("a.example.", TypeA,
		chainTestCNAME("a.example.", "b.example.", 300),
		chainTestCNAME("a.example.", "c.example.", 300),
	)
	_, err := FollowCNAMEChain(*q, m, 10)
	if !errors.Is(err, ErrCNAMEChainConflict) {
		t.Fatalf("err = %v, want ErrCNAMEChainConflict", err)
	}
}

func TestFollowCNAMEChainTooLong(t *testing.T) {
	q, m := chainTestMsg("a.example.", TypeA,
		chainTestCNAME("a.example.", "b.example.", 300),
		chainTestCNAME("b.example.", "c.example.", 300),
		chainTestA("c.example.", "192.0.2.1", 300),
	)
	_, err := FollowCNAMEChain(*q, m, 1)
	if !errors.Is(err, ErrCNAMEChainTooLong) {
		t.Fatalf("err = %v, want ErrCNAMEChainTooLong", err)
	}
	// A negative limit disables the hop check.
	if _, err := FollowCNAMEChain(*q, m, -1); err != nil {
		t.Fatalf("unexpected error with unlimited hops: %v", err)
	}
}

func TestFollowCNAMEChainTruncated(t *testing.T) {
	q, m := chainTestMsg("a.example.", TypeA,
		chainTestCNAME("a.example.", "b.example.", 300),
	)
	m.Truncated = true
	m.Rcode = RcodeServerFailure
	chain, err := FollowCNAMEChain(*q, m, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !chain.Truncated {
		t.Error("Truncated flag was not preserved")
	}
	if chain.Rcode != RcodeServerFailure {
		t.Errorf("Rcode = %d, want %d", chain.Rcode, RcodeServerFailure)
	}
}

func TestFollowCNAMEChainMissingTail(t *testing.T) {
	q, m := chainTestMsg("a.example.", TypeA,
		chainTestCNAME("a.example.", "b.example.", 300),
		chainTestCNAME("b.example.", "c.example.", 200),
	)
	chain, err := FollowCNAMEChain(*q, m, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if chain.Complete {
		t.Fatal("chain must not be complete without a final answer")
	}
	if chain.LastName != "c.example." {
		t.Errorf("LastName = %q, want %q", chain.LastName, "c.example.")
	}
	if chain.RRset != nil {
		t.Errorf("RRset = %v, want nil", chain.RRset)
	}
	if chain.TTL != 200 {
		t.Errorf("TTL = %d, want 200 (minimum of the followed CNAMEs)", chain.TTL)
	}
	// An incomplete chain is not an NXDOMAIN verdict.
	if chain.Rcode != RcodeSuccess {
		t.Errorf("Rcode = %d, want %d", chain.Rcode, RcodeSuccess)
	}
}

func TestFollowCNAMEChainIgnoresAdditional(t *testing.T) {
	q, m := chainTestMsg("a.example.", TypeA,
		chainTestCNAME("a.example.", "b.example.", 300),
	)
	// The final A record only exists in the additional section and must
	// not be used to complete the chain.
	m.Extra = []RR{chainTestA("b.example.", "192.0.2.1", 300)}
	chain, err := FollowCNAMEChain(*q, m, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if chain.Complete {
		t.Fatal("chain completed from an unrelated additional record")
	}
	if chain.LastName != "b.example." {
		t.Errorf("LastName = %q, want %q", chain.LastName, "b.example.")
	}
}

func TestFollowCNAMEChainDoesNotMutateInput(t *testing.T) {
	q, m := chainTestMsg("a.example.", TypeA,
		chainTestCNAME("a.example.", "b.example.", 300),
		chainTestCNAME("b.example.", "c.example.", 200),
		chainTestA("c.example.", "192.0.2.1", 100),
	)
	packedBefore, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FollowCNAMEChain(*q, m, 10); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	packedAfter, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(packedBefore, packedAfter) {
		t.Error("packed response differs after analysis")
	}
}

func ExampleFollowCNAMEChain() {
	// A normal a.example -> b.example -> c.example chain with two A
	// records at the end.
	q := Question{Name: "a.example.", Qtype: TypeA, Qclass: ClassINET}
	resp := new(Msg)
	resp.SetQuestion(q.Name, q.Qtype)
	resp.Response = true
	resp.Answer = []RR{
		&CNAME{Hdr: RR_Header{Name: "a.example.", Rrtype: TypeCNAME, Class: ClassINET, Ttl: 300}, Target: "b.example."},
		&CNAME{Hdr: RR_Header{Name: "b.example.", Rrtype: TypeCNAME, Class: ClassINET, Ttl: 200}, Target: "c.example."},
	}
	a1, _ := NewRR("c.example. 100 IN A 192.0.2.1")
	a2, _ := NewRR("c.example. 400 IN A 192.0.2.2")
	resp.Answer = append(resp.Answer, a1, a2)

	chain, err := FollowCNAMEChain(q, resp, 10)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("chain:", chain.Chain)
	for _, rr := range chain.RRset {
		fmt.Println("answer:", rr)
	}
	fmt.Println("complete:", chain.Complete, "ttl:", chain.TTL, "rcode:", RcodeToString[chain.Rcode], "truncated:", chain.Truncated)

	// The same name with two different CNAME targets is a conflict.
	conflict := new(Msg)
	conflict.SetQuestion(q.Name, q.Qtype)
	conflict.Response = true
	conflict.Answer = []RR{
		&CNAME{Hdr: RR_Header{Name: "a.example.", Rrtype: TypeCNAME, Class: ClassINET, Ttl: 300}, Target: "b.example."},
		&CNAME{Hdr: RR_Header{Name: "a.example.", Rrtype: TypeCNAME, Class: ClassINET, Ttl: 300}, Target: "c.example."},
	}
	_, err = FollowCNAMEChain(q, conflict, 10)
	fmt.Println("conflict:", errors.Is(err, ErrCNAMEChainConflict))

	// Output:
	// chain: [a.example. b.example. c.example.]
	// answer: c.example.	100	IN	A	192.0.2.1
	// answer: c.example.	400	IN	A	192.0.2.2
	// complete: true ttl: 100 rcode: NOERROR truncated: false
	// conflict: true
}
