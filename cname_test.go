package dns

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"
)

func cnameRecord(owner, target string, ttl uint32) *CNAME {
	return &CNAME{
		Hdr:    RR_Header{Name: owner, Rrtype: TypeCNAME, Class: ClassINET, Ttl: ttl},
		Target: target,
	}
}

func aRecord(name, ip string, ttl uint32) *A {
	return &A{
		Hdr: RR_Header{Name: name, Rrtype: TypeA, Class: ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip),
	}
}

func chaseQuestion() *Msg {
	q := new(Msg)
	q.SetQuestion("a.example.", TypeA)
	return q
}

// chainResponse builds a.example -> b.example -> c.example with two A
// records at c.example.
func chainResponse() *Msg {
	r := new(Msg)
	r.SetRcode(chaseQuestion(), RcodeSuccess)
	r.Answer = []RR{
		cnameRecord("a.example.", "b.example.", 300),
		cnameRecord("b.example.", "c.example.", 200),
		aRecord("c.example.", "192.0.2.1", 100),
		aRecord("c.example.", "192.0.2.2", 150),
	}
	return r
}

func TestChaseCNAMEChain(t *testing.T) {
	q := chaseQuestion()
	r := chainResponse()

	res, err := ChaseCNAME(q, r, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Complete {
		t.Fatal("expected complete chain")
	}
	wantChain := []string{"a.example.", "b.example.", "c.example."}
	if !reflect.DeepEqual(res.Chain, wantChain) {
		t.Errorf("chain = %v, want %v", res.Chain, wantChain)
	}
	if len(res.RRset) != 2 {
		t.Fatalf("RRset has %d records, want 2", len(res.RRset))
	}
	for _, rr := range res.RRset {
		if rr.Header().Rrtype != TypeA || CanonicalName(rr.Header().Name) != "c.example." {
			t.Errorf("unexpected RR in RRset: %v", rr)
		}
	}
	if res.MinTTL != 100 {
		t.Errorf("MinTTL = %d, want 100", res.MinTTL)
	}
	if res.FinalName() != "c.example." {
		t.Errorf("FinalName = %q, want c.example.", res.FinalName())
	}
	if res.Rcode != RcodeSuccess || res.Truncated {
		t.Errorf("Rcode/Truncated = %d/%v, want 0/false", res.Rcode, res.Truncated)
	}
}

func TestChaseCNAMECaseInsensitive(t *testing.T) {
	q := new(Msg)
	q.SetQuestion("A.Example.", TypeA)
	r := new(Msg)
	r.SetRcode(q, RcodeSuccess)
	r.Answer = []RR{
		cnameRecord("a.EXAMPLE.", "B.example.", 300),
		cnameRecord("b.Example.", "C.EXAMPLE.", 300),
		aRecord("c.Example.", "192.0.2.1", 300),
	}

	res, err := ChaseCNAME(q, r, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Complete || len(res.RRset) != 1 {
		t.Fatalf("expected complete chain with 1 RR, got %+v", res)
	}
	wantChain := []string{"a.example.", "b.example.", "c.example."}
	if !reflect.DeepEqual(res.Chain, wantChain) {
		t.Errorf("chain = %v, want %v", res.Chain, wantChain)
	}
}

func TestChaseCNAMELoop(t *testing.T) {
	q := chaseQuestion()
	r := new(Msg)
	r.SetRcode(q, RcodeSuccess)
	r.Answer = []RR{
		cnameRecord("a.example.", "b.example.", 300),
		cnameRecord("b.example.", "a.example.", 300),
	}

	_, err := ChaseCNAME(q, r, 10)
	if !errors.Is(err, ErrCNAMELoop) {
		t.Fatalf("err = %v, want ErrCNAMELoop", err)
	}
}

func TestChaseCNAMEConflict(t *testing.T) {
	q := chaseQuestion()
	r := new(Msg)
	r.SetRcode(q, RcodeSuccess)
	r.Answer = []RR{
		cnameRecord("a.example.", "b.example.", 300),
		cnameRecord("a.example.", "x.example.", 300),
	}

	_, err := ChaseCNAME(q, r, 10)
	if !errors.Is(err, ErrCNAMEConflict) {
		t.Fatalf("err = %v, want ErrCNAMEConflict", err)
	}
}

func TestChaseCNAMETooManyHops(t *testing.T) {
	q := chaseQuestion()
	r := chainResponse()

	_, err := ChaseCNAME(q, r, 1)
	if !errors.Is(err, ErrCNAMETooManyHops) {
		t.Fatalf("err = %v, want ErrCNAMETooManyHops", err)
	}
}

func TestChaseCNAMETruncated(t *testing.T) {
	q := chaseQuestion()
	r := chainResponse()
	r.Truncated = true

	res, err := ChaseCNAME(q, r, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Truncated {
		t.Error("expected Truncated to be preserved")
	}
}

func TestChaseCNAMEIncomplete(t *testing.T) {
	q := chaseQuestion()
	r := new(Msg)
	r.SetRcode(q, RcodeSuccess)
	r.Answer = []RR{
		cnameRecord("a.example.", "b.example.", 300),
		cnameRecord("b.example.", "c.example.", 200),
	}

	res, err := ChaseCNAME(q, r, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Complete {
		t.Fatal("expected incomplete chain")
	}
	if res.FinalName() != "c.example." {
		t.Errorf("FinalName = %q, want c.example.", res.FinalName())
	}
	if res.Rcode != RcodeSuccess {
		t.Errorf("Rcode = %d, want %d (not NXDOMAIN)", res.Rcode, RcodeSuccess)
	}
	if res.MinTTL != 200 {
		t.Errorf("MinTTL = %d, want 200", res.MinTTL)
	}
}

func TestChaseCNAMEIgnoresAdditional(t *testing.T) {
	q := chaseQuestion()
	r := new(Msg)
	r.SetRcode(q, RcodeSuccess)
	r.Answer = []RR{
		cnameRecord("a.example.", "b.example.", 300),
	}
	// The A record for b.example. only exists in the additional section
	// and must not be used to complete the chain.
	r.Extra = []RR{aRecord("b.example.", "192.0.2.1", 300)}

	res, err := ChaseCNAME(q, r, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Complete {
		t.Fatal("chain must not be completed from additional-section records")
	}
	if res.FinalName() != "b.example." {
		t.Errorf("FinalName = %q, want b.example.", res.FinalName())
	}
}

func TestChaseCNAMEDoesNotMutateInput(t *testing.T) {
	q := chaseQuestion()
	r := chainResponse()
	r.Truncated = true
	qBefore, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	rBefore, err := r.Pack()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ChaseCNAME(q, r, 10); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	qAfter, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	rAfter, err := r.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(qBefore, qAfter) {
		t.Error("question message was modified")
	}
	if !bytes.Equal(rBefore, rAfter) {
		t.Error("response message was modified")
	}
}

func ExampleChaseCNAME() {
	q := new(Msg)
	q.SetQuestion("a.example.", TypeA)

	// A normal response: a.example. -> b.example. -> c.example. with two
	// A records at the end of the chain.
	normal := new(Msg)
	normal.SetRcode(q, RcodeSuccess)
	normal.Answer = []RR{
		&CNAME{Hdr: RR_Header{Name: "a.example.", Rrtype: TypeCNAME, Class: ClassINET, Ttl: 300}, Target: "b.example."},
		&CNAME{Hdr: RR_Header{Name: "b.example.", Rrtype: TypeCNAME, Class: ClassINET, Ttl: 200}, Target: "c.example."},
		&A{Hdr: RR_Header{Name: "c.example.", Rrtype: TypeA, Class: ClassINET, Ttl: 100}, A: net.ParseIP("192.0.2.1")},
		&A{Hdr: RR_Header{Name: "c.example.", Rrtype: TypeA, Class: ClassINET, Ttl: 100}, A: net.ParseIP("192.0.2.2")},
	}
	res, err := ChaseCNAME(q, normal, 10)
	if err != nil {
		fmt.Println("error:", err)
	} else {
		fmt.Println("chain:", res.Chain)
		for _, rr := range res.RRset {
			fmt.Println("answer:", rr.(*A).A)
		}
		fmt.Println("min TTL:", res.MinTTL)
	}

	// A conflicting response: two CNAMEs for a.example. with different
	// targets.
	conflict := new(Msg)
	conflict.SetRcode(q, RcodeSuccess)
	conflict.Answer = []RR{
		&CNAME{Hdr: RR_Header{Name: "a.example.", Rrtype: TypeCNAME, Class: ClassINET, Ttl: 300}, Target: "b.example."},
		&CNAME{Hdr: RR_Header{Name: "a.example.", Rrtype: TypeCNAME, Class: ClassINET, Ttl: 300}, Target: "x.example."},
	}
	if _, err := ChaseCNAME(q, conflict, 10); err != nil {
		fmt.Println("error:", err)
	}

	// Output:
	// chain: [a.example. b.example. c.example.]
	// answer: 192.0.2.1
	// answer: 192.0.2.2
	// min TTL: 100
	// error: dns: conflicting CNAME targets for a.example.: b.example. and x.example.
}
