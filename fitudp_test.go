package dns

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

func makeFitUDPTestMsg() *Msg {
	m := new(Msg)
	m.SetQuestion("example.com.", TypeA)
	m.Response = true
	m.Compress = true
	m.Answer = []RR{
		&TXT{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 300}, Txt: []string{strings.Repeat("a", 240)}},
		&TXT{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 300}, Txt: []string{strings.Repeat("b", 240)}},
		&TXT{Hdr: RR_Header{Name: "www.example.com.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 300}, Txt: []string{strings.Repeat("c", 150)}},
	}
	m.Ns = []RR{
		&NS{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeNS, Class: ClassINET, Ttl: 300}, Ns: "ns1.example.com."},
	}
	m.Extra = []RR{
		&TXT{Hdr: RR_Header{Name: "ns1.example.com.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 300}, Txt: []string{strings.Repeat("d", 150)}},
		&TXT{Hdr: RR_Header{Name: "ns2.example.com.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 300}, Txt: []string{strings.Repeat("e", 150)}},
	}
	m.SetEdns0(4096, false)
	return m
}

func checkFitPack(t *testing.T, fit *Msg, report *FitUDPReport, limit int) {
	t.Helper()
	if limit < MinMsgSize {
		limit = MinMsgSize
	}
	p, err := fit.Pack()
	if err != nil {
		t.Fatalf("failed to pack fitted message: %v", err)
	}
	if len(p) > limit {
		t.Fatalf("packed message is %d bytes, exceeds limit %d", len(p), limit)
	}
	if len(p) != report.WireLengthAfter {
		t.Fatalf("packed length %d does not match reported wire length %d", len(p), report.WireLengthAfter)
	}
}

func TestFitUDPResponseFits(t *testing.T) {
	m := makeFitUDPTestMsg()
	limit := m.Len()
	fit, report, err := FitUDPResponse(m, limit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.RemovedSets) != 0 {
		t.Fatalf("expected no removals, got %v", report.RemovedSets)
	}
	if fit.Truncated {
		t.Fatal("TC bit must not be set when nothing was removed")
	}
	if report.WireLengthBefore != limit || report.WireLengthAfter != limit {
		t.Fatalf("unexpected wire lengths in report: %v", report)
	}
	checkFitPack(t, fit, report, limit)
	if fit.IsEdns0() == nil {
		t.Fatal("OPT record must be kept")
	}
}

func TestFitUDPResponseRemovesWholeGroups(t *testing.T) {
	m := makeFitUDPTestMsg()

	expected := []FitUDPRemovedSet{
		{Section: "additional", Owner: "ns2.example.com.", Type: TypeTXT, Count: 1},
		{Section: "additional", Owner: "ns1.example.com.", Type: TypeTXT, Count: 1},
		{Section: "authority", Owner: "example.com.", Type: TypeNS, Count: 1},
		{Section: "answer", Owner: "www.example.com.", Type: TypeTXT, Count: 1},
		{Section: "answer", Owner: "example.com.", Type: TypeTXT, Count: 2},
	}

	cur := m
	for i, want := range expected {
		before := cur.Len()
		fit, report, err := FitUDPResponse(cur, before-1)
		if err != nil {
			t.Fatalf("step %d: unexpected error: %v", i, err)
		}
		if report.WireLengthBefore != before {
			t.Fatalf("step %d: report says before=%d, want %d", i, report.WireLengthBefore, before)
		}
		if len(report.RemovedSets) != 1 {
			t.Fatalf("step %d: expected exactly one removed set, got %v", i, report.RemovedSets)
		}
		if got := report.RemovedSets[0]; got != want {
			t.Fatalf("step %d: removed %+v, want %+v", i, got, want)
		}
		if !fit.Truncated {
			t.Fatalf("step %d: TC bit must be set after removals", i)
		}
		checkFitPack(t, fit, report, before-1)
		if len(fit.Question) != 1 || fit.IsEdns0() == nil {
			t.Fatalf("step %d: question and OPT must be kept", i)
		}
		cur = fit
	}

	// Everything removable is gone; the mandatory remainder must still fit.
	if _, _, err := FitUDPResponse(cur, MinMsgSize); err != nil {
		t.Fatalf("mandatory remainder does not fit: %v", err)
	}
}

func TestFitUDPResponseTooSmall(t *testing.T) {
	m := makeFitUDPTestMsg()
	opt := m.IsEdns0()
	opt.Option = append(opt.Option, &EDNS0_LOCAL{Code: 65001, Data: make([]byte, 600)})

	if _, _, err := FitUDPResponse(m, MinMsgSize); !errors.Is(err, ErrFitUDPTooSmall) {
		t.Fatalf("expected ErrFitUDPTooSmall, got %v", err)
	}
}

func TestFitUDPResponseRRSIG(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("example.com.", TypeA)
	m.Response = true
	m.Compress = true
	sig := &RRSIG{
		Hdr:         RR_Header{Name: "example.com.", Rrtype: TypeRRSIG, Class: ClassINET, Ttl: 300},
		TypeCovered: TypeA,
		Algorithm:   RSASHA256,
		Labels:      2,
		OrigTtl:     300,
		SignerName:  "example.com.",
		Signature:   strings.Repeat("QUJD", 200),
	}
	m.Answer = []RR{
		&A{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeA, Class: ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.1")},
		sig,
	}

	// When the RRset fits, the RRSIG is kept with it.
	fit, report, err := FitUDPResponse(m, m.Len())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fit.Answer) != 2 {
		t.Fatalf("expected RRSIG to be kept with its RRset, got %d answer records", len(fit.Answer))
	}
	if len(report.RemovedSets) != 0 {
		t.Fatalf("expected no removals, got %v", report.RemovedSets)
	}

	// When the RRset is removed, the RRSIG goes with it.
	fit, report, err = FitUDPResponse(m, m.Len()-1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fit.Answer) != 0 {
		t.Fatalf("expected RRSIG to be removed with its RRset, got %d answer records", len(fit.Answer))
	}
	want := FitUDPRemovedSet{Section: "answer", Owner: "example.com.", Type: TypeA, Count: 2}
	if len(report.RemovedSets) != 1 || report.RemovedSets[0] != want {
		t.Fatalf("removed %+v, want %+v", report.RemovedSets, want)
	}
	if !fit.Truncated {
		t.Fatal("TC bit must be set after removals")
	}
}

func TestFitUDPResponseOwnerCaseInsensitive(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("example.com.", TypeA)
	m.Response = true
	m.Compress = true
	m.Answer = []RR{
		&TXT{Hdr: RR_Header{Name: "Example.COM.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 300}, Txt: []string{strings.Repeat("a", 240)}},
		&TXT{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 300}, Txt: []string{strings.Repeat("b", 240)}},
	}

	fit, report, err := FitUDPResponse(m, m.Len()-1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fit.Answer) != 0 {
		t.Fatalf("owner names differing only in case must form one RRset, got %d answer records", len(fit.Answer))
	}
	if len(report.RemovedSets) != 1 || report.RemovedSets[0].Count != 2 {
		t.Fatalf("expected one removed set of 2 records, got %v", report.RemovedSets)
	}
}

func TestFitUDPResponseKeepsTC(t *testing.T) {
	m := makeFitUDPTestMsg()
	m.Truncated = true
	fit, report, err := FitUDPResponse(m, m.Len())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.RemovedSets) != 0 {
		t.Fatalf("expected no removals, got %v", report.RemovedSets)
	}
	if !fit.Truncated {
		t.Fatal("pre-existing TC bit must be preserved when nothing was removed")
	}
}

func TestFitUDPResponseTsig(t *testing.T) {
	m := makeFitUDPTestMsg()
	m.Extra = append(m.Extra, &TSIG{
		Hdr:       RR_Header{Name: "key.example.", Rrtype: TypeTSIG, Class: ClassANY},
		Algorithm: HmacSHA256,
	})

	if _, _, err := FitUDPResponse(m, MinMsgSize); !errors.Is(err, ErrFitUDPTsig) {
		t.Fatalf("expected ErrFitUDPTsig, got %v", err)
	}
	if m.IsTsig() == nil {
		t.Fatal("original message must keep its TSIG record")
	}
}

func TestFitUDPResponseInputUnchanged(t *testing.T) {
	m := makeFitUDPTestMsg()
	before, err := m.Pack()
	if err != nil {
		t.Fatalf("failed to pack original message: %v", err)
	}

	if _, _, err := FitUDPResponse(m, MinMsgSize); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	after, err := m.Pack()
	if err != nil {
		t.Fatalf("failed to pack original message: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("FitUDPResponse must not modify the input message")
	}
	if !m.Compress {
		t.Fatal("FitUDPResponse must not modify the input Compress flag")
	}
}

func ExampleFitUDPResponse() {
	m := makeFitUDPTestMsg()

	// Pick a budget that keeps every RRset except the last additional one.
	limit := m.Len() - 1
	fit, report, err := FitUDPResponse(m, limit)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	p, _ := fit.Pack()
	fmt.Println(report)
	fmt.Println("packed length:", len(p), "<= limit:", len(p) <= limit)
	fmt.Println("truncated:", fit.Truncated)
	// Output:
	// wire length: 1061 -> 894
	// removed additional RRset ns2.example.com. TXT (1 records)
	// packed length: 894 <= limit: true
	// truncated: true
}
