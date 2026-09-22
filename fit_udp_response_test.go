package dns

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fitTestMsg builds a response with two Answer RRsets, one Authority
// RRset and two Additional RRsets, plus an OPT record. With name
// compression enabled it packs to more than MinMsgSize bytes.
func fitTestMsg() *Msg {
	m := new(Msg)
	m.SetQuestion("www.example.com.", TypeA)
	m.Response = true
	for i := 1; i <= 15; i++ {
		m.Answer = append(m.Answer, testRR(fmt.Sprintf("a.example.com. 300 IN A 192.0.2.%d", i)))
	}
	for i := 1; i <= 15; i++ {
		m.Answer = append(m.Answer, testRR(fmt.Sprintf("b.example.com. 300 IN A 192.0.3.%d", i)))
	}
	m.Ns = []RR{testRR("example.com. 300 IN NS ns1.example.com.")}
	for i := 1; i <= 5; i++ {
		m.Extra = append(m.Extra, testRR(fmt.Sprintf("ns1.example.com. 300 IN A 192.0.4.%d", i)))
	}
	for i := 1; i <= 5; i++ {
		m.Extra = append(m.Extra, testRR(fmt.Sprintf("ns2.example.com. 300 IN A 192.0.5.%d", i)))
	}
	m.SetEdns0(4096, false)
	return m
}

func fitPackLen(t *testing.T, m *Msg) int {
	t.Helper()
	m.Compress = true
	buf, err := m.Pack()
	if err != nil {
		t.Fatalf("failed to pack message: %v", err)
	}
	return len(buf)
}

func TestFitUDPResponseKeepsWholeGroups(t *testing.T) {
	msg := fitTestMsg()
	full := fitPackLen(t, msg)
	if full <= MinMsgSize {
		t.Fatalf("test message should exceed %d bytes, got %d", MinMsgSize, full)
	}

	// A budget that exactly fits the whole message keeps every group.
	fitted, report, err := FitUDPResponse(msg, full)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Removed) != 0 {
		t.Fatalf("expected no trimmed RRsets, got %v", report.Removed)
	}
	if fitted.Truncated {
		t.Error("TC bit should not be set when nothing was trimmed")
	}
	if report.WireLengthBefore != full || report.WireLengthAfter != full {
		t.Errorf("report wire lengths = %d -> %d, want %d -> %d",
			report.WireLengthBefore, report.WireLengthAfter, full, full)
	}
	if got := fitPackLen(t, fitted); got > full {
		t.Errorf("fitted message packs to %d bytes, exceeding the %d byte budget", got, full)
	}

	// One byte less forces the last Additional RRset out as a whole.
	fitted, report, err = FitUDPResponse(msg, full-1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Removed) != 1 {
		t.Fatalf("expected exactly one trimmed RRset, got %v", report.Removed)
	}
	tr := report.Removed[0]
	if tr.Section != "Additional" || tr.Owner != "ns2.example.com." || tr.Type != TypeA || tr.Count != 5 {
		t.Errorf("unexpected trimmed RRset: %+v", tr)
	}
	if !fitted.Truncated {
		t.Error("TC bit should be set after trimming")
	}
	if got := fitPackLen(t, fitted); got > full-1 {
		t.Errorf("fitted message packs to %d bytes, exceeding the %d byte budget", got, full-1)
	}
	if report.WireLengthAfter != fitPackLen(t, fitted) {
		t.Errorf("report wire length after = %d, real packed length = %d",
			report.WireLengthAfter, fitPackLen(t, fitted))
	}
	for _, rr := range fitted.Extra {
		if rr.Header().Name == "ns2.example.com." {
			t.Error("ns2.example.com. RRset should have been removed completely")
		}
	}
}

func TestFitUDPResponseSectionOrder(t *testing.T) {
	msg := fitTestMsg()

	// Budget that fits the question, OPT and Answer sections only.
	smallest := msg.Copy()
	smallest.Ns = nil
	smallest.Extra = []RR{msg.IsEdns0()}
	limit := fitPackLen(t, smallest)

	fitted, report, err := FitUDPResponse(msg, limit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fitted.Truncated {
		t.Error("TC bit should be set after trimming")
	}
	if len(fitted.Answer) != len(msg.Answer) {
		t.Errorf("Answer section should be untouched, got %d of %d RRs", len(fitted.Answer), len(msg.Answer))
	}
	if len(fitted.Ns) != 0 {
		t.Errorf("Authority section should be empty, got %d RRs", len(fitted.Ns))
	}
	if len(fitted.Extra) != 1 || fitted.IsEdns0() == nil {
		t.Errorf("Additional section should only hold the OPT record, got %d RRs", len(fitted.Extra))
	}
	want := []TrimmedRRset{
		{Section: "Additional", Owner: "ns2.example.com.", Type: TypeA, Count: 5},
		{Section: "Additional", Owner: "ns1.example.com.", Type: TypeA, Count: 5},
		{Section: "Authority", Owner: "example.com.", Type: TypeNS, Count: 1},
	}
	if !reflect.DeepEqual(report.Removed, want) {
		t.Errorf("trimmed RRsets = %v, want %v", report.Removed, want)
	}
	if got := fitPackLen(t, fitted); got > limit {
		t.Errorf("fitted message packs to %d bytes, exceeding the %d byte budget", got, limit)
	}
}

func TestFitUDPResponseDropsAnswersLast(t *testing.T) {
	msg := fitTestMsg()
	// Budget below the Answer sections: the last Answer RRset goes
	// first, and only whole RRsets are dropped.
	smallest := msg.Copy()
	smallest.Answer = smallest.Answer[:15] // keep only the a.example.com. RRset
	smallest.Ns = nil
	smallest.Extra = []RR{msg.IsEdns0()}
	limit := fitPackLen(t, smallest)

	fitted, report, err := FitUDPResponse(msg, limit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fitted.Answer) != 15 {
		t.Fatalf("expected only the a.example.com. RRset to survive, got %d answer RRs", len(fitted.Answer))
	}
	last := report.Removed[len(report.Removed)-1]
	if last.Section != "Answer" || last.Owner != "b.example.com." || last.Count != 15 {
		t.Errorf("last trimmed RRset = %+v, want the b.example.com. Answer RRset", last)
	}
	if got := fitPackLen(t, fitted); got > limit {
		t.Errorf("fitted message packs to %d bytes, exceeding the %d byte budget", got, limit)
	}
}

func TestFitUDPResponseRequiredTooLarge(t *testing.T) {
	// An OPT record that alone exceeds the budget.
	msg := new(Msg)
	msg.SetQuestion("www.example.com.", TypeA)
	opt := new(OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = TypeOPT
	opt.SetUDPSize(4096)
	opt.Option = append(opt.Option, &EDNS0_LOCAL{Code: 65001, Data: make([]byte, 600)})
	msg.Extra = []RR{opt}
	if _, _, err := FitUDPResponse(msg, MinMsgSize); err == nil {
		t.Error("expected an error when the OPT record exceeds the budget")
	}

	// A Question section that alone exceeds the budget.
	msg = new(Msg)
	name := strings.Repeat("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789.", 4) + "example.com."
	for i := 0; i < 5; i++ {
		msg.Question = append(msg.Question, Question{Name: name, Qtype: TypeA, Qclass: ClassINET})
	}
	if _, _, err := FitUDPResponse(msg, MinMsgSize); err == nil {
		t.Error("expected an error when the Question section exceeds the budget")
	}
}

func TestFitUDPResponseRRSIGStaysWithRRset(t *testing.T) {
	msg := new(Msg)
	msg.SetQuestion("www.example.com.", TypeA)
	msg.Response = true
	// The signed RRset appears last, so it is trimmed first.
	for i := 1; i <= 15; i++ {
		msg.Answer = append(msg.Answer, testRR(fmt.Sprintf("b.example.com. 300 IN A 192.0.3.%d", i)))
	}
	for i := 1; i <= 15; i++ {
		msg.Answer = append(msg.Answer, testRR(fmt.Sprintf("a.example.com. 300 IN A 192.0.2.%d", i)))
	}
	msg.Answer = append(msg.Answer, testRR("a.example.com. 300 IN RRSIG A 1 2 300 20300101000000 20260101000000 12345 example.com. AQIDBAUGBwg="))

	full := fitPackLen(t, msg)
	fitted, report, err := FitUDPResponse(msg, full-1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Removed) != 1 {
		t.Fatalf("expected exactly one trimmed RRset, got %v", report.Removed)
	}
	tr := report.Removed[0]
	if tr.Section != "Answer" || tr.Owner != "a.example.com." || tr.Type != TypeA || tr.Count != 16 {
		t.Errorf("trimmed RRset = %+v, want the a.example.com. A RRset including its RRSIG (16 RRs)", tr)
	}
	for _, rr := range fitted.Answer {
		if rr.Header().Rrtype == TypeRRSIG {
			t.Error("RRSIG must be removed together with the RRset it signs")
		}
	}
	if got := fitPackLen(t, fitted); got > full-1 {
		t.Errorf("fitted message packs to %d bytes, exceeding the %d byte budget", got, full-1)
	}
}

func TestFitUDPResponseOwnerCaseInsensitive(t *testing.T) {
	msg := new(Msg)
	msg.SetQuestion("www.example.com.", TypeA)
	msg.Response = true
	for i := 1; i <= 15; i++ {
		msg.Answer = append(msg.Answer, testRR(fmt.Sprintf("b.example.com. 300 IN A 192.0.3.%d", i)))
	}
	// Same owner, differing only in case: a single RRset.
	for i := 1; i <= 8; i++ {
		msg.Answer = append(msg.Answer, testRR(fmt.Sprintf("Web.Example.COM. 300 IN A 192.0.2.%d", i)))
	}
	for i := 9; i <= 16; i++ {
		msg.Answer = append(msg.Answer, testRR(fmt.Sprintf("web.example.com. 300 IN A 192.0.2.%d", i)))
	}

	full := fitPackLen(t, msg)
	_, report, err := FitUDPResponse(msg, full-1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Removed) != 1 {
		t.Fatalf("expected exactly one trimmed RRset, got %v", report.Removed)
	}
	if tr := report.Removed[0]; tr.Count != 16 || tr.Type != TypeA {
		t.Errorf("trimmed RRset = %+v, want a single 16-RR A set for the case-insensitive owner", tr)
	}
}

func TestFitUDPResponseKeepsTCWhenUntrimmed(t *testing.T) {
	msg := fitTestMsg()
	msg.Truncated = true
	full := fitPackLen(t, msg)

	fitted, report, err := FitUDPResponse(msg, full)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Removed) != 0 {
		t.Fatalf("expected no trimmed RRsets, got %v", report.Removed)
	}
	if !fitted.Truncated {
		t.Error("pre-existing TC bit must be preserved when nothing is trimmed")
	}
}

func TestFitUDPResponseRejectsTSIG(t *testing.T) {
	msg := fitTestMsg()
	msg.SetTsig("example.key.", HmacSHA256, 300, time.Now().Unix())
	fitted, report, err := FitUDPResponse(msg, MinMsgSize)
	if err == nil {
		t.Error("expected an error for a TSIG-signed message")
	}
	if fitted != nil || report != nil {
		t.Error("no message or report should be returned for a TSIG-signed message")
	}
}

func TestFitUDPResponseInputUnchanged(t *testing.T) {
	msg := fitTestMsg()
	full := fitPackLen(t, msg)
	msg.Compress = false
	before, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack message: %v", err)
	}

	if _, _, err := FitUDPResponse(msg, full-1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	after, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack message: %v", err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Error("input message must not be modified")
	}
	if msg.Compress {
		t.Error("input message Compress flag must not be modified")
	}
}

func ExampleFitUDPResponse() {
	msg := new(Msg)
	msg.SetQuestion("www.example.com.", TypeA)
	msg.Response = true
	for i := 1; i <= 20; i++ {
		msg.Answer = append(msg.Answer, testRR(fmt.Sprintf("a.example.com. 300 IN A 192.0.2.%d", i)))
	}
	for i := 1; i <= 20; i++ {
		msg.Answer = append(msg.Answer, testRR(fmt.Sprintf("b.example.com. 300 IN A 192.0.3.%d", i)))
	}
	msg.Ns = []RR{testRR("example.com. 300 IN NS ns1.example.com.")}
	for i := 1; i <= 5; i++ {
		msg.Extra = append(msg.Extra, testRR(fmt.Sprintf("ns1.example.com. 300 IN A 192.0.4.%d", i)))
	}
	msg.SetEdns0(4096, false)

	fitted, report, err := FitUDPResponse(msg, MinMsgSize)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("TC:", fitted.Truncated)
	fmt.Println(report)

	// Output:
	// TC: true
	// wire length: 786 -> 366 bytes, trimmed RRsets:
	//   Additional ns1.example.com. A (5 RRs)
	//   Authority example.com. NS (1 RRs)
	//   Answer b.example.com. A (20 RRs)
}
