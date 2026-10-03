package dns

import (
	"bytes"
	"fmt"
	"testing"
)

// TestSummarizeRRsetPermutations verifies that different orderings of the
// same RRset produce the same content summary.
func TestSummarizeRRsetPermutations(t *testing.T) {
	rrs := []RR{
		&A{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeA, Class: ClassINET, Ttl: 3600}, A: []byte{1, 2, 3, 4}},
		&A{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeA, Class: ClassINET, Ttl: 3600}, A: []byte{5, 6, 7, 8}},
		&A{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeA, Class: ClassINET, Ttl: 3600}, A: []byte{9, 10, 11, 12}},
	}

	s1, err := SummarizeRRsets(rrs)
	if err != nil {
		t.Fatal(err)
	}

	// Shuffle the order.
	rrs[0], rrs[2] = rrs[2], rrs[0]
	s2, err := SummarizeRRsets(rrs)
	if err != nil {
		t.Fatal(err)
	}

	if len(s1) != 1 || len(s2) != 1 {
		t.Fatalf("expected 1 summary, got %d and %d", len(s1), len(s2))
	}
	if !bytes.Equal(s1[0].Digest(), s2[0].Digest()) {
		t.Errorf("digests differ after permutation:\n%s\n%s", s1[0].Hex(), s2[0].Hex())
	}
}

// TestSummarizeRRsetOwnerCase verifies that owner name case does not
// affect the content summary.
func TestSummarizeRRsetOwnerCase(t *testing.T) {
	mkRR := func(name string) RR {
		return &A{Hdr: RR_Header{Name: name, Rrtype: TypeA, Class: ClassINET, Ttl: 3600}, A: []byte{1, 2, 3, 4}}
	}

	rrs1 := []RR{mkRR("EXAMPLE.COM.")}
	rrs2 := []RR{mkRR("example.com.")}
	rrs3 := []RR{mkRR("Example.COM")}

	s1, err := SummarizeRRsets(rrs1)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := SummarizeRRsets(rrs2)
	if err != nil {
		t.Fatal(err)
	}
	s3, err := SummarizeRRsets(rrs3)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(s1[0].Digest(), s2[0].Digest()) {
		t.Error("digests differ for EXAMPLE.COM. vs example.com.")
	}
	if !bytes.Equal(s1[0].Digest(), s3[0].Digest()) {
		t.Error("digests differ for EXAMPLE.COM. vs Example.COM")
	}
	if s1[0].Owner() != "example.com." {
		t.Errorf("owner = %q, want %q", s1[0].Owner(), "example.com.")
	}
}

// TestSummarizeRRsetTXTCase verifies that TXT byte case IS preserved and
// affects the content summary (TXT bytes are not normalized).
func TestSummarizeRRsetTXTCase(t *testing.T) {
	mkRR := func(txt []string) RR {
		return &TXT{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 3600}, Txt: txt}
	}

	rrs1 := []RR{mkRR([]string{"v=spf1", "include:EXAMPLE.COM"})}
	rrs2 := []RR{mkRR([]string{"v=spf1", "include:example.com"})}

	s1, err := SummarizeRRsets(rrs1)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := SummarizeRRsets(rrs2)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(s1[0].Digest(), s2[0].Digest()) {
		t.Error("digests should differ for TXT case changes, but they are equal")
	}
}

// TestSummarizeRRsetTTL verifies that TTL changes only affect the TTL
// min/max report and not the content digest.
func TestSummarizeRRsetTTL(t *testing.T) {
	mkRR := func(ttl uint32) RR {
		return &A{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeA, Class: ClassINET, Ttl: ttl}, A: []byte{1, 2, 3, 4}}
	}

	rrs1 := []RR{mkRR(3600)}
	rrs2 := []RR{mkRR(7200)}
	rrs3 := []RR{mkRR(1800), mkRR(7200)}

	s1, err := SummarizeRRsets(rrs1)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := SummarizeRRsets(rrs2)
	if err != nil {
		t.Fatal(err)
	}
	s3, err := SummarizeRRsets(rrs3)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(s1[0].Digest(), s2[0].Digest()) {
		t.Error("digests differ for TTL changes (should not)")
	}
	if !bytes.Equal(s1[0].Digest(), s3[0].Digest()) {
		t.Error("digests differ for TTL range changes (should not)")
	}
	if s1[0].TTLMin() != 3600 || s1[0].TTLMax() != 3600 {
		t.Errorf("ttl = %d-%d, want 3600-3600", s1[0].TTLMin(), s1[0].TTLMax())
	}
	if s3[0].TTLMin() != 1800 || s3[0].TTLMax() != 7200 {
		t.Errorf("ttl = %d-%d, want 1800-7200", s3[0].TTLMin(), s3[0].TTLMax())
	}
}

// TestSummarizeRRsetMXTarget verifies that the MX target domain is also
// normalized (not just the owner).
func TestSummarizeRRsetMXTarget(t *testing.T) {
	mkRR := func(target string) RR {
		return &MX{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeMX, Class: ClassINET, Ttl: 3600}, Mx: target}
	}

	rrs1 := []RR{mkRR("MAIL.EXAMPLE.COM.")}
	rrs2 := []RR{mkRR("mail.example.com.")}
	rrs3 := []RR{mkRR("mail.example.com")}

	s1, err := SummarizeRRsets(rrs1)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := SummarizeRRsets(rrs2)
	if err != nil {
		t.Fatal(err)
	}
	s3, err := SummarizeRRsets(rrs3)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(s1[0].Digest(), s2[0].Digest()) {
		t.Error("digests differ for MX target case changes")
	}
	if !bytes.Equal(s1[0].Digest(), s3[0].Digest()) {
		t.Error("digests differ for MX target FQDN changes")
	}
}

// TestSummarizeRRsetEscapedNames verifies that escaped names (including
// escaped bytes and escaped dots) are normalized correctly.
func TestSummarizeRRsetEscapedNames(t *testing.T) {
	mkRR := func(name string) RR {
		return &A{Hdr: RR_Header{Name: name, Rrtype: TypeA, Class: ClassINET, Ttl: 3600}, A: []byte{1, 2, 3, 4}}
	}

	// \065 is the escape sequence for byte 0x41 ('A').
	rrs1 := []RR{mkRR(`\065XAMPLE.COM.`)}
	rrs2 := []RR{mkRR(`axample.com.`)}

	s1, err := SummarizeRRsets(rrs1)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := SummarizeRRsets(rrs2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(s1[0].Digest(), s2[0].Digest()) {
		t.Errorf("digests differ for escaped byte name:\n%s\n%s", s1[0].Hex(), s2[0].Hex())
	}

	// Escaped dot: EX\.AMPLE.COM. has a literal dot in the first label.
	rrs3 := []RR{mkRR(`EX\.AMPLE.COM.`)}
	rrs4 := []RR{mkRR(`ex\.ample.com.`)}

	s3, err := SummarizeRRsets(rrs3)
	if err != nil {
		t.Fatal(err)
	}
	s4, err := SummarizeRRsets(rrs4)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(s3[0].Digest(), s4[0].Digest()) {
		t.Errorf("digests differ for escaped dot name:\n%s\n%s", s3[0].Hex(), s4[0].Hex())
	}
}

// TestSummarizeRRsetTypeMixing verifies that RRs of different types are
// grouped separately.
func TestSummarizeRRsetTypeMixing(t *testing.T) {
	rrs := []RR{
		&A{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeA, Class: ClassINET, Ttl: 3600}, A: []byte{1, 2, 3, 4}},
		&NS{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeNS, Class: ClassINET, Ttl: 3600}, Ns: "ns1.example.com."},
		&MX{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeMX, Class: ClassINET, Ttl: 3600}, Mx: "mail.example.com."},
	}

	summaries, err := SummarizeRRsets(rrs)
	if err != nil {
		t.Fatal(err)
	}

	if len(summaries) != 3 {
		t.Fatalf("expected 3 summaries, got %d", len(summaries))
	}

	// Verify sorted by type.
	expectedTypes := []uint16{TypeA, TypeNS, TypeMX}
	for i, s := range summaries {
		if s.Type() != expectedTypes[i] {
			t.Errorf("summary %d: type = %d, want %d", i, s.Type(), expectedTypes[i])
		}
	}

	// Verify all owners are the same.
	for _, s := range summaries {
		if s.Owner() != "example.com." {
			t.Errorf("owner = %q, want %q", s.Owner(), "example.com.")
		}
	}
}

// TestSummarizeRRsetUnknownType verifies that unknown types are rejected.
func TestSummarizeRRsetUnknownType(t *testing.T) {
	// RFC3597 is the unknown RR representation.
	rrs := []RR{
		&RFC3597{Hdr: RR_Header{Name: "example.com.", Rrtype: 99, Class: ClassINET, Ttl: 3600}},
	}

	_, err := SummarizeRRsets(rrs)
	if err == nil {
		t.Error("expected error for unknown type, got nil")
	}
}

// TestSummarizeRRsetInputNotModified verifies that the input RRs and
// their TTLs are not modified.
func TestSummarizeRRsetInputNotModified(t *testing.T) {
	rr := &MX{
		Hdr: RR_Header{Name: "EXAMPLE.COM.", Rrtype: TypeMX, Class: ClassINET, Ttl: 3600},
		Mx:  "MAIL.EXAMPLE.COM.",
	}

	_, err := SummarizeRRsets([]RR{rr})
	if err != nil {
		t.Fatal(err)
	}

	if rr.Hdr.Name != "EXAMPLE.COM." {
		t.Errorf("owner modified: %q, want %q", rr.Hdr.Name, "EXAMPLE.COM.")
	}
	if rr.Mx != "MAIL.EXAMPLE.COM." {
		t.Errorf("MX target modified: %q, want %q", rr.Mx, "MAIL.EXAMPLE.COM.")
	}
	if rr.Hdr.Ttl != 3600 {
		t.Errorf("TTL modified: %d, want %d", rr.Hdr.Ttl, 3600)
	}
}

// TestSummarizeRRsetEmpty verifies that an empty input returns an empty
// summary list.
func TestSummarizeRRsetEmpty(t *testing.T) {
	summaries, err := SummarizeRRsets(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 0 {
		t.Errorf("expected 0 summaries, got %d", len(summaries))
	}
}

// TestSummarizeRRsetAllTypes verifies that all explicitly supported
// types can be summarized.
func TestSummarizeRRsetAllTypes(t *testing.T) {
	rrs := []RR{
		&A{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeA, Class: ClassINET, Ttl: 3600}, A: []byte{1, 2, 3, 4}},
		&AAAA{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeAAAA, Class: ClassINET, Ttl: 3600}, AAAA: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
		&NS{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeNS, Class: ClassINET, Ttl: 3600}, Ns: "ns1.example.com."},
		&CNAME{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeCNAME, Class: ClassINET, Ttl: 3600}, Target: "target.example.com."},
		&MX{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeMX, Class: ClassINET, Ttl: 3600}, Mx: "mail.example.com."},
		&SRV{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeSRV, Class: ClassINET, Ttl: 3600}, Target: "srv.example.com."},
		&SOA{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeSOA, Class: ClassINET, Ttl: 3600}, Ns: "ns1.example.com.", Mbox: "admin.example.com."},
		&TXT{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 3600}, Txt: []string{"hello"}},
	}

	summaries, err := SummarizeRRsets(rrs)
	if err != nil {
		t.Fatal(err)
	}

	if len(summaries) != len(rrs) {
		t.Fatalf("expected %d summaries, got %d", len(rrs), len(summaries))
	}
}

// TestSummarizeRRsetHexReport demonstrates the hex report output.
func TestSummarizeRRsetHexReport(t *testing.T) {
	rrs := []RR{
		&A{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeA, Class: ClassINET, Ttl: 3600}, A: []byte{1, 2, 3, 4}},
		&A{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeA, Class: ClassINET, Ttl: 7200}, A: []byte{5, 6, 7, 8}},
	}

	summaries, err := SummarizeRRsets(rrs)
	if err != nil {
		t.Fatal(err)
	}

	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}

	hex := summaries[0].Hex()
	fmt.Printf("Hex report:\n%s\n", hex)

	// Verify the report contains expected fields.
	if !bytes.Contains([]byte(hex), []byte("owner:")) {
		t.Error("hex report missing owner field")
	}
	if !bytes.Contains([]byte(hex), []byte("digest:")) {
		t.Error("hex report missing digest field")
	}
	if !bytes.Contains([]byte(hex), []byte("ttl:")) {
		t.Error("hex report missing ttl field")
	}
}
