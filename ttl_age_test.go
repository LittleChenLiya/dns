package dns

import (
	"net"
	"testing"
	"time"
)

func newTestMsg() *Msg {
	return &Msg{
		Answer: []RR{
			&A{Hdr: RR_Header{Name: "example.org.", Rrtype: TypeA, Class: ClassINET, Ttl: 5}, A: net.ParseIP("192.0.2.1")},
			&A{Hdr: RR_Header{Name: "example.org.", Rrtype: TypeA, Class: ClassINET, Ttl: 9}, A: net.ParseIP("192.0.2.2")},
		},
		Ns: []RR{
			&NS{Hdr: RR_Header{Name: "example.org.", Rrtype: TypeNS, Class: ClassINET, Ttl: 100}, Ns: "ns.example.org."},
		},
		Extra: []RR{
			&OPT{Hdr: RR_Header{Name: ".", Rrtype: TypeOPT, Class: 4096, Ttl: 0x00100000}},
			&A{Hdr: RR_Header{Name: "ns.example.org.", Rrtype: TypeA, Class: ClassINET, Ttl: 200}, A: net.ParseIP("192.0.2.3")},
		},
	}
}

// TestAgeTTLBasic verifies the acceptance scenario: TTLs 5 and 9 aged by 3
// seconds become 2 and 6, while the original message is untouched.
func TestAgeTTLBasic(t *testing.T) {
	m := newTestMsg()

	aged, summary, err := AgeTTL(m, 3*time.Second)
	if err != nil {
		t.Fatalf("AgeTTL: %v", err)
	}

	wantAged := []uint32{2, 6}
	for i, want := range wantAged {
		if got := aged.Answer[i].Header().Ttl; got != want {
			t.Errorf("aged Answer[%d] TTL = %d, want %d", i, got, want)
		}
	}
	if got := aged.Ns[0].Header().Ttl; got != 97 {
		t.Errorf("aged Ns[0] TTL = %d, want 97", got)
	}
	if got := aged.Extra[1].Header().Ttl; got != 197 {
		t.Errorf("aged Extra[1] TTL = %d, want 197", got)
	}

	wantOrig := []uint32{5, 9}
	for i, want := range wantOrig {
		if got := m.Answer[i].Header().Ttl; got != want {
			t.Errorf("original Answer[%d] TTL = %d, want %d (must not change)", i, got, want)
		}
	}
	if got := m.Ns[0].Header().Ttl; got != 100 {
		t.Errorf("original Ns[0] TTL = %d, want 100 (must not change)", got)
	}

	if summary.MinTTL != 2 {
		t.Errorf("summary.MinTTL = %d, want 2", summary.MinTTL)
	}
	if summary.Expired {
		t.Errorf("summary.Expired = true, want false")
	}
}

// TestAgeTTLOPTAndRRSIG verifies that OPT TTL fields (extended rcode/version/
// flags) and RRSIG OriginalTtl fields are not aged.
func TestAgeTTLOPTAndRRSIG(t *testing.T) {
	m := &Msg{
		Answer: []RR{
			&RRSIG{
				Hdr:         RR_Header{Name: "example.org.", Rrtype: TypeRRSIG, Class: ClassINET, Ttl: 300},
				TypeCovered: TypeA,
				Algorithm:   8,
				Labels:      2,
				OrigTtl:     300,
				Expiration:  1767225600,
				Inception:   1767225600,
				KeyTag:      12345,
				SignerName:  "example.org.",
				Signature:   "AAAA",
			},
		},
		Extra: []RR{
			&OPT{Hdr: RR_Header{Name: ".", Rrtype: TypeOPT, Class: 4096, Ttl: 0x00100000}},
		},
	}

	aged, _, err := AgeTTL(m, 100*time.Second)
	if err != nil {
		t.Fatalf("AgeTTL: %v", err)
	}

	if got := aged.Answer[0].Header().Ttl; got != 200 {
		t.Errorf("aged RRSIG TTL = %d, want 200", got)
	}
	if got := aged.Answer[0].(*RRSIG).OrigTtl; got != 300 {
		t.Errorf("aged RRSIG OrigTtl = %d, want 300", got)
	}
	if got := aged.Extra[0].Header().Ttl; got != 0x00100000 {
		t.Errorf("aged OPT TTL = %#x, want 0x00100000", got)
	}

	if got := m.Answer[0].Header().Ttl; got != 300 {
		t.Errorf("original RRSIG TTL = %d, want 300", got)
	}
	if got := m.Answer[0].(*RRSIG).OrigTtl; got != 300 {
		t.Errorf("original RRSIG OrigTtl = %d, want 300", got)
	}
	if got := m.Extra[0].Header().Ttl; got != 0x00100000 {
		t.Errorf("original OPT TTL = %#x, want 0x00100000", got)
	}
}

// TestAgeTTLNegativeRejected verifies that a negative elapsed duration is
// rejected.
func TestAgeTTLNegativeRejected(t *testing.T) {
	m := newTestMsg()
	if _, _, err := AgeTTL(m, -1*time.Second); err == nil {
		t.Errorf("AgeTTL(-1s) error = nil, want error")
	}
	if got := m.Answer[0].Header().Ttl; got != 5 {
		t.Errorf("original Answer[0] TTL = %d, want 5", got)
	}
}

// TestAgeTTLSaturates verifies that an elapsed duration larger than any TTL
// saturates every TTL to 0 and reports the answer as expired.
func TestAgeTTLSaturates(t *testing.T) {
	m := newTestMsg()
	aged, summary, err := AgeTTL(m, 10*time.Second)
	if err != nil {
		t.Fatalf("AgeTTL: %v", err)
	}
	for i, rr := range aged.Answer {
		if got := rr.Header().Ttl; got != 0 {
			t.Errorf("aged Answer[%d] TTL = %d, want 0", i, got)
		}
	}
	if summary.MinTTL != 0 {
		t.Errorf("summary.MinTTL = %d, want 0", summary.MinTTL)
	}
	if !summary.Expired {
		t.Errorf("summary.Expired = false, want true")
	}
}

// TestAgeTTLOversized verifies that an oversized elapsed duration saturates
// every TTL to 0.
func TestAgeTTLOversized(t *testing.T) {
	m := newTestMsg()
	aged, summary, err := AgeTTL(m, 100*time.Hour)
	if err != nil {
		t.Fatalf("AgeTTL: %v", err)
	}
	for _, section := range [][]RR{aged.Answer, aged.Ns, aged.Extra} {
		for _, rr := range section {
			if _, ok := rr.(*OPT); ok {
				continue
			}
			if got := rr.Header().Ttl; got != 0 {
				t.Errorf("aged TTL = %d, want 0", got)
			}
		}
	}
	if !summary.Expired {
		t.Errorf("summary.Expired = false, want true")
	}
}

// TestAgeTTLSubSecondRounding verifies the API rounding rule: sub-second
// parts are truncated (rounded down).
func TestAgeTTLSubSecondRounding(t *testing.T) {
	m := &Msg{
		Answer: []RR{
			&A{Hdr: RR_Header{Name: "example.org.", Rrtype: TypeA, Class: ClassINET, Ttl: 10}, A: net.ParseIP("192.0.2.1")},
		},
	}
	aged, summary, err := AgeTTL(m, 3500*time.Millisecond)
	if err != nil {
		t.Fatalf("AgeTTL: %v", err)
	}
	if got := aged.Answer[0].Header().Ttl; got != 7 {
		t.Errorf("aged TTL = %d, want 7 (sub-seconds truncated)", got)
	}
	if summary.MinTTL != 7 {
		t.Errorf("summary.MinTTL = %d, want 7", summary.MinTTL)
	}
}

// TestAgeTTLCopyIsolation verifies that mutating the aged copy does not
// affect the original message.
func TestAgeTTLCopyIsolation(t *testing.T) {
	m := newTestMsg()
	aged, _, err := AgeTTL(m, 3*time.Second)
	if err != nil {
		t.Fatalf("AgeTTL: %v", err)
	}

	aged.Answer[0].Header().Ttl = 12345
	aged.Answer[0].(*A).A = net.ParseIP("10.0.0.1")
	aged.Ns[0].Header().Ttl = 54321

	if got := m.Answer[0].Header().Ttl; got != 5 {
		t.Errorf("original Answer[0] TTL = %d, want 5", got)
	}
	if got := m.Answer[0].(*A).A.String(); got != "192.0.2.1" {
		t.Errorf("original Answer[0] A = %s, want 192.0.2.1", got)
	}
	if got := m.Ns[0].Header().Ttl; got != 100 {
		t.Errorf("original Ns[0] TTL = %d, want 100", got)
	}
}

// TestAgeTTLPackUnpack verifies that both the original and the aged message
// can be packed and unpacked without losing protocol fields.
func TestAgeTTLPackUnpack(t *testing.T) {
	m := newTestMsg()
	m.Extra = append(m.Extra,
		&RRSIG{
			Hdr:         RR_Header{Name: "example.org.", Rrtype: TypeRRSIG, Class: ClassINET, Ttl: 300},
			TypeCovered: TypeA,
			Algorithm:   8,
			Labels:      2,
			OrigTtl:     300,
			Expiration:  1767225600,
			Inception:   1767225600,
			KeyTag:      12345,
			SignerName:  "example.org.",
			Signature:   "AAAA",
		},
	)

	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack original: %v", err)
	}
	var orig Msg
	if err := orig.Unpack(wire); err != nil {
		t.Fatalf("Unpack original: %v", err)
	}

	aged, _, err := AgeTTL(&orig, 3*time.Second)
	if err != nil {
		t.Fatalf("AgeTTL: %v", err)
	}

	agedWire, err := aged.Pack()
	if err != nil {
		t.Fatalf("Pack aged: %v", err)
	}
	var agedUnpacked Msg
	if err := agedUnpacked.Unpack(agedWire); err != nil {
		t.Fatalf("Unpack aged: %v", err)
	}

	if got := agedUnpacked.Answer[0].Header().Ttl; got != 2 {
		t.Errorf("aged Answer[0] TTL after round trip = %d, want 2", got)
	}
	if got := agedUnpacked.Answer[1].Header().Ttl; got != 6 {
		t.Errorf("aged Answer[1] TTL after round trip = %d, want 6", got)
	}
	if got := agedUnpacked.Extra[0].Header().Ttl; got != 0x00100000 {
		t.Errorf("aged OPT TTL after round trip = %#x, want 0x00100000", got)
	}
	if got := agedUnpacked.Extra[2].(*RRSIG).OrigTtl; got != 300 {
		t.Errorf("aged RRSIG OrigTtl after round trip = %d, want 300", got)
	}

	if got := orig.Answer[0].Header().Ttl; got != 5 {
		t.Errorf("original Answer[0] TTL = %d, want 5 (must not change)", got)
	}
}

// TestAgeTTLNilMessage verifies that a nil message is rejected.
func TestAgeTTLNilMessage(t *testing.T) {
	if _, _, err := AgeTTL(nil, 3*time.Second); err == nil {
		t.Errorf("AgeTTL(nil) error = nil, want error")
	}
}
