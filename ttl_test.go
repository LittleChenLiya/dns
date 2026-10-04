package dns

import (
	"testing"
	"time"
)

func optPseudo(udpSize uint16, do bool, options []EDNS0) *OPT {
	opt := &OPT{Hdr: RR_Header{Name: ".", Rrtype: TypeOPT}, Option: options}
	opt.SetUDPSize(udpSize)
	if do {
		opt.SetDo()
	}
	return opt
}

func newAgedTestMsg() *Msg {
	return &Msg{
		MsgHdr: MsgHdr{
			Id:                 42,
			Response:           true,
			RecursionDesired:   true,
			RecursionAvailable: true,
		},
		Question: []Question{
			{Name: "example.org.", Qtype: TypeA, Qclass: ClassINET},
		},
		Answer: []RR{
			optPseudo(1232, true, []EDNS0{&EDNS0_NSID{Code: EDNS0NSID, Nsid: "666f6f"}}),
			&A{Hdr: RR_Header{Name: "example.org.", Rrtype: TypeA, Class: ClassINET, Ttl: 5},
				A: []byte{192, 0, 2, 1}},
			&A{Hdr: RR_Header{Name: "example.org.", Rrtype: TypeA, Class: ClassINET, Ttl: 9},
				A: []byte{192, 0, 2, 2}},
			&RRSIG{Hdr: RR_Header{Name: "example.org.", Rrtype: TypeRRSIG, Class: ClassINET, Ttl: 9},
				TypeCovered: TypeA, Algorithm: 13, Labels: 1, OrigTtl: 3600,
				Expiration: 4000000000, Inception: 3999990000, KeyTag: 1234,
				SignerName: "example.org.", Signature: "ZmFrZXNpZw=="},
		},
		Ns: []RR{
			&NS{Hdr: RR_Header{Name: "example.org.", Rrtype: TypeNS, Class: ClassINET, Ttl: 10},
				Ns: "ns1.example.org."},
		},
		Extra: []RR{
			&AAAA{Hdr: RR_Header{Name: "ns1.example.org.", Rrtype: TypeAAAA, Class: ClassINET, Ttl: 20},
				AAAA: []byte{0x20, 0x01, 0xdb, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		},
	}
}

func TestMsgAgeBasic(t *testing.T) {
	original := newAgedTestMsg()

	// Baseline: the original can be packed and unpacked before aging.
	origWire, err := original.Pack()
	if err != nil {
		t.Fatalf("original pack before age: %v", err)
	}
	var roundtrip Msg
	if err := roundtrip.Unpack(origWire); err != nil {
		t.Fatalf("original unpack before age: %v", err)
	}

	aged, summary, err := original.Age(3 * time.Second)
	if err != nil {
		t.Fatalf("Age returned error: %v", err)
	}

	// Acceptance: TTLs 5 and 9 become 2 and 6.
	if got := aged.Answer[1].Header().Ttl; got != 2 {
		t.Errorf("first answer TTL = %d, want 2", got)
	}
	if got := aged.Answer[2].Header().Ttl; got != 6 {
		t.Errorf("second answer TTL = %d, want 6", got)
	}

	// Authority and additional sections are aged too.
	if got := aged.Ns[0].Header().Ttl; got != 7 {
		t.Errorf("authority TTL = %d, want 7", got)
	}
	if got := aged.Extra[0].Header().Ttl; got != 17 {
		t.Errorf("additional TTL = %d, want 17", got)
	}

	// RRSIG header TTL ages, OrigTtl must not change.
	rrsig := aged.Answer[3].(*RRSIG)
	if got := rrsig.Hdr.Ttl; got != 6 {
		t.Errorf("RRSIG header TTL = %d, want 6", got)
	}
	if got := rrsig.OrigTtl; got != 3600 {
		t.Errorf("RRSIG OrigTtl = %d, want 3600", got)
	}

	// OPT pseudo-record must not be aged; its extended information survives.
	// The header TTL word carries extended-RCODE/version/flags: bit 0x8000 is DO.
	opt := aged.Answer[0].(*OPT)
	if opt.Hdr.Ttl != original.Answer[0].Header().Ttl || opt.Hdr.Ttl != 0x8000 {
		t.Errorf("OPT header TTL word changed: aged %d, original %d", opt.Hdr.Ttl, original.Answer[0].Header().Ttl)
	}
	if opt.UDPSize() != 1232 || !opt.Do() || opt.Version() != 0 {
		t.Errorf("OPT fields corrupted: %+v", opt)
	}
	if len(opt.Option) != 1 {
		t.Fatalf("OPT options = %d, want 1", len(opt.Option))
	}
	if nsid, ok := opt.Option[0].(*EDNS0_NSID); !ok || nsid.Nsid != "666f6f" {
		t.Errorf("OPT NSID option corrupted: %#v", opt.Option[0])
	}

	// Summary: minimum valid remaining TTL, not expired.
	if summary.MinTtl != 2 {
		t.Errorf("summary MinTtl = %d, want 2", summary.MinTtl)
	}
	if summary.Expired {
		t.Errorf("summary Expired = true, want false")
	}

	// The cached original message must be untouched.
	if got := original.Answer[1].Header().Ttl; got != 5 {
		t.Errorf("original first answer TTL = %d, want 5", got)
	}
	if got := original.Answer[2].Header().Ttl; got != 9 {
		t.Errorf("original second answer TTL = %d, want 9", got)
	}
	if got := original.Answer[3].(*RRSIG).OrigTtl; got != 3600 {
		t.Errorf("original RRSIG OrigTtl = %d, want 3600", got)
	}
	if got := original.Ns[0].Header().Ttl; got != 10 {
		t.Errorf("original authority TTL = %d, want 10", got)
	}
	if got := original.Extra[0].Header().Ttl; got != 20 {
		t.Errorf("original additional TTL = %d, want 20", got)
	}

	// The aged message can be packed and unpacked and keeps the aged TTLs.
	agedWire, err := aged.Pack()
	if err != nil {
		t.Fatalf("aged pack: %v", err)
	}
	var agedRT Msg
	if err := agedRT.Unpack(agedWire); err != nil {
		t.Fatalf("aged unpack: %v", err)
	}
	if got := agedRT.Answer[1].Header().Ttl; got != 2 {
		t.Errorf("roundtripped first answer TTL = %d, want 2", got)
	}
	if got := agedRT.Answer[2].Header().Ttl; got != 6 {
		t.Errorf("roundtripped second answer TTL = %d, want 6", got)
	}
	if got := agedRT.Answer[3].(*RRSIG).OrigTtl; got != 3600 {
		t.Errorf("roundtripped RRSIG OrigTtl = %d, want 3600", got)
	}
	if optRT, ok := agedRT.Answer[0].(*OPT); !ok || optRT.UDPSize() != 1232 || !optRT.Do() {
		t.Errorf("roundtripped OPT corrupted: %#v", agedRT.Answer[0])
	}

	// Original remains packable with byte-identical wire format.
	origWire2, err := original.Pack()
	if err != nil {
		t.Fatalf("original pack after age: %v", err)
	}
	if string(origWire) != string(origWire2) {
		t.Errorf("original message wire format changed after Age")
	}
}

func TestMsgAgeNegative(t *testing.T) {
	original := newAgedTestMsg()
	aged, summary, err := original.Age(-1 * time.Second)
	if err == nil {
		t.Fatal("Age with negative elapsed did not error")
	}
	if aged != nil {
		t.Errorf("aged message should be nil on error, got %#v", aged)
	}
	if summary.MinTtl != 0 || summary.Expired {
		t.Errorf("summary on error should be zero value, got %+v", summary)
	}
	// Original must remain intact.
	if got := original.Answer[1].Header().Ttl; got != 5 {
		t.Errorf("original first answer TTL = %d, want 5", got)
	}
}

func TestMsgAgeHugeElapsedSaturates(t *testing.T) {
	original := newAgedTestMsg()
	aged, summary, err := original.Age(time.Duration(1 << 62))
	if err != nil {
		t.Fatalf("Age with huge elapsed: %v", err)
	}
	for i, r := range aged.Answer {
		if r.Header().Rrtype == TypeOPT {
			if r.Header().Ttl != original.Answer[i].Header().Ttl {
				t.Errorf("OPT at index %d altered: aged %d, original %d", i, r.Header().Ttl, original.Answer[i].Header().Ttl)
			}
			continue
		}
		if got := r.Header().Ttl; got != 0 {
			t.Errorf("answer %d TTL = %d, want 0", i, got)
		}
	}
	if got := aged.Ns[0].Header().Ttl; got != 0 {
		t.Errorf("authority TTL = %d, want 0", got)
	}
	if got := aged.Extra[0].Header().Ttl; got != 0 {
		t.Errorf("additional TTL = %d, want 0", got)
	}
	if rrsig := aged.Answer[3].(*RRSIG); rrsig.OrigTtl != 3600 {
		t.Errorf("RRSIG OrigTtl = %d, want 3600", rrsig.OrigTtl)
	}
	if summary.MinTtl != 0 {
		t.Errorf("summary MinTtl = %d, want 0", summary.MinTtl)
	}
	if !summary.Expired {
		t.Errorf("summary Expired = false, want true")
	}
}

func TestMsgAgeTruncation(t *testing.T) {
	// Sub-second portions are truncated toward zero for non-negative durations.
	original := newAgedTestMsg()
	aged, summary, err := original.Age(3900 * time.Millisecond)
	if err != nil {
		t.Fatalf("Age: %v", err)
	}
	if got := aged.Answer[1].Header().Ttl; got != 2 {
		t.Errorf("first answer TTL = %d, want 2", got)
	}
	if summary.MinTtl != 2 || summary.Expired {
		t.Errorf("unexpected summary: %+v", summary)
	}
}

func TestMsgAgeExpiryBoundary(t *testing.T) {
	original := newAgedTestMsg()
	// Elapsed equal to the smallest TTL (5) saturates it to 0, so it expired.
	aged, summary, err := original.Age(5 * time.Second)
	if err != nil {
		t.Fatalf("Age: %v", err)
	}
	if got := aged.Answer[1].Header().Ttl; got != 0 {
		t.Errorf("first answer TTL = %d, want 0", got)
	}
	if got := aged.Answer[2].Header().Ttl; got != 4 {
		t.Errorf("second answer TTL = %d, want 4", got)
	}
	if summary.MinTtl != 0 || !summary.Expired {
		t.Errorf("unexpected summary: %+v", summary)
	}
}

func TestMsgAgeEmpty(t *testing.T) {
	original := new(Msg)
	aged, summary, err := original.Age(10 * time.Second)
	if err != nil {
		t.Fatalf("Age: %v", err)
	}
	if summary.MinTtl != 0 || summary.Expired {
		t.Errorf("empty message summary = %+v, want zero value", summary)
	}
	if aged == nil {
		t.Errorf("aged message should not be nil")
	}
	// An OPT-only message also yields an empty, non-expired summary.
	optOnly := &Msg{Extra: []RR{optPseudo(4096, false, nil)}}
	agedOpt, summaryOpt, err := optOnly.Age(time.Duration(1 << 32))
	if err != nil {
		t.Fatalf("Age: %v", err)
	}
	if summaryOpt.MinTtl != 0 || summaryOpt.Expired {
		t.Errorf("OPT-only summary = %+v, want zero value", summaryOpt)
	}
	if agedOpt.Extra[0].(*OPT).UDPSize() != 4096 {
		t.Errorf("OPT UDPSize altered: %d", agedOpt.Extra[0].(*OPT).UDPSize())
	}
}
