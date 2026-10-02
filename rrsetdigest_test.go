package dns

import (
	"strings"
	"testing"
)

func mustRRs(t *testing.T, rrs ...string) []RR {
	t.Helper()
	out := make([]RR, 0, len(rrs))
	for _, s := range rrs {
		rr, err := NewRR(s)
		if err != nil {
			t.Fatalf("NewRR(%q): %v", s, err)
		}
		out = append(out, rr)
	}
	return out
}

func mustDigest(t *testing.T, rrs ...string) RRsetDigest {
	t.Helper()
	d, err := DigestRRset(mustRRs(t, rrs...))
	if err != nil {
		t.Fatalf("DigestRRset: %v", err)
	}
	return d
}

// Different record orderings and owner-name case must yield the same digest.
func TestDigestRRsetOrderAndOwnerCase(t *testing.T) {
	d1 := mustDigest(t,
		"WWW.Example.COM. 300 IN A 192.0.2.1",
		"WWW.Example.COM. 300 IN A 192.0.2.2",
	)
	d2 := mustDigest(t,
		"www.example.com. 300 IN A 192.0.2.2",
		"www.example.com. 300 IN A 192.0.2.1",
	)
	if d1.Sum != d2.Sum {
		t.Fatalf("digest differs for reordered/recased RRset:\n%s\n%s", d1.Hex(), d2.Hex())
	}
	if d1.Owner != "www.example.com." {
		t.Fatalf("owner not canonicalized: %q", d1.Owner)
	}
	if d1.Records != 2 {
		t.Fatalf("Records = %d, want 2", d1.Records)
	}
}

// MX (and other domain-name RDATA) targets must be normalized, not just the
// owner name.
func TestDigestRRsetRdataNameCase(t *testing.T) {
	d1 := mustDigest(t,
		"example.com. 300 IN MX 10 Mail.Example.COM.",
		"example.com. 300 IN MX 20 mail2.example.com.",
	)
	d2 := mustDigest(t,
		"example.com. 300 IN MX 20 MAIL2.EXAMPLE.COM.",
		"example.com. 300 IN MX 10 mail.example.com.",
	)
	if d1.Sum != d2.Sum {
		t.Fatalf("MX target case leaked into digest:\n%s\n%s", d1.Hex(), d2.Hex())
	}

	s1 := mustDigest(t, "example.com. 300 IN SOA NS1.EXAMPLE.com. Hostmaster.EXAMPLE.com. 1 7200 3600 1209600 300")
	s2 := mustDigest(t, "example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300")
	if s1.Sum != s2.Sum {
		t.Fatalf("SOA MNAME/RNAME case leaked into digest")
	}

	v1 := mustDigest(t, "_sip._tcp.example.com. 300 IN SRV 10 60 5060 SIP.EXAMPLE.com.")
	v2 := mustDigest(t, "_sip._tcp.example.com. 300 IN SRV 10 60 5060 sip.example.com.")
	if v1.Sum != v2.Sum {
		t.Fatalf("SRV target case leaked into digest")
	}
}

// TXT data is byte-exact: case changes must change the digest.
func TestDigestRRsetTXTCaseSensitive(t *testing.T) {
	d1 := mustDigest(t, "example.com. 300 IN TXT \"Hello World\"")
	d2 := mustDigest(t, "example.com. 300 IN TXT \"hello world\"")
	if d1.Sum == d2.Sum {
		t.Fatalf("TXT case change must change the digest")
	}
	d3 := mustDigest(t, "example.com. 300 IN TXT \"Hello World\"")
	if d1.Sum != d3.Sum {
		t.Fatalf("identical TXT must give identical digest")
	}
}

// TTL is not part of the content identity; it only shows up in MinTTL/MaxTTL.
func TestDigestRRsetTTLExcluded(t *testing.T) {
	d1 := mustDigest(t,
		"www.example.com. 300 IN A 192.0.2.1",
		"www.example.com. 300 IN A 192.0.2.2",
	)
	d2 := mustDigest(t,
		"www.example.com. 60 IN A 192.0.2.1",
		"www.example.com. 3600 IN A 192.0.2.2",
	)
	if d1.Sum != d2.Sum {
		t.Fatalf("TTL leaked into digest")
	}
	if d2.MinTTL != 60 || d2.MaxTTL != 3600 {
		t.Fatalf("MinTTL/MaxTTL = %d/%d, want 60/3600", d2.MinTTL, d2.MaxTTL)
	}
	if d1.MinTTL != 300 || d1.MaxTTL != 300 {
		t.Fatalf("MinTTL/MaxTTL = %d/%d, want 300/300", d1.MinTTL, d1.MaxTTL)
	}
}

// Escaped owner names: \065 is 'A' and must normalize to 'a'; escaped
// spaces and dots must survive normalization.
func TestDigestRRsetEscapedNames(t *testing.T) {
	d1 := mustDigest(t, `www.\065bc.example. 300 IN A 192.0.2.1`)
	d2 := mustDigest(t, `www.abc.example. 300 IN A 192.0.2.1`)
	if d1.Sum != d2.Sum {
		t.Fatalf(`\065 escape not normalized to 'a'`)
	}
	if d1.Owner != "www.abc.example." {
		t.Fatalf("owner = %q, want www.abc.example.", d1.Owner)
	}

	e1 := mustDigest(t, `weird\032name.example. 300 IN TXT "x"`)
	e2 := mustDigest(t, `weird\032NAME.example. 300 IN TXT "x"`)
	if e1.Sum != e2.Sum {
		t.Fatalf("escaped space name with case change must digest equally")
	}
	if !strings.Contains(e1.Owner, `\032`) && !strings.Contains(e1.Owner, " ") {
		t.Fatalf("escaped space lost in owner: %q", e1.Owner)
	}
}

// Duplicate RRs collapse; dedupe must not change the digest.
func TestDigestRRsetDedup(t *testing.T) {
	d1 := mustDigest(t, "www.example.com. 300 IN A 192.0.2.1")
	d2 := mustDigest(t,
		"www.example.com. 300 IN A 192.0.2.1",
		"WWW.EXAMPLE.COM. 300 IN A 192.0.2.1",
	)
	if d1.Sum != d2.Sum {
		t.Fatalf("duplicate records changed the digest")
	}
	if d2.Records != 1 {
		t.Fatalf("Records = %d, want 1", d2.Records)
	}
}

// Mixed types or owners in one set are rejected.
func TestDigestRRsetMixedSetRejected(t *testing.T) {
	if _, err := DigestRRset(mustRRs(t,
		"www.example.com. 300 IN A 192.0.2.1",
		"www.example.com. 300 IN AAAA 2001:db8::1",
	)); err == nil {
		t.Fatal("mixed A/AAAA set accepted")
	}
	if _, err := DigestRRset(mustRRs(t,
		"www.example.com. 300 IN A 192.0.2.1",
		"other.example.com. 300 IN A 192.0.2.1",
	)); err == nil {
		t.Fatal("mixed owner set accepted")
	}
	if _, err := DigestRRset(nil); err == nil {
		t.Fatal("empty RRset accepted")
	}
}

// Unknown (unsupported) types are explicitly rejected.
func TestDigestRRsetUnknownTypeRejected(t *testing.T) {
	if _, err := DigestRRset(mustRRs(t, "example.com. 300 IN CAA 0 issue \"letsencrypt.org\"")); err == nil {
		t.Fatal("CAA accepted, want rejection")
	}
	if _, err := DigestRRset(mustRRs(t, "example.com. 300 IN DNSKEY 256 3 8 AwEAAa==")); err == nil {
		t.Fatal("DNSKEY accepted, want rejection")
	}
}

// The input RRs, including TTLs, must not be modified.
func TestDigestRRsetReadOnly(t *testing.T) {
	rrs := mustRRs(t,
		"WWW.Example.COM. 300 IN MX 10 Mail.Example.COM.",
		"WWW.Example.COM. 300 IN A 192.0.2.1",
	)
	_ = rrs
	set := mustRRs(t,
		"WWW.Example.COM. 300 IN A 192.0.2.1",
		"WWW.Example.COM. 300 IN A 192.0.2.2",
	)
	before := make([]string, len(set))
	for i, rr := range set {
		before[i] = rr.String()
	}
	if _, err := DigestRRset(set); err != nil {
		t.Fatal(err)
	}
	for i, rr := range set {
		if rr.String() != before[i] {
			t.Fatalf("record %d mutated: %q -> %q", i, before[i], rr.String())
		}
		if rr.Header().Ttl != 300 {
			t.Fatalf("TTL of record %d mutated to %d", i, rr.Header().Ttl)
		}
	}
}
