package dns

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const maxPrintableLabel = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789x"

var (
	longDomain = maxPrintableLabel[:53] + strings.TrimSuffix(
		strings.Join([]string{".", ".", ".", ".", "."}, maxPrintableLabel[:49]), ".")

	reChar              = regexp.MustCompile(`.`)
	i                   = -1
	maxUnprintableLabel = reChar.ReplaceAllStringFunc(maxPrintableLabel, func(ch string) string {
		if i++; i >= 32 {
			i = 0
		}
		return fmt.Sprintf("\\%03d", i)
	})

	// These are the longest possible domain names in presentation format.
	longestDomain            = maxPrintableLabel[:61] + strings.Join([]string{".", ".", ".", "."}, maxPrintableLabel)
	longestUnprintableDomain = maxUnprintableLabel[:61*4] + strings.Join([]string{".", ".", ".", "."}, maxUnprintableLabel)
)

func TestPackNoSideEffect(t *testing.T) {
	m := new(Msg)
	m.SetQuestion(Fqdn("example.com."), TypeNS)

	a := new(Msg)
	o := &OPT{
		Hdr: RR_Header{
			Name:   ".",
			Rrtype: TypeOPT,
		},
	}
	o.SetUDPSize(DefaultMsgSize)

	a.Extra = append(a.Extra, o)
	a.SetRcode(m, RcodeBadVers)

	a.Pack()
	if a.Rcode != RcodeBadVers {
		t.Errorf("after pack: Rcode is expected to be BADVERS")
	}
}

func TestPackExtendedBadCookie(t *testing.T) {
	m := new(Msg)
	m.SetQuestion(Fqdn("example.com."), TypeNS)

	a := new(Msg)
	a.SetReply(m)
	o := &OPT{
		Hdr: RR_Header{
			Name:   ".",
			Rrtype: TypeOPT,
		},
	}
	o.SetUDPSize(DefaultMsgSize)
	a.Extra = append(a.Extra, o)

	a.SetRcode(m, RcodeBadCookie)

	edns0 := a.IsEdns0()
	if edns0 == nil {
		t.Fatal("Expected OPT RR")
	}
	// SetExtendedRcode is only called as part of `Pack()`, hence at this stage,
	// the OPT RR is not set yet.
	if edns0.ExtendedRcode() == RcodeBadCookie&0xFFFFFFF0 {
		t.Errorf("ExtendedRcode is expected to not be BADCOOKIE before Pack")
	}

	a.Pack()

	edns0 = a.IsEdns0()
	if edns0 == nil {
		t.Fatal("Expected OPT RR")
	}

	if edns0.ExtendedRcode() != RcodeBadCookie&0xFFFFFFF0 {
		t.Errorf("ExtendedRcode is expected to be BADCOOKIE after Pack")
	}
}

func TestUnPackExtendedRcode(t *testing.T) {
	m := new(Msg)
	m.SetQuestion(Fqdn("example.com."), TypeNS)

	a := new(Msg)
	a.SetReply(m)
	o := &OPT{
		Hdr: RR_Header{
			Name:   ".",
			Rrtype: TypeOPT,
		},
	}
	o.SetUDPSize(DefaultMsgSize)
	a.Extra = append(a.Extra, o)

	a.SetRcode(m, RcodeBadCookie)

	packed, err := a.Pack()
	if err != nil {
		t.Fatalf("Could not unpack %v", a)
	}

	unpacked := new(Msg)
	if err := unpacked.Unpack(packed); err != nil {
		t.Fatalf("Failed to unpack message")
	}

	if unpacked.Rcode != RcodeBadCookie {
		t.Fatalf("Rcode should be matching RcodeBadCookie (%d), got (%d)", RcodeBadCookie, unpacked.Rcode)
	}
}

func TestUnpackDomainName(t *testing.T) {
	var cases = []struct {
		label          string
		input          string
		expectedOutput string
		expectedError  string
	}{
		{"empty domain",
			"\x00",
			".",
			""},
		{"long label",
			"?" + maxPrintableLabel + "\x00",
			maxPrintableLabel + ".",
			""},
		{"unprintable label",
			"?" + regexp.MustCompile(`\\[0-9]+`).ReplaceAllStringFunc(maxUnprintableLabel,
				func(escape string) string {
					n, _ := strconv.ParseInt(escape[1:], 10, 8)
					return string(rune(n))
				}) + "\x00",
			maxUnprintableLabel + ".",
			""},
		{"long domain",
			"5" + strings.Replace(longDomain, ".", "1", -1) + "\x00",
			longDomain + ".",
			""},
		{"compression pointer",
			// an unrealistic but functional test referencing an offset _inside_ a label
			"\x03foo" + "\x05\x03com\x00" + "\x07example" + "\xC0\x05",
			"foo.\\003com\\000.example.com.",
			""},
		{"too long domain",
			"6" + "x" + strings.Replace(longDomain, ".", "1", -1) + "\x00",
			"",
			ErrLongDomain.Error()},
		{"too long by pointer",
			// a matryoshka doll name to get over 255 octets after expansion via internal pointers
			string([]byte{
				// 11 length values, first to last
				40, 37, 34, 31, 28, 25, 22, 19, 16, 13, 0,
				// 12 filler values
				120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120,
				// 10 pointers, last to first
				192, 10, 192, 9, 192, 8, 192, 7, 192, 6, 192, 5, 192, 4, 192, 3, 192, 2, 192, 1,
			}),
			"",
			ErrLongDomain.Error()},
		{"long by pointer",
			// a matryoshka doll name _not_ exceeding 255 octets after expansion
			string([]byte{
				// 11 length values, first to last
				37, 34, 31, 28, 25, 22, 19, 16, 13, 10, 0,
				// 9 filler values
				120, 120, 120, 120, 120, 120, 120, 120, 120,
				// 10 pointers, last to first
				192, 10, 192, 9, 192, 8, 192, 7, 192, 6, 192, 5, 192, 4, 192, 3, 192, 2, 192, 1,
			}),
			"" +
				(`\"\031\028\025\022\019\016\013\010\000xxxxxxxxx` +
					`\192\010\192\009\192\008\192\007\192\006\192\005\192\004\192\003\192\002.`) +
				(`\031\028\025\022\019\016\013\010\000xxxxxxxxx` +
					`\192\010\192\009\192\008\192\007\192\006\192\005\192\004\192\003.`) +
				(`\028\025\022\019\016\013\010\000xxxxxxxxx` +
					`\192\010\192\009\192\008\192\007\192\006\192\005\192\004.`) +
				(`\025\022\019\016\013\010\000xxxxxxxxx` +
					`\192\010\192\009\192\008\192\007\192\006\192\005.`) +
				`\022\019\016\013\010\000xxxxxxxxx\192\010\192\009\192\008\192\007\192\006.` +
				`\019\016\013\010\000xxxxxxxxx\192\010\192\009\192\008\192\007.` +
				`\016\013\010\000xxxxxxxxx\192\010\192\009\192\008.` +
				`\013\010\000xxxxxxxxx\192\010\192\009.` +
				`\010\000xxxxxxxxx\192\010.` +
				`\000xxxxxxxxx.`,
			""},
		{"truncated name", "\x07example\x03", "", "dns: buffer size too small"},
		{"non-absolute name", "\x07example\x03com", "", "dns: buffer size too small"},
		{"compression pointer cycle (too many)", "\xC0\x00", "", "dns: too many compression pointers"},
		{"compression pointer cycle (too long)",
			"\x03foo" + "\x03bar" + "\x07example" + "\xC0\x04",
			"",
			ErrLongDomain.Error()},
		{"forward compression pointer", "\x02\xC0\xFF\xC0\x01", "", ErrBuf.Error()},
		{"reserved compression pointer 0b10", "\x07example\x80", "", "dns: bad rdata"},
		{"reserved compression pointer 0b01", "\x07example\x40", "", "dns: bad rdata"},
	}
	for _, test := range cases {
		output, idx, err := UnpackDomainName([]byte(test.input), 0)
		if test.expectedOutput != "" && output != test.expectedOutput {
			t.Errorf("%s: expected %s, got %s", test.label, test.expectedOutput, output)
		}
		if test.expectedError == "" && err != nil {
			t.Errorf("%s: expected no error, got %d %v", test.label, idx, err)
		} else if test.expectedError != "" && (err == nil || err.Error() != test.expectedError) {
			t.Errorf("%s: expected error %s, got %d %v", test.label, test.expectedError, idx, err)
		}
	}
}

func TestUnpackDomainNameTrace(t *testing.T) {
	// A small fabricated DNS payload:
	//   offset 0: first name  "\x07example\x03com\x00" ("example.com.")
	//   offset 13: second name "\x03www\xC0\x00"       ("www.example.com.")
	msg := []byte("\x07example\x03com\x00\x03www\xC0\x00")

	t.Run("compression jump to first name", func(t *testing.T) {
		name, off, tr, err := UnpackDomainNameTrace(msg, 13)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != "www.example.com." {
			t.Fatalf("name = %q, want www.example.com.", name)
		}
		// The caller-facing offset advances only past the pointer.
		if off != 19 {
			t.Fatalf("offset = %d, want 19", off)
		}
		if tr.NextOffset != 19 {
			t.Fatalf("trace next offset = %d, want 19", tr.NextOffset)
		}
		if tr.Root != 12 {
			t.Fatalf("root = %d, want 12", tr.Root)
		}
		if tr.FailAt != -1 {
			t.Fatalf("FailAt = %d, want -1", tr.FailAt)
		}
		want := []NameStep{
			{Kind: NameStepLabel, Start: 13, End: 17, Label: []byte("www"), Target: -1},
			{Kind: NameStepPointer, Start: 17, End: 19, Target: 0},
			{Kind: NameStepLabel, Start: 0, End: 8, Label: []byte("example"), Target: -1},
			{Kind: NameStepLabel, Start: 8, End: 12, Label: []byte("com"), Target: -1},
			{Kind: NameStepRoot, Start: 12, End: 13, Target: -1},
		}
		if len(tr.Steps) != len(want) {
			t.Fatalf("steps = %d, want %d\ntrace:\n%s", len(tr.Steps), len(want), tr)
		}
		for i, st := range tr.Steps {
			w := want[i]
			if st.Kind != w.Kind || st.Start != w.Start || st.End != w.End || st.Target != w.Target ||
				string(st.Label) != string(w.Label) {
				t.Errorf("step %d = %+v, want %+v", i, st, w)
			}
			if st.Span() != w.End-w.Start {
				t.Errorf("step %d span = %d, want %d", i, st.Span(), w.End-w.Start)
			}
		}
	})

	t.Run("first name without pointer", func(t *testing.T) {
		name, off, tr, err := UnpackDomainNameTrace(msg, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != "example.com." || off != 13 || tr.NextOffset != 13 {
			t.Fatalf("got %q off=%d trace=%#v", name, off, tr)
		}
		for _, st := range tr.Steps {
			if st.Kind == NameStepPointer {
				t.Fatalf("unexpected pointer step: %+v", st)
			}
		}
	})

	t.Run("escaped presentation keeps raw span", func(t *testing.T) {
		// Label "a.b" + unprintable 0x01: presentation is "a\.b\001"
		// (6 bytes) while the raw label is only 4 wire octets.
		raw := []byte{4, 'a', '.', 'b', 0x01, 0}
		name, _, tr, err := UnpackDomainNameTrace(raw, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != `a\.b\001.` {
			t.Fatalf("name = %q, want a\\.b\\001.", name)
		}
		st := tr.Steps[0]
		if st.Kind != NameStepLabel || st.Start != 0 || st.End != 5 || len(st.Label) != 4 {
			t.Fatalf("label step = %+v, want raw span 0-5 of 4 bytes", st)
		}
		if st.Span() != 5 { // length octet + four label octets
			t.Fatalf("span = %d, want 5", st.Span())
		}
	})

	t.Run("mixed label then pointer then label", func(t *testing.T) {
		// offset 0: "\x02ns\x00"  ("ns."), offset 4: "\x03pod\xC0\x00" ("pod.ns.")
		m := []byte("\x02ns\x00\x03pod\xC0\x00")
		name, off, tr, err := UnpackDomainNameTrace(m, 4)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != "pod.ns." {
			t.Fatalf("name = %q, want pod.ns.", name)
		}
		if off != 10 {
			t.Fatalf("offset = %d, want 10", off)
		}
		kinds := []NameStepKind{NameStepLabel, NameStepPointer, NameStepLabel, NameStepRoot}
		if len(tr.Steps) != len(kinds) {
			t.Fatalf("steps = %d, want %d\ntrace:\n%s", len(tr.Steps), len(kinds), tr)
		}
		for i, k := range kinds {
			if tr.Steps[i].Kind != k {
				t.Errorf("step %d kind = %d, want %d", i, tr.Steps[i].Kind, k)
			}
		}
		// pod label 4-8 (length octet + 3 label octets), pointer 8-10 -> 0.
		if l := tr.Steps[0]; l.Start != 4 || l.End != 8 || string(l.Label) != "pod" {
			t.Errorf("label step = %+v, want 4-8 \"pod\"", l)
		}
		if p := tr.Steps[1]; p.Start != 8 || p.End != 10 || p.Target != 0 {
			t.Errorf("pointer step = %+v, want 8-10 -> 0", p)
		}
		if r := tr.Steps[3]; r.Kind != NameStepRoot || r.Start != 3 {
			t.Errorf("root step = %+v, want root at 3", r)
		}
		if shown := tr.String(); !strings.Contains(shown, "8-10 pointer -> 0") ||
			!strings.HasSuffix(shown, "name \"pod.ns.\" next offset 10") {
			t.Errorf("trace report:\n%s", shown)
		}
	})

	t.Run("self pointer does not hang", func(t *testing.T) {
		m := []byte("\xC0\x00")
		name, off, tr, err := UnpackDomainNameTrace(m, 0)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if name != "" || off != len(m) {
			t.Fatalf("name=%q off=%d, want empty name and len(msg)", name, off)
		}
		if tr.FailAt != 0 || tr.FailStep == "" {
			t.Fatalf("trace = FailAt %d step %q, want failure at offset 0", tr.FailAt, tr.FailStep)
		}
		if tr.Root != -1 {
			t.Fatalf("root = %d, want -1 for incomplete trace", tr.Root)
		}
		if n := len(tr.Steps); n == 0 || tr.Steps[n-1].Kind != NameStepPointer {
			t.Fatalf("last step = %+v, want a pointer step", tr.Steps)
		}
	})

	t.Run("pointer target out of range", func(t *testing.T) {
		m := []byte("\x03www\xC0\xFF")
		_, _, tr, err := UnpackDomainNameTrace(m, 0)
		if err != ErrBuf {
			t.Fatalf("err = %v, want %v", err, ErrBuf)
		}
		if tr.FailAt != 0xFF {
			t.Fatalf("FailAt = %d, want 255 (the real pointer target)", tr.FailAt)
		}
		if len(tr.Steps) != 2 || tr.Steps[1].Target != 0xFF {
			t.Fatalf("steps = %+v, want label then pointer to 255", tr.Steps)
		}
	})

	t.Run("truncated label reports failing node", func(t *testing.T) {
		m := []byte("\x07exa") // length promises 7 octets, only 3 follow
		_, _, tr, err := UnpackDomainNameTrace(m, 0)
		if err != ErrBuf {
			t.Fatalf("err = %v, want %v", err, ErrBuf)
		}
		if tr.FailAt != 1 {
			t.Fatalf("FailAt = %d, want 1 (first missing label octet)", tr.FailAt)
		}
		if tr.Root != -1 {
			t.Fatalf("root = %d, want -1", tr.Root)
		}
	})

	t.Run("truncated pointer second octet", func(t *testing.T) {
		m := []byte("\xC0")
		_, _, tr, err := UnpackDomainNameTrace(m, 0)
		if err != ErrBuf {
			t.Fatalf("err = %v, want %v", err, ErrBuf)
		}
		if tr.FailAt != 1 {
			t.Fatalf("FailAt = %d, want 1 (missing second pointer octet)", tr.FailAt)
		}
	})
}

// TestUnpackDomainNameTraceParity makes sure the traced entry point
// returns exactly the same name and offset as UnpackDomainName, and
// that parallel parses do not share report state.
func TestUnpackDomainNameTraceParity(t *testing.T) {
	cases := [][]byte{
		[]byte("\x00"),
		[]byte("\x07example\x03com\x00"),
		[]byte("\x07example\x03com\x00\x03www\xC0\x00"),
		[]byte("\x03foo\xC0\x00"),
		[]byte{4, 'a', '.', 'b', 0x01, 0},
		[]byte("\xC0\x00"),
		[]byte("\x07example\x03"),
		[]byte("\x02\xC0\xFF\xC0\x01"),
	}
	t.Parallel()
	var wg sync.WaitGroup
	for loop := 0; loop < 8; loop++ {
		for ci, in := range cases {
			wg.Add(1)
			go func(loop, ci int, in []byte) {
				defer wg.Done()
				want, wantOff, wantErr := UnpackDomainName(in, 0)
				got, gotOff, tr, gotErr := UnpackDomainNameTrace(in, 0)
				if got != want || gotOff != wantOff || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
					t.Errorf("loop=%d case=%d trace result (%q,%d,%v) != plain (%q,%d,%v)",
						loop, ci, got, gotOff, gotErr, want, wantOff, wantErr)
				}
				if tr == nil {
					t.Errorf("loop=%d case=%d nil trace", loop, ci)
				}
				if wantErr == nil && got != "" && tr != nil && !strings.HasSuffix(tr.String(), "next offset "+strconv.Itoa(wantOff)) {
					t.Errorf("loop=%d case=%d trace report missing final offset:\n%s", loop, ci, tr)
				}
			}(loop, ci, in)
		}
	}
	wg.Wait()
}

func TestPackDomainNameCompressionMap(t *testing.T) {
	expected := map[string]struct{}{
		`www\.this.is.\131an.example.org.`: {},
		`is.\131an.example.org.`:           {},
		`\131an.example.org.`:              {},
		`example.org.`:                     {},
		`org.`:                             {},
	}

	msg := make([]byte, 256)
	for _, compress := range []bool{true, false} {
		compression := make(map[string]int)

		_, err := PackDomainName(`www\.this.is.\131an.example.org.`, msg, 0, compression, compress)
		if err != nil {
			t.Fatalf("PackDomainName failed: %v", err)
		}

		if !compressionMapsEqual(expected, compression) {
			t.Errorf("expected compression maps to be equal\n%s", compressionMapsDifference(expected, compression))
		}
	}
}

func TestPackDomainNameNSECTypeBitmap(t *testing.T) {
	ownername := "some-very-long-ownername.com."
	msg := &Msg{
		Compress: true,
		Answer: []RR{
			&NS{
				Hdr: RR_Header{
					Name:   ownername,
					Rrtype: TypeNS,
					Class:  ClassINET,
				},
				Ns: "ns1.server.com.",
			},
			&NSEC{
				Hdr: RR_Header{
					Name:   ownername,
					Rrtype: TypeNSEC,
					Class:  ClassINET,
				},
				NextDomain: "a.com.",
				TypeBitMap: []uint16{TypeNS, TypeNSEC},
			},
		},
	}

	// Pack msg and then unpack into msg2
	buf, err := msg.Pack()
	if err != nil {
		t.Fatalf("msg.Pack failed: %v", err)
	}

	var msg2 Msg
	if err := msg2.Unpack(buf); err != nil {
		t.Fatalf("msg2.Unpack failed: %v", err)
	}

	if !IsDuplicate(msg.Answer[1], msg2.Answer[1]) {
		t.Error("message differs after packing and unpacking")

		// Print NSEC RR for both cases
		t.Logf("expected: %v", msg.Answer[1])
		t.Logf("got:      %v", msg2.Answer[1])
	}
}

func TestPackUnpackManyCompressionPointers(t *testing.T) {
	m := new(Msg)
	m.Compress = true
	m.SetQuestion("example.org.", TypeNS)

	for domain := "a."; len(domain) < maxDomainNameWireOctets; domain += "a." {
		m.Answer = append(m.Answer, &NS{Hdr: RR_Header{Name: domain, Rrtype: TypeNS, Class: ClassINET}, Ns: "example.org."})

		b, err := m.Pack()
		if err != nil {
			t.Fatalf("Pack failed for %q and %d records with: %v", domain, len(m.Answer), err)
		}

		var m2 Msg
		if err := m2.Unpack(b); err != nil {
			t.Fatalf("Unpack failed for %q and %d records with: %v", domain, len(m.Answer), err)
		}
	}
}

func TestLenDynamicA(t *testing.T) {
	for _, rr := range []RR{
		testRR("example.org. A"),
		testRR("example.org. AAAA"),
		testRR("example.org. L32"),
	} {
		msg := make([]byte, Len(rr))
		off, err := PackRR(rr, msg, 0, nil, false)
		if err != nil {
			t.Fatalf("PackRR failed for %T: %v", rr, err)
		}
		if off != len(msg) {
			t.Errorf("Len(rr) wrong for %T: Len(rr) = %d, PackRR(rr) = %d", rr, len(msg), off)
		}
	}
}
