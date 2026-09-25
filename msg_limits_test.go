package dns

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
)

// ampleLimits never rejects any message that Unpack can parse.
func ampleLimits() UnpackLimits {
	return UnpackLimits{
		MaxDomainNameOctets:    1 << 20,
		MaxResourceRecords:     1 << 16,
		MaxCompressionPointers: 1 << 16,
	}
}

// amplificationWire builds a message with a single 255-octet owner name at
// offset 12, followed by answers A records. Every answer after the first
// references the long name with a compression pointer, so the wire message
// is small while every answer expands to 255 domain name octets.
//
// Layout:
//   - header (12 octets), answer count = answers
//   - offset 12: labels 'a'*63 'b'*63 'c'*63 'd'*61 and root label (255 octets)
//   - offset 267: first answer (literal name + 14-octet A rdata), ends 281
//   - answers 2..answers: 2-octet compression pointer 0xc00c + 14 fixed octets
func amplificationWire(answers int) []byte {
	msg := []byte{
		0x12, 0x34, // id
		0x81, 0x80, // bits: response
		0x00, 0x00, // qdcount
		byte(answers >> 8), byte(answers), // ancount
		0x00, 0x00, // nscount
		0x00, 0x00, // arcount
	}
	labels := []struct {
		c byte
		n int
	}{
		{'a', 63}, {'b', 63}, {'c', 63}, {'d', 61},
	}
	for _, label := range labels {
		msg = append(msg, byte(label.n))
		msg = append(msg, bytes.Repeat([]byte{label.c}, label.n)...)
	}
	msg = append(msg, 0) // root label
	// rrType A, class IN, ttl 60, rdlength 4, rdata 127.0.0.1
	fixed := []byte{
		0x00, 0x01, // type A
		0x00, 0x01, // class IN
		0x00, 0x00, 0x00, 0x3c, // ttl
		0x00, 0x04, // rdlength
		0x7f, 0x00, 0x00, 0x01, // 127.0.0.1
	}
	msg = append(msg, fixed...)
	for i := 1; i < answers; i++ {
		msg = append(msg, 0xc0, 0x0c) // compression pointer to offset 12
		msg = append(msg, fixed...)
	}
	return msg
}

// amplificationPointerOffset returns the offset of the compression pointer
// of the nth answer (1-based, n >= 2).
func amplificationPointerOffset(n int) int {
	return 281 + (n-2)*16
}

func TestUnpackWithLimitsEquivalentToUnpack(t *testing.T) {
	m := new(Msg)
	m.Response = true
	m.SetQuestion("www.example.org.", TypeA)
	m.Answer = []RR{
		&CNAME{Hdr: RR_Header{Name: "www.example.org.", Rrtype: TypeCNAME, Class: ClassINET, Ttl: 60}, Target: "cname.example.org."},
		&A{Hdr: RR_Header{Name: "cname.example.org.", Rrtype: TypeA, Class: ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1").To4()},
		&MX{Hdr: RR_Header{Name: "example.org.", Rrtype: TypeMX, Class: ClassINET, Ttl: 60}, Preference: 10, Mx: "mail.example.org."},
	}
	m.Ns = []RR{
		&NS{Hdr: RR_Header{Name: "example.org.", Rrtype: TypeNS, Class: ClassINET, Ttl: 60}, Ns: "ns1.example.org."},
	}
	m.Extra = []RR{
		&A{Hdr: RR_Header{Name: "ns1.example.org.", Rrtype: TypeA, Class: ClassINET, Ttl: 60}, A: net.ParseIP("10.0.0.1").To4()},
	}
	m.SetEdns0(4096, true)
	m.Compress = true
	packed, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		data []byte
	}{
		{"compressed response with opt", packed},
		{"compression amplification", amplificationWire(8)},
		{"header only", []byte{0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var unlimited, withLimits Msg
			if err := unlimited.Unpack(tc.data); err != nil {
				t.Fatalf("Unpack: %v", err)
			}
			if err := withLimits.UnpackWithLimits(tc.data, ampleLimits()); err != nil {
				t.Fatalf("UnpackWithLimits: %v", err)
			}
			if !reflect.DeepEqual(&unlimited, &withLimits) {
				t.Fatalf("messages differ:\nUnpack: %+v\nLimits: %+v", &unlimited, &withLimits)
			}

			// A zero UnpackLimits disables every limit, the result must
			// match Unpack as well.
			var zeroLimits Msg
			if err := zeroLimits.UnpackWithLimits(tc.data, UnpackLimits{}); err != nil {
				t.Fatalf("UnpackWithLimits with zero limits: %v", err)
			}
			if !reflect.DeepEqual(&unlimited, &zeroLimits) {
				t.Fatalf("messages differ:\nUnpack: %+v\nZeroLimits: %+v", &unlimited, &zeroLimits)
			}
		})
	}
}

func TestUnpackWithLimitsCompressionAmplification(t *testing.T) {
	// 40 answers expand to 40 * 255 = 10200 domain name octets while the
	// wire message is only 905 octets long.
	data := amplificationWire(40)
	if got := len(data); got != 905 {
		t.Fatalf("wire message is %d octets long, expected 905", got)
	}

	var m Msg
	if err := m.UnpackWithLimits(data, UnpackLimits{MaxDomainNameOctets: 10200}); err != nil {
		t.Fatalf("exact budget rejected a valid message: %v", err)
	}

	err := m.UnpackWithLimits(data, UnpackLimits{MaxDomainNameOctets: 5000})
	if err == nil {
		t.Fatal("compression amplification was not rejected")
	}
	if !errors.Is(err, ErrNameLimit) {
		t.Fatalf("error is %v, want ErrNameLimit", err)
	}
	// After 19 expansions 19*255 = 4845 octets are spent and 155 remain.
	// The 20th expansion charges two 64-octet labels (91, then 27 left) and
	// then fails on the third label's length byte at offset 12+64+64 = 140.
	var limitErr *LimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("error %T is not a *LimitError", err)
	}
	if limitErr.Offset != 140 {
		t.Fatalf("failure offset is %d, expected 140", limitErr.Offset)
	}
}

func TestUnpackWithLimitsExactBudgets(t *testing.T) {
	data := amplificationWire(10)

	cases := []struct {
		name    string
		limits  UnpackLimits
		wantErr error
		offset  int
	}{
		{"exact name octets", UnpackLimits{MaxDomainNameOctets: 10 * 255}, nil, 0},
		// 2549 = 10*255 - 1: the last expansion is one octet short for
		// its root label, which sits at offset 12+254 = 266.
		{"one octet short", UnpackLimits{MaxDomainNameOctets: 10*255 - 1}, ErrNameLimit, 266},
		{"exact records", UnpackLimits{MaxResourceRecords: 10}, nil, 0},
		{"one record short", UnpackLimits{MaxResourceRecords: 9}, ErrRecordLimit, amplificationPointerOffset(10)},
		{"exact pointers", UnpackLimits{MaxCompressionPointers: 9}, nil, 0},
		{"one pointer short", UnpackLimits{MaxCompressionPointers: 8}, ErrPointerLimit, amplificationPointerOffset(10)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var m Msg
			err := m.UnpackWithLimits(data, tc.limits)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error is %v, want %v", err, tc.wantErr)
			}
			var limitErr *LimitError
			if !errors.As(err, &limitErr) {
				t.Fatalf("error %T is not a *LimitError", err)
			}
			if limitErr.Offset != tc.offset {
				t.Fatalf("failure offset is %d, expected %d", limitErr.Offset, tc.offset)
			}
		})
	}
}

func TestUnpackWithLimitsCompressionLoop(t *testing.T) {
	// One question, whose name at offset 12 points back to itself.
	data := []byte{
		0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xc0, 0x0c,
	}
	var m Msg
	err := m.UnpackWithLimits(data, UnpackLimits{MaxCompressionPointers: 1 << 10})
	if !errors.Is(err, ErrCompressionLoop) {
		t.Fatalf("error is %v, want ErrCompressionLoop", err)
	}
	var limitErr *LimitError
	if !errors.As(err, &limitErr) || limitErr.Offset != 12 {
		t.Fatalf("error %v at unexpected offset", err)
	}

	// Plain Unpack must keep its historical pointer-count failure.
	err = m.Unpack(data)
	if err == nil || !strings.Contains(err.Error(), "too many compression pointers") {
		t.Fatalf("Unpack error is %v, want the historical error", err)
	}
}

func TestUnpackWithLimitsPointerOutOfBounds(t *testing.T) {
	// Question name is a pointer to offset 255, outside the 14-octet message.
	data := []byte{
		0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xc0, 0xff,
	}
	var m Msg
	err := m.UnpackWithLimits(data, ampleLimits())
	if !errors.Is(err, ErrBuf) {
		t.Fatalf("error is %v, want ErrBuf", err)
	}
	var limitErr *LimitError
	if !errors.As(err, &limitErr) || limitErr.Offset != 12 {
		t.Fatalf("error %v at unexpected offset", err)
	}
}

func TestUnpackWithLimitsBadRdlength(t *testing.T) {
	m := new(Msg)
	m.Response = true
	m.SetQuestion("example.org.", TypeA)
	m.Answer = []RR{
		&A{Hdr: RR_Header{Name: "example.org.", Rrtype: TypeA, Class: ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1").To4()},
	}
	packed, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}

	// Locate the RDLENGTH field of the answer: 12 (header) + question name
	// (13) + qtype/qclass (4), then name (13) + type(2) + class(2) + ttl(4).
	rdlengthOff := 12 + 13 + 4 + 13 + 2 + 2 + 4

	// RDLENGTH larger than the remaining message is reported as an error.
	tooLarge := append([]byte(nil), packed...)
	tooLarge[rdlengthOff] = 0xff
	tooLarge[rdlengthOff+1] = 0xff
	var dst Msg
	if err := dst.UnpackWithLimits(tooLarge, ampleLimits()); err == nil {
		t.Fatal("unexpected success with overflowing RDLENGTH")
	}

	// RDLENGTH smaller than the actual rdata fails with a bad rdlength.
	tooSmall := append([]byte(nil), packed...)
	tooSmall[rdlengthOff] = 0x00
	tooSmall[rdlengthOff+1] = 0x02
	if err := dst.UnpackWithLimits(tooSmall, ampleLimits()); err == nil {
		t.Fatal("unexpected success with truncated RDLENGTH")
	}
}

func TestUnpackWithLimitsZeroRR(t *testing.T) {
	// A header-only message declares zero records in every section.
	data := []byte{0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0}
	var m Msg
	if err := m.UnpackWithLimits(data, UnpackLimits{MaxResourceRecords: 1}); err != nil {
		t.Fatalf("zero-RR message rejected: %v", err)
	}
	if m.Question != nil || m.Answer != nil || m.Ns != nil || m.Extra != nil {
		t.Fatalf("expected all sections to be nil, got %+v", &m)
	}

	// A message that only carries an OPT record in the additional section.
	opt := new(Msg)
	opt.SetQuestion("example.org.", TypeA)
	opt.SetEdns0(4096, true)
	packed, err := opt.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var m1, m2 Msg
	if err := m1.Unpack(packed); err != nil {
		t.Fatal(err)
	}
	if err := m2.UnpackWithLimits(packed, UnpackLimits{MaxResourceRecords: 1}); err != nil {
		t.Fatalf("OPT message rejected: %v", err)
	}
	if !reflect.DeepEqual(&m1, &m2) {
		t.Fatalf("messages differ:\nUnpack: %+v\nLimits: %+v", &m1, &m2)
	}
	if m2.IsEdns0() == nil {
		t.Fatal("OPT record missing after UnpackWithLimits")
	}
}

func TestUnpackWithLimitsReceiverUnchangedOnFailure(t *testing.T) {
	before := new(Msg)
	before.SetQuestion("keep.example.org.", TypeAAAA)
	before.Answer = []RR{
		&TXT{Hdr: RR_Header{Name: "keep.example.org.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 60}, Txt: []string{"keep me"}},
	}
	before.Ns = []RR{
		&NS{Hdr: RR_Header{Name: "example.org.", Rrtype: TypeNS, Class: ClassINET, Ttl: 60}, Ns: "ns1.example.org."},
	}
	before.Extra = []RR{
		&A{Hdr: RR_Header{Name: "ns1.example.org.", Rrtype: TypeA, Class: ClassINET, Ttl: 60}, A: net.ParseIP("10.0.0.1").To4()},
	}
	snapshot := before.Copy()

	failures := [][]byte{
		// Compression amplification exceeding the name budget.
		amplificationWire(40),
		// Compression loop.
		{0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c},
		// Pointer outside the message.
		{0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0xff},
	}
	for i, data := range failures {
		err := before.UnpackWithLimits(data, UnpackLimits{MaxDomainNameOctets: 128})
		if err == nil {
			t.Fatalf("case %d: expected failure", i)
		}
		if !reflect.DeepEqual(before, snapshot) {
			t.Fatalf("case %d: receiver modified on failure:\ngot:  %+v\nwant: %+v", i, before, snapshot)
		}
	}
}

// FuzzMsgUnpackWithLimits fuzzes UnpackWithLimits next to Unpack. Seeds are
// taken from the existing fuzz crash regressions in fuzz_test.go and from
// the limit-specific messages constructed above.
func FuzzMsgUnpackWithLimits(f *testing.F) {
	// Message that triggered the packDataOpt overflow, see TestPackDataOpt.
	f.Add([]byte{
		0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x2,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x30,
		0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x0b,
		0x00, 0x23, 0x08, 0x30, 0x30, 0x30, 0x30, 0x30,
		0x30, 0x30, 0x30, 0x00, 0x00, 0x29, 0x30, 0x30,
		0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x30,
		0x30, 0x00, 0x00, 0x30, 0x30, 0x00, 0x01, 0x30,
		0x00, 0x00, 0x00, 0x00,
	})
	f.Add(amplificationWire(8))
	f.Add([]byte{0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c}) // compression loop
	f.Add([]byte{0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0xff}) // pointer out of bounds
	f.Add([]byte{0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0})       // header only

	f.Fuzz(func(t *testing.T, data []byte) {
		var unlimited, withLimits Msg
		errUnpack := unlimited.Unpack(data)

		// Limits scaled to the message size can never reject anything
		// Unpack accepts, so both must agree and produce equal messages.
		generous := UnpackLimits{
			MaxDomainNameOctets:    300*len(data) + 1,
			MaxResourceRecords:     len(data) + 1,
			MaxCompressionPointers: 300*len(data) + 1,
		}
		errLimits := withLimits.UnpackWithLimits(data, generous)
		if (errUnpack == nil) != (errLimits == nil) {
			t.Fatalf("Unpack: %v, UnpackWithLimits: %v", errUnpack, errLimits)
		}
		if errLimits == nil && !reflect.DeepEqual(&unlimited, &withLimits) {
			t.Fatalf("messages differ:\nUnpack: %+v\nLimits: %+v", &unlimited, &withLimits)
		}

		// Tight limits must never panic and must leave the receiver
		// untouched on failure.
		newTight := func() *Msg {
			return &Msg{Question: []Question{{Name: "sentinel.", Qtype: TypeA, Qclass: ClassINET}}}
		}
		tight := newTight()
		err := tight.UnpackWithLimits(data, UnpackLimits{
			MaxDomainNameOctets:    64,
			MaxResourceRecords:     2,
			MaxCompressionPointers: 2,
		})
		if err != nil && !reflect.DeepEqual(tight, newTight()) {
			t.Fatalf("receiver modified on failure:\ngot:  %+v\nwant: %+v", tight, newTight())
		}
	})
}

func ExampleMsg_UnpackWithLimits() {
	// A normal message unpacks exactly like Unpack when the limits are
	// generous enough.
	query := new(Msg)
	query.SetQuestion("www.example.org.", TypeA)
	packed, err := query.Pack()
	if err != nil {
		panic(err)
	}

	var m Msg
	err = m.UnpackWithLimits(packed, UnpackLimits{
		MaxDomainNameOctets:    4096,
		MaxResourceRecords:     100,
		MaxCompressionPointers: 100,
	})
	fmt.Println("valid message:", err == nil, m.Question[0].Name)

	// A small message that expands to many octets of compressed domain
	// names is rejected once the decompressed name budget is spent, and
	// the returned error locates the violation in the message.
	err = m.UnpackWithLimits(amplificationWire(40), UnpackLimits{MaxDomainNameOctets: 5000})
	fmt.Println("compression bomb rejected:", errors.Is(err, ErrNameLimit))
	var limitErr *LimitError
	if errors.As(err, &limitErr) {
		fmt.Println("violation offset:", limitErr.Offset)
	}

	// Output:
	// valid message: true www.example.org.
	// compression bomb rejected: true
	// violation offset: 140
}
