package dns_test

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

// paddedMsg builds a small message with a compressed domain name and an OPT
// RR carrying two other EDNS0 options (NSID and COOKIE).
func paddedMsg() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	m.Compress = true
	m.SetEdns0(4096, true)
	opt := m.IsEdns0()
	opt.Option = append(opt.Option,
		&dns.EDNS0_NSID{Code: dns.EDNS0NSID},
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE},
	)
	return m
}

// TestPreparePaddingBasic is the acceptance test: a small message with a
// compressed domain name and two other EDNS0 options ends up with a packed
// length that is an exact multiple of the block size, and repeated
// preparation yields identical bytes.
func TestPreparePaddingBasic(t *testing.T) {
	m := paddedMsg()
	blockSize := 64
	maxSize := 4096

	prepared, err := m.PreparePadding(blockSize, maxSize)
	if err != nil {
		t.Fatalf("PreparePadding() error = %v", err)
	}
	if prepared == nil {
		t.Fatal("PreparePadding() returned a nil message")
	}

	wire, err := prepared.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	if len(wire)%blockSize != 0 {
		t.Errorf("packed length %d is not a multiple of block size %d", len(wire), blockSize)
	}

	// Repeated preparation yields identical bytes.
	prepared2, err := m.PreparePadding(blockSize, maxSize)
	if err != nil {
		t.Fatalf("second PreparePadding() error = %v", err)
	}
	wire2, err := prepared2.Pack()
	if err != nil {
		t.Fatalf("second Pack() error = %v", err)
	}
	if !bytes.Equal(wire, wire2) {
		t.Errorf("repeated preparation produced different bytes:\n%x\n%x", wire, wire2)
	}

	// The prepared message carries exactly one padding option.
	var padding *dns.EDNS0_PADDING
	for _, o := range prepared.IsEdns0().Option {
		if p, ok := o.(*dns.EDNS0_PADDING); ok {
			if padding != nil {
				t.Errorf("more than one padding option present")
			}
			padding = p
		}
	}
	if padding == nil {
		t.Fatal("no padding option in prepared message")
	}
}

// TestPreparePaddingNoOPT verifies that a message without an OPT RR gets one
// created so the padding option has a home, and that the original message is
// left without an OPT.
func TestPreparePaddingNoOPT(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	m.Compress = true

	prepared, err := m.PreparePadding(64, 4096)
	if err != nil {
		t.Fatalf("PreparePadding() error = %v", err)
	}
	if prepared.IsEdns0() == nil {
		t.Fatal("PreparePadding() did not create an OPT RR")
	}
	wire, err := prepared.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	if len(wire)%64 != 0 {
		t.Errorf("packed length %d is not a multiple of 64", len(wire))
	}
	if m.IsEdns0() != nil {
		t.Errorf("original message gained an OPT RR")
	}
}

// TestPreparePaddingExistingPadding verifies that an existing padding option
// is removed and replaced by a single new padding option whose bytes are all
// zero, and that the resulting message is aligned.
func TestPreparePaddingExistingPadding(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	m.Compress = true
	m.SetEdns0(4096, true)
	opt := m.IsEdns0()
	opt.Option = append(opt.Option,
		&dns.EDNS0_NSID{Code: dns.EDNS0NSID},
		&dns.EDNS0_PADDING{Padding: []byte{0xff, 0xff, 0xff, 0xff}},
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE},
	)

	prepared, err := m.PreparePadding(64, 4096)
	if err != nil {
		t.Fatalf("PreparePadding() error = %v", err)
	}
	popt := prepared.IsEdns0()
	var padding *dns.EDNS0_PADDING
	for _, o := range popt.Option {
		if p, ok := o.(*dns.EDNS0_PADDING); ok {
			if padding != nil {
				t.Errorf("more than one padding option present")
			}
			padding = p
		}
	}
	if padding == nil {
		t.Fatal("no padding option in prepared message")
	}
	for i, b := range padding.Padding {
		if b != 0 {
			t.Errorf("padding byte %d is 0x%02x, want 0x00", i, b)
		}
	}
	wire, err := prepared.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	if len(wire)%64 != 0 {
		t.Errorf("packed length %d is not a multiple of 64", len(wire))
	}
}

// TestPreparePaddingOptionOrder verifies that the relative order of the OPT
// RR and of all other EDNS0 options is preserved, with the new padding
// option appended after every other option.
func TestPreparePaddingOptionOrder(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	m.Compress = true
	m.SetEdns0(4096, true)
	opt := m.IsEdns0()
	opt.Option = append(opt.Option,
		&dns.EDNS0_NSID{Code: dns.EDNS0NSID},
		&dns.EDNS0_PADDING{Padding: []byte{0xff}},
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE},
	)

	prepared, err := m.PreparePadding(64, 4096)
	if err != nil {
		t.Fatalf("PreparePadding() error = %v", err)
	}
	wantCodes := []uint16{dns.EDNS0NSID, dns.EDNS0COOKIE, dns.EDNS0PADDING}
	gotCodes := make([]uint16, 0, len(prepared.IsEdns0().Option))
	for _, o := range prepared.IsEdns0().Option {
		gotCodes = append(gotCodes, o.Option())
	}
	if !reflect.DeepEqual(gotCodes, wantCodes) {
		t.Errorf("option order = %v, want %v", gotCodes, wantCodes)
	}
}

// TestPreparePaddingAligned verifies that a message which is already aligned
// without padding does not get pushed off the block boundary by the added
// option header: the padding length must account for the 4 header octets.
func TestPreparePaddingAligned(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	m.Compress = true
	m.SetEdns0(4096, true)

	base, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	baseLen := len(base)

	// Use a block size equal to the unpadded length: the message is already
	// aligned, so the option header must be accounted for.
	prepared, err := m.PreparePadding(baseLen, 4096)
	if err != nil {
		t.Fatalf("PreparePadding() error = %v", err)
	}
	wire, err := prepared.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	if len(wire)%baseLen != 0 {
		t.Errorf("packed length %d is not a multiple of block size %d", len(wire), baseLen)
	}
	if len(wire) != 2*baseLen {
		t.Errorf("packed length = %d, want %d (padding must account for the option header)", len(wire), 2*baseLen)
	}
}

// TestPreparePaddingErrors verifies that invalid arguments are rejected and
// that a failed call leaves the original message unchanged.
func TestPreparePaddingErrors(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	m.Compress = true
	m.SetEdns0(4096, true)
	opt := m.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID})

	// Snapshot the original wire before the failing calls.
	origWire, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	for _, tc := range []struct {
		blockSize int
		maxSize   int
	}{
		{0, 4096},  // block size zero
		{-1, 4096}, // block size negative
		{64, -1},   // max size negative
	} {
		if _, err := m.PreparePadding(tc.blockSize, tc.maxSize); err == nil {
			t.Errorf("PreparePadding(%d, %d) error = nil, want error", tc.blockSize, tc.maxSize)
		}
	}

	// maxSize too small: the original message must be unchanged.
	if _, err := m.PreparePadding(64, 10); err == nil {
		t.Errorf("PreparePadding(64, 10) error = nil, want error")
	}
	afterWire, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack() after error = %v", err)
	}
	if !bytes.Equal(origWire, afterWire) {
		t.Errorf("original message changed after failed PreparePadding")
	}
	if m.IsEdns0() != nil {
		for _, o := range m.IsEdns0().Option {
			if _, ok := o.(*dns.EDNS0_PADDING); ok {
				t.Errorf("original message gained a padding option after failed call")
			}
		}
	}

	// Multiple OPT RRs must be explicitly rejected.
	m2 := m.Copy()
	opt2 := new(dns.OPT)
	opt2.Hdr.Name = "."
	opt2.Hdr.Rrtype = dns.TypeOPT
	m2.Extra = append(m2.Extra, opt2)
	if _, err := m2.PreparePadding(64, 4096); err == nil {
		t.Errorf("PreparePadding with multiple OPTs error = nil, want error")
	}
}

// ExampleMsg_PreparePadding shows how to prepare EDNS0 padding so the packed
// message length is a multiple of 64 octets, and prints the length before and
// after.
func ExampleMsg_PreparePadding() {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	m.Compress = true
	m.SetEdns0(4096, true)
	opt := m.IsEdns0()
	opt.Option = append(opt.Option,
		&dns.EDNS0_NSID{Code: dns.EDNS0NSID},
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE},
	)

	blockSize := 64
	prepared, err := m.PreparePadding(blockSize, 4096)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	before, err := m.Pack()
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	after, err := prepared.Pack()
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("before: %d bytes\n", len(before))
	fmt.Printf("after:  %d bytes\n", len(after))
	// Output:
	// before: 48 bytes
	// after:  64 bytes
}
