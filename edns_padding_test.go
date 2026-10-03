package dns

import (
	"bytes"
	"errors"
	"testing"
)

// newPaddingTestMsg builds a small compressible query containing a compressed
// domain name in its answer and two EDNS0 options other than PADDING.
func newPaddingTestMsg() *Msg {
	m := new(Msg)
	m.SetQuestion("www.example.org.", TypeA)
	m.Compress = true
	m.Answer = append(m.Answer, &CNAME{
		Hdr:    RR_Header{Name: "www.example.org.", Rrtype: TypeCNAME, Class: ClassINET, Ttl: 300, Rdlength: 0},
		Target: "example.org.",
	})

	o := &OPT{Hdr: RR_Header{Name: ".", Rrtype: TypeOPT}}
	o.SetUDPSize(4096)
	o.SetDo()
	o.Option = append(o.Option,
		&EDNS0_NSID{Code: EDNS0NSID, Nsid: "deadbeef"},
		&EDNS0_COOKIE{Code: EDNS0COOKIE, Cookie: "0102030405060708"},
	)
	m.Extra = append(m.Extra, o)
	return m
}

func TestPreparePaddingAlignedWithCompression(t *testing.T) {
	m := newPaddingTestMsg()
	const block = 128

	before, err := m.Pack()
	if err != nil {
		t.Fatalf("initial pack: %v", err)
	}
	if len(before)%block == 0 {
		t.Fatalf("test setup: message already aligned at %d", len(before))
	}

	if err := m.PreparePadding(block, 0); err != nil {
		t.Fatalf("PreparePadding: %v", err)
	}

	padded, err := m.Pack()
	if err != nil {
		t.Fatalf("pack after padding: %v", err)
	}
	if len(padded)%block != 0 {
		t.Fatalf("packed length %d not a multiple of block size %d", len(padded), block)
	}

	// The PADDING option must be the last option of the OPT RR.
	opt := m.IsEdns0()
	if opt == nil {
		t.Fatal("missing OPT after PreparePadding")
	}
	if len(opt.Option) != 3 {
		t.Fatalf("expected 3 options, got %d", len(opt.Option))
	}
	if _, ok := opt.Option[2].(*EDNS0_PADDING); !ok {
		t.Fatalf("last option is %T, want *EDNS0_PADDING", opt.Option[2])
	}
	for _, b := range opt.Option[2].(*EDNS0_PADDING).Padding {
		if b != 0 {
			t.Fatal("padding bytes must be zero")
		}
	}

	// Preparing again must replace the old padding and produce identical bytes.
	again := m.Copy()
	if err := again.PreparePadding(block, 0); err != nil {
		t.Fatalf("second PreparePadding: %v", err)
	}
	againWire, err := again.Pack()
	if err != nil {
		t.Fatalf("pack after second padding: %v", err)
	}
	if !bytes.Equal(padded, againWire) {
		t.Fatalf("repeated preparation produced different bytes:\n%x\n%x", padded, againWire)
	}
}

func TestPreparePaddingPreservesOptions(t *testing.T) {
	m := newPaddingTestMsg()
	if err := m.PreparePadding(64, 0); err != nil {
		t.Fatalf("PreparePadding: %v", err)
	}
	opt := m.IsEdns0()
	if _, ok := opt.Option[0].(*EDNS0_NSID); !ok {
		t.Fatalf("first option is %T, want *EDNS0_NSID", opt.Option[0])
	}
	if _, ok := opt.Option[1].(*EDNS0_COOKIE); !ok {
		t.Fatalf("second option is %T, want *EDNS0_COOKIE", opt.Option[1])
	}
	if _, ok := opt.Option[2].(*EDNS0_PADDING); !ok {
		t.Fatalf("third option is %T, want *EDNS0_PADDING", opt.Option[2])
	}
	if !opt.Do() || opt.UDPSize() != 4096 {
		t.Fatal("OPT header fields must be preserved")
	}
}

func TestPreparePaddingReplacesExistingPadding(t *testing.T) {
	m := newPaddingTestMsg()
	opt := m.IsEdns0()
	// Put an oversized, non-zero PADDING option in the middle of the list.
	opt.Option = append(opt.Option[:1], append([]EDNS0{
		&EDNS0_PADDING{Padding: bytes.Repeat([]byte{0xff}, 300)},
	}, opt.Option[1:]...)...)

	if err := m.PreparePadding(32, 0); err != nil {
		t.Fatalf("PreparePadding: %v", err)
	}

	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if len(wire)%32 != 0 {
		t.Fatalf("packed length %d not a multiple of 32", len(wire))
	}

	opt = m.IsEdns0()
	if len(opt.Option) != 3 {
		t.Fatalf("expected exactly one padding option, got %d", len(opt.Option))
	}
	if _, ok := opt.Option[2].(*EDNS0_PADDING); !ok {
		t.Fatalf("padding must be last, got %T", opt.Option[2])
	}
	if got := len(opt.Option[2].(*EDNS0_PADDING).Padding); got >= 300 {
		t.Fatalf("old padding not removed, padding length %d", got)
	}
}

func TestPreparePaddingNoOPT(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("example.com.", TypeAAAA)

	if err := m.PreparePadding(16, 0); err != nil {
		t.Fatalf("PreparePadding: %v", err)
	}
	opt := m.IsEdns0()
	if opt == nil {
		t.Fatal("PreparePadding must create an OPT RR")
	}
	if len(opt.Option) != 1 {
		t.Fatalf("expected 1 option, got %d", len(opt.Option))
	}
	if _, ok := opt.Option[0].(*EDNS0_PADDING); !ok {
		t.Fatalf("option is %T, want *EDNS0_PADDING", opt.Option[0])
	}
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if len(wire)%16 != 0 {
		t.Fatalf("packed length %d not a multiple of 16", len(wire))
	}
}

func TestPreparePaddingKeepsTSIGLast(t *testing.T) {
	m := newPaddingTestMsg()
	m.SetTsig("key.", HmacSHA256, 300, 0)

	if err := m.PreparePadding(64, 0); err != nil {
		t.Fatalf("PreparePadding: %v", err)
	}
	if m.IsTsig() == nil {
		t.Fatal("TSIG must remain the last record of the additional section")
	}
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if len(wire)%64 != 0 {
		t.Fatalf("packed length %d not a multiple of 64", len(wire))
	}
}

func TestPreparePaddingAlignedInputAddsFullBlock(t *testing.T) {
	m := newPaddingTestMsg()
	if err := m.PreparePadding(128, 0); err != nil {
		t.Fatalf("PreparePadding: %v", err)
	}
	first, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if len(first)%128 != 0 {
		t.Fatalf("packed length %d not aligned", len(first))
	}

	// Re-preparing an already prepared message must not move off the boundary:
	// the option header is counted, so padding is recomputed to a full block.
	if err := m.PreparePadding(128, 0); err != nil {
		t.Fatalf("second PreparePadding: %v", err)
	}
	second, err := m.Pack()
	if err != nil {
		t.Fatalf("second pack: %v", err)
	}
	if len(second)%128 != 0 {
		t.Fatalf("re-prepared length %d not aligned", len(second))
	}
	if !bytes.Equal(first, second) {
		t.Fatal("re-preparing an aligned message changed the wire format")
	}
}

func TestPreparePaddingRejectsBlockSizeZero(t *testing.T) {
	m := newPaddingTestMsg()
	before, _ := m.Pack()
	if err := m.PreparePadding(0, 0); !errors.Is(err, ErrPaddingBlockSize) {
		t.Fatalf("err = %v, want ErrPaddingBlockSize", err)
	}
	if err := m.PreparePadding(-8, 0); !errors.Is(err, ErrPaddingBlockSize) {
		t.Fatalf("err = %v, want ErrPaddingBlockSize", err)
	}
	after, _ := m.Pack()
	if !bytes.Equal(before, after) {
		t.Fatal("message changed after rejected block size")
	}
}

func TestPreparePaddingRejectsMultipleOPT(t *testing.T) {
	m := newPaddingTestMsg()
	second := &OPT{Hdr: RR_Header{Name: ".", Rrtype: TypeOPT}}
	second.Option = append(second.Option, &EDNS0_NSID{Code: EDNS0NSID, Nsid: "aa"})
	m.Extra = append(m.Extra, second)

	before, _ := m.Pack()
	if err := m.PreparePadding(64, 0); !errors.Is(err, ErrPaddingMultipleOPT) {
		t.Fatalf("err = %v, want ErrPaddingMultipleOPT", err)
	}
	after, _ := m.Pack()
	if !bytes.Equal(before, after) {
		t.Fatal("message changed after rejected multiple OPT")
	}
	// Both OPT RRs must still be present and untouched; no implicit choice.
	optCount := 0
	for _, r := range m.Extra {
		if r.Header().Rrtype == TypeOPT {
			optCount++
		}
	}
	if optCount != 2 {
		t.Fatalf("receiver must not be implicitly modified, got %d OPT RRs", optCount)
	}
}

func TestPreparePaddingTooSmallMaxSize(t *testing.T) {
	m := newPaddingTestMsg()
	unpadded, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	// A maximum smaller than even the unpadded message must fail.
	if err := m.PreparePadding(128, len(unpadded)-1); !errors.Is(err, ErrPaddingTooLarge) {
		t.Fatalf("err = %v, want ErrPaddingTooLarge", err)
	}
	after, err := m.Pack()
	if err != nil {
		t.Fatalf("pack after error: %v", err)
	}
	if !bytes.Equal(unpadded, after) {
		t.Fatal("original message must be unchanged when the size limit is too small")
	}
	if opt := m.IsEdns0(); opt == nil || len(opt.Option) != 2 {
		t.Fatalf("options must not be modified, got %v", opt)
	}

	// With room for the aligned message the same call must succeed.
	target := ((len(unpadded) + 4 + 127) / 128) * 128
	if err := m.PreparePadding(128, target); err != nil {
		t.Fatalf("PreparePadding with sufficient maxSize: %v", err)
	}
	wire, _ := m.Pack()
	if len(wire) != target {
		t.Fatalf("padded length = %d, want %d", len(wire), target)
	}
}
