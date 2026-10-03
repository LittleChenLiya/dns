package dns

import (
	"errors"
	"fmt"
)

// edns0PaddingOptionHeader is the fixed wire size of an EDNS0 option header:
// 2 octets for the OPTION-CODE and 2 octets for the OPTION-LENGTH. The
// padding computation must account for these 4 octets, otherwise an already
// aligned message would be pushed off the block boundary by the option
// header itself.
const edns0PaddingOptionHeader = 4

// PreparePadding returns a deep copy of dns with the EDNS0 padding option
// prepared so that the packed message length is an exact multiple of
// blockSize. blockSize is the desired alignment (in octets); it must be
// greater than zero. maxSize is the maximum allowed packed message length
// (in octets); it must be non-negative.
//
// The padding is computed from the actual wire encoding of the message
// (via Pack), not from field lengths, so compression and any other
// encoding details are taken into account. The compression settings used
// for the measurement are the same as those the final Pack will use.
//
// An existing padding option is removed and replaced by a single new
// padding option that is appended after every other option; the relative
// order of the OPT RR and of all other EDNS0 options is preserved. The
// new padding option contributes its own 4-octet option header plus the
// padding octets, both of which are included in the alignment
// calculation. When the message is already aligned without padding, the
// padding length is chosen so that the added option header does not move
// the message off the block boundary.
//
// If the padded message would exceed maxSize, an error is returned and no
// message is returned. The receiver message is never modified: on error it
// is left exactly as it was before the call. A message that contains more
// than one OPT RR is rejected rather than silently picking one. If the
// message has no OPT RR, one is created so the padding option has a home.
//
// Example:
//
//	m := new(dns.Msg)
//	m.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
//	m.Compress = true
//	m.SetEdns0(4096, true)
//	padded, err := m.PreparePadding(64, 4096)
//	if err != nil {
//		// handle error
//	}
//	wire, err := padded.Pack() // len(wire) is a multiple of 64
func (dns *Msg) PreparePadding(blockSize, maxSize int) (*Msg, error) {
	if dns == nil {
		return nil, errors.New("dns: nil message")
	}
	if blockSize <= 0 {
		return nil, errors.New("dns: EDNS padding block size must be greater than zero")
	}
	if maxSize < 0 {
		return nil, errors.New("dns: EDNS padding maximum size must be non-negative")
	}

	// RFC 6891 section 6.1.1 allows at most one OPT RR. Reject messages that
	// carry more than one instead of implicitly picking one to pad.
	var optCount int
	for _, rr := range dns.Extra {
		if rr != nil && rr.Header().Rrtype == TypeOPT {
			optCount++
		}
	}
	if optCount > 1 {
		return nil, errors.New("dns: message contains multiple OPT RRs")
	}

	// Work on a deep copy so the receiver message is never modified, even
	// when the call fails.
	m := dns.Copy()

	opt := m.IsEdns0()
	if opt == nil {
		// No OPT RR present: create one so the padding option has a home.
		opt = new(OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = TypeOPT
		m.Extra = append(m.Extra, opt)
	}

	// Remove every existing padding option, preserving the relative order of
	// the remaining options and the position of the OPT RR within the
	// additional section.
	kept := make([]EDNS0, 0, len(opt.Option))
	for _, o := range opt.Option {
		if o.Option() != EDNS0PADDING {
			kept = append(kept, o)
		}
	}
	opt.Option = kept

	// Pack the message without the padding option to obtain the exact wire
	// length, using the same compression settings the final Pack will use.
	base, err := m.Pack()
	if err != nil {
		return nil, err
	}
	baseLen := len(base)

	// The padding option contributes its own option header plus the padding
	// octets. Choose the padding length so the whole message becomes a
	// multiple of blockSize. When the message is already aligned, the header
	// is accounted for so the boundary is not missed.
	padLen := (blockSize - (baseLen+edns0PaddingOptionHeader)%blockSize) % blockSize
	total := baseLen + edns0PaddingOptionHeader + padLen
	if total > maxSize {
		return nil, fmt.Errorf("dns: padded message would be %d octets, exceeding maximum of %d", total, maxSize)
	}

	opt.Option = append(opt.Option, &EDNS0_PADDING{Padding: make([]byte, padLen)})
	return m, nil
}
