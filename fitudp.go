package dns

import (
	"errors"
	"fmt"
	"strings"
)

// ErrFitUDPTsig is returned by FitUDPResponse when the message carries a
// TSIG signature. Trimming a signed message would invalidate the
// signature, so such messages are refused outright instead of being
// forwarded with a stale signature.
var ErrFitUDPTsig = errors.New("dns: cannot fit a TSIG-signed message into a UDP response")

// ErrFitUDPTooSmall is returned by FitUDPResponse when the mandatory part
// of the message - the header, the question section and the OPT record -
// does not fit within the UDP size limit on its own. This also covers an
// OPT record that is too large for the limit.
var ErrFitUDPTooSmall = errors.New("dns: question section and OPT record exceed the UDP size limit")

// FitUDPRemovedSet describes a single RRset that FitUDPResponse removed
// from a message.
type FitUDPRemovedSet struct {
	Section string // "answer", "authority" or "additional"
	Owner   string // owner name of the RRset
	Type    uint16 // RR type of the RRset (the covered type for RRSIGs)
	Count   int    // number of records removed, including related RRSIGs
}

// FitUDPReport describes how FitUDPResponse trimmed a message.
type FitUDPReport struct {
	// RemovedSets lists the RRsets that were removed, in removal order.
	RemovedSets []FitUDPRemovedSet
	// WireLengthBefore is the compressed wire length of the original message.
	WireLengthBefore int
	// WireLengthAfter is the compressed wire length of the returned message.
	WireLengthAfter int
}

func (r *FitUDPReport) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "wire length: %d -> %d", r.WireLengthBefore, r.WireLengthAfter)
	for _, rs := range r.RemovedSets {
		fmt.Fprintf(&sb, "\nremoved %s RRset %s %s (%d records)", rs.Section, rs.Owner, Type(rs.Type), rs.Count)
	}
	return sb.String()
}

// fitUDPGroup is a set of records that must be kept or removed together:
// an RRset plus the RRSIGs covering it.
type fitUDPGroup struct {
	owner   string
	rrtype  uint16
	records []RR
}

// FitUDPResponse returns a copy of msg trimmed to fit within limit bytes
// of UDP wire format, together with a report of what was removed. The
// original message is left untouched. The returned message has Compress
// set to true and the limit is enforced against the real, compressed wire
// length, as reported by Len.
//
// The limit is raised to MinMsgSize (512) when smaller, mirroring RFC 6891
// which mandates that payload sizes below 512 bytes are treated as 512.
//
// Records are removed as whole RRsets: all records sharing the same owner
// name (case-insensitively), class and type form one group, and RRSIG
// records are kept or removed together with the RRset they sign. The
// trimming strategy chosen by this interface is to remove groups from the
// additional section first, then from the authority section and only then
// from the answer section; within a section groups are removed starting
// from the one appearing last in the original message. Trimming stops as
// soon as the message fits.
//
// The question section and the OPT record are always kept. If they alone
// exceed the limit, ErrFitUDPTooSmall is returned. Messages carrying a
// TSIG signature are rejected with ErrFitUDPTsig.
//
// If any record was removed the TC bit is set on the returned message;
// otherwise all header flags and EDNS fields keep their original values.
func FitUDPResponse(msg *Msg, limit int) (*Msg, *FitUDPReport, error) {
	if msg.IsTsig() != nil {
		return nil, nil, ErrFitUDPTsig
	}
	if limit < MinMsgSize {
		limit = MinMsgSize
	}

	fit := msg.Copy()
	fit.Compress = true

	report := &FitUDPReport{WireLengthBefore: fit.Len()}

	// The OPT record is mandatory and exempt from removal; set it aside
	// and add it back at the end.
	opt := fit.popEdns0()

	// The header, question section and OPT record are mandatory. If they
	// don't fit on their own, no amount of RRset trimming will help.
	required := &Msg{
		MsgHdr:   fit.MsgHdr,
		Compress: true,
		Question: fit.Question,
	}
	if opt != nil {
		required.Extra = []RR{opt}
	}
	if l := required.Len(); l > limit {
		return nil, nil, fmt.Errorf("%w: need %d bytes, limit is %d", ErrFitUDPTooSmall, l, limit)
	}

	// The OPT record is currently set aside; reserve its share of the
	// budget so every length check accounts for it.
	optLen := 0
	if opt != nil {
		optLen = Len(opt)
	}

	// Removal order: additional, then authority, then answer.
	sections := []struct {
		name string
		rrs  *[]RR
	}{
		{"additional", &fit.Extra},
		{"authority", &fit.Ns},
		{"answer", &fit.Answer},
	}

	for _, sec := range sections {
		if fit.Len()+optLen <= limit {
			break
		}
		groups := groupRRsets(*sec.rrs)
		// Within a section, remove the group that appeared last first.
		for i := len(groups) - 1; i >= 0 && fit.Len()+optLen > limit; i-- {
			g := groups[i]
			*sec.rrs = removeRecords(*sec.rrs, g.records)
			report.RemovedSets = append(report.RemovedSets, FitUDPRemovedSet{
				Section: sec.name,
				Owner:   g.owner,
				Type:    g.rrtype,
				Count:   len(g.records),
			})
		}
	}

	if len(report.RemovedSets) > 0 {
		fit.Truncated = true
	}

	if opt != nil {
		fit.Extra = append(fit.Extra, opt)
	}

	report.WireLengthAfter = fit.Len()
	return fit, report, nil
}

// groupRRsets groups records by owner name (case-insensitively), class
// and type. RRSIG records join the group of the RRset they cover. Groups
// are returned in order of first appearance.
func groupRRsets(rrs []RR) []*fitUDPGroup {
	type key struct {
		owner  string
		class  uint16
		rrtype uint16
	}
	var groups []*fitUDPGroup
	index := make(map[key]*fitUDPGroup)
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		h := rr.Header()
		t := h.Rrtype
		if t == TypeRRSIG {
			t = rr.(*RRSIG).TypeCovered
		}
		k := key{strings.ToLower(h.Name), h.Class, t}
		g := index[k]
		if g == nil {
			g = &fitUDPGroup{owner: h.Name, rrtype: t}
			index[k] = g
			groups = append(groups, g)
		}
		g.records = append(g.records, rr)
	}
	return groups
}

// removeRecords returns rrs without the records listed in remove.
func removeRecords(rrs, remove []RR) []RR {
	drop := make(map[RR]struct{}, len(remove))
	for _, rr := range remove {
		drop[rr] = struct{}{}
	}
	kept := rrs[:0]
	for _, rr := range rrs {
		if _, ok := drop[rr]; !ok {
			kept = append(kept, rr)
		}
	}
	return kept
}
