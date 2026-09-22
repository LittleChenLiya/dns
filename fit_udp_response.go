package dns

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// TrimmedRRset describes a single RRset (plus its covering RRSIG
// records, if any) that FitUDPResponse removed from a message.
type TrimmedRRset struct {
	Section string // "Answer", "Authority" or "Additional"
	Owner   string // owner name of the removed RRset
	Type    uint16 // the RRset's type (the covered type for RRSIGs)
	Count   int    // number of RRs removed, including covering RRSIGs
}

// String returns a human-readable summary of the trimmed RRset.
func (t TrimmedRRset) String() string {
	typ := TypeToString[t.Type]
	if typ == "" {
		typ = "TYPE" + strconv.Itoa(int(t.Type))
	}
	return fmt.Sprintf("%s %s %s (%d RRs)", t.Section, t.Owner, typ, t.Count)
}

// FitUDPResponseReport describes what FitUDPResponse did to a message.
type FitUDPResponseReport struct {
	// Removed lists every RRset that was dropped, in removal order.
	Removed []TrimmedRRset
	// WireLengthBefore is the compressed wire length of the message
	// before trimming.
	WireLengthBefore int
	// WireLengthAfter is the compressed wire length of the returned
	// message after trimming.
	WireLengthAfter int
}

// String returns a human-readable summary of the report.
func (r *FitUDPResponseReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "wire length: %d -> %d bytes", r.WireLengthBefore, r.WireLengthAfter)
	if len(r.Removed) == 0 {
		b.WriteString(", nothing trimmed")
		return b.String()
	}
	b.WriteString(", trimmed RRsets:")
	for _, t := range r.Removed {
		b.WriteString("\n  ")
		b.WriteString(t.String())
	}
	return b.String()
}

// FitUDPResponse returns a copy of msg trimmed to fit within limit bytes
// of UDP wire format, together with a report describing what was removed.
// The input message is never modified.
//
// The limit is raised to MinMsgSize (512) if smaller, per RFC 6891. The
// message is measured by its real wire length with name compression
// enabled, and the returned message has Compress set to true.
//
// The trimming policy is deliberately simple and deterministic: whole
// RRsets are dropped, never individual records of a set. Records are
// grouped by owner name (case-insensitively), class and type; RRSIG
// records are kept or removed together with the RRset they sign. First
// the Additional section is trimmed, then the Authority section, and
// only then the Answer section. Within a section, RRsets are dropped
// starting from the one appearing last in the original message.
//
// The Question section and the OPT record are always preserved. If the
// OPT record alone is too large, or the question and OPT record together
// already exceed the limit, an error is returned. If any record was
// removed, the TC bit is set on the returned message; otherwise all
// header flags and EDNS fields keep their original semantics.
//
// Messages carrying a TSIG signature are rejected: trimming would
// invalidate the signature, and silently keeping the old signature is
// not an option.
func FitUDPResponse(msg *Msg, limit int) (*Msg, *FitUDPResponseReport, error) {
	if msg.IsTsig() != nil {
		return nil, nil, errors.New("dns: FitUDPResponse refuses to trim a TSIG-signed message")
	}

	// RFC 6891 mandates that a payload size smaller than MinMsgSize
	// must be treated as MinMsgSize.
	if limit < MinMsgSize {
		limit = MinMsgSize
	}

	fitted := msg.Copy()
	fitted.Compress = true

	before, err := udpWireLen(fitted)
	if err != nil {
		return nil, nil, err
	}
	report := &FitUDPResponseReport{WireLengthBefore: before, WireLengthAfter: before}

	// The Question section and the OPT record must always be
	// preserved; make sure they fit on their own before trimming.
	answer, ns, extra := fitted.Answer, fitted.Ns, fitted.Extra
	fitted.Answer, fitted.Ns, fitted.Extra = nil, nil, nil
	if opt := msg.IsEdns0(); opt != nil {
		fitted.Extra = []RR{opt}
	}
	required, err := udpWireLen(fitted)
	fitted.Answer, fitted.Ns, fitted.Extra = answer, ns, extra
	if err != nil {
		return nil, nil, err
	}
	if required > limit {
		return nil, nil, fmt.Errorf("dns: question and OPT record alone need %d bytes, exceeding the %d byte limit", required, limit)
	}

	if before <= limit {
		return fitted, report, nil
	}

	current := before
	trim := func(section string, rrs []RR) ([]RR, error) {
		groups := groupRRsets(rrs)
		for i := len(groups) - 1; i >= 0 && current > limit; i-- {
			g := groups[i]
			rrs = removeGroup(rrs, g)
			report.Removed = append(report.Removed, TrimmedRRset{
				Section: section,
				Owner:   g.owner,
				Type:    g.typ,
				Count:   len(g.rrs),
			})
			switch section {
			case "Additional":
				fitted.Extra = rrs
			case "Authority":
				fitted.Ns = rrs
			case "Answer":
				fitted.Answer = rrs
			}
			if current, err = udpWireLen(fitted); err != nil {
				return nil, err
			}
		}
		return rrs, nil
	}

	if fitted.Extra, err = trim("Additional", fitted.Extra); err != nil {
		return nil, nil, err
	}
	if fitted.Ns, err = trim("Authority", fitted.Ns); err != nil {
		return nil, nil, err
	}
	if fitted.Answer, err = trim("Answer", fitted.Answer); err != nil {
		return nil, nil, err
	}

	// See Msg.Truncate for why we set TC: we cannot know which RRs are
	// "required", so any omitted RR raises the flag.
	if len(report.Removed) > 0 {
		fitted.Truncated = true
	}
	report.WireLengthAfter = current
	return fitted, report, nil
}

// udpWireLen returns the real wire length of m when packed.
func udpWireLen(m *Msg) (int, error) {
	buf, err := m.Pack()
	if err != nil {
		return 0, err
	}
	return len(buf), nil
}

// rrsetGroup is a set of RRs sharing owner, class and type, plus the
// RRSIG records covering them.
type rrsetGroup struct {
	owner string
	typ   uint16
	rrs   []RR
}

// groupRRsets groups rrs by owner name (case-insensitively), class and
// type, keeping first-appearance order. RRSIG records join the group of
// the RRset they sign. OPT records are not grouped; they are always
// preserved.
func groupRRsets(rrs []RR) []*rrsetGroup {
	var groups []*rrsetGroup
	index := make(map[string]*rrsetGroup)
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		h := rr.Header()
		if h.Rrtype == TypeOPT {
			continue
		}
		typ := h.Rrtype
		if sig, ok := rr.(*RRSIG); ok {
			typ = sig.TypeCovered
		}
		key := strings.ToLower(h.Name) + "\x00" + strconv.Itoa(int(h.Class)) + "\x00" + strconv.Itoa(int(typ))
		g := index[key]
		if g == nil {
			g = &rrsetGroup{owner: h.Name, typ: typ}
			index[key] = g
			groups = append(groups, g)
		}
		g.rrs = append(g.rrs, rr)
	}
	return groups
}

// removeGroup returns rrs with the records of g removed.
func removeGroup(rrs []RR, g *rrsetGroup) []RR {
	drop := make(map[RR]struct{}, len(g.rrs))
	for _, rr := range g.rrs {
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
