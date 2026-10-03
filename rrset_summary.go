package dns

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
)

// RRsetSummary is a stable, read-only content summary of a small RRset,
// intended for cache comparison. Two RRsets with the same owner, type and
// class and the same normalized RDATA produce the same summary.
//
// RRsetSummary is NOT a DNSSEC signature and must not be used as one. It
// provides no authentication or integrity guarantee beyond what a plain
// content hash offers. It is a read-only tool: the input RRs are never
// modified.
//
// The content identity covers the owner, type, class and the normalized
// RDATA of every record in the RRset. TTL is deliberately excluded from
// the content identity and reported separately as TTLMin and TTLMax.
type RRsetSummary struct {
	owner  string
	rrtype uint16
	class  uint16
	ttlMin uint32
	ttlMax uint32
	digest []byte
}

// Owner returns the canonical (lowercase, fully qualified) owner name of
// the RRset.
func (s RRsetSummary) Owner() string { return s.owner }

// Type returns the RR type of the RRset.
func (s RRsetSummary) Type() uint16 { return s.rrtype }

// Class returns the RR class of the RRset.
func (s RRsetSummary) Class() uint16 { return s.class }

// TTLMin returns the minimum TTL across all records in the RRset.
func (s RRsetSummary) TTLMin() uint32 { return s.ttlMin }

// TTLMax returns the maximum TTL across all records in the RRset.
func (s RRsetSummary) TTLMax() uint32 { return s.ttlMax }

// Digest returns the content digest of the RRset. The digest is a
// SHA-256 hash over the normalized, sorted and deduplicated wire-format
// records of the RRset, with TTL zeroed.
func (s RRsetSummary) Digest() []byte { return s.digest }

// Hex returns a hex-encoded report of the summary, suitable for logging
// or display. The digest is rendered as a lowercase hexadecimal string.
func (s RRsetSummary) Hex() string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "owner:   %s\n", s.owner)
	fmt.Fprintf(&buf, "type:    %s (%d)\n", Type(s.rrtype), s.rrtype)
	fmt.Fprintf(&buf, "class:   %s (%d)\n", Class(s.class), s.class)
	fmt.Fprintf(&buf, "ttl:     %d - %d\n", s.ttlMin, s.ttlMax)
	fmt.Fprintf(&buf, "digest:  %x\n", s.digest)
	return buf.String()
}

// String returns the same hex-encoded report as Hex.
func (s RRsetSummary) String() string { return s.Hex() }

// rrsetGroupKey identifies a group of RRs that share the same canonical
// owner, type and class.
type rrsetGroupKey struct {
	owner  string
	rrtype uint16
	class  uint16
}

// SummarizeRRsets groups rrs into RRsets by owner, type and class and
// returns a stable, read-only content summary for each group. The
// summaries are sorted by owner, type and class for deterministic output.
//
// Only the explicitly supported types A, AAAA, NS, CNAME, MX, SRV, SOA
// and TXT are accepted. Any other type (including RFC3597 unknown RRs)
// is rejected with an error.
//
// The input RRs and their TTLs are not modified. The owner and
// domain-type RDATA are normalized per DNS case semantics (lowercase,
// fully qualified). TXT bytes are preserved verbatim. TTL is excluded
// from the content identity and reported separately as TTLMin and
// TTLMax. After normalization, the records are packed to wire format,
// sorted lexicographically and deduplicated before hashing.
//
// SummarizeRRsets is NOT a DNSSEC signing tool and must not be used as
// one. It is intended for cache comparison and change detection.
func SummarizeRRsets(rrs []RR) ([]RRsetSummary, error) {
	groups := make(map[rrsetGroupKey][]RR)
	var groupOrder []rrsetGroupKey

	for _, rr := range rrs {
		if rr == nil {
			return nil, &Error{err: "nil rr"}
		}
		h := rr.Header()
		if !isSupportedSummaryType(h.Rrtype) {
			return nil, &Error{err: fmt.Sprintf("unsupported RR type for summary: %s (%d)", Type(h.Rrtype), h.Rrtype)}
		}
		owner, err := canonicalSummaryName(h.Name)
		if err != nil {
			return nil, err
		}
		key := rrsetGroupKey{owner: owner, rrtype: h.Rrtype, class: h.Class}
		if _, ok := groups[key]; !ok {
			groupOrder = append(groupOrder, key)
		}
		groups[key] = append(groups[key], rr)
	}

	summaries := make([]RRsetSummary, 0, len(groups))
	for _, key := range groupOrder {
		summary, err := summarizeRRsetGroup(key, groups[key])
		if err != nil {
			return nil, err
		}
		summaries = append(summaries, summary)
	}

	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].owner != summaries[j].owner {
			return summaries[i].owner < summaries[j].owner
		}
		if summaries[i].rrtype != summaries[j].rrtype {
			return summaries[i].rrtype < summaries[j].rrtype
		}
		return summaries[i].class < summaries[j].class
	})

	return summaries, nil
}

// isSupportedSummaryType reports whether t is one of the explicitly
// supported RR types for summarization.
func isSupportedSummaryType(t uint16) bool {
	switch t {
	case TypeA, TypeAAAA, TypeNS, TypeCNAME, TypeMX, TypeSRV, TypeSOA, TypeTXT:
		return true
	}
	return false
}

// summarizeRRsetGroup computes the content summary for a single RRset
// group. The group is identified by key and contains the RRs in group.
func summarizeRRsetGroup(key rrsetGroupKey, group []RR) (RRsetSummary, error) {
	var ttlMin, ttlMax uint32
	var haveTTL bool
	wires := make([][]byte, 0, len(group))

	for _, rr := range group {
		h := rr.Header()
		if !haveTTL {
			ttlMin = h.Ttl
			ttlMax = h.Ttl
			haveTTL = true
		} else {
			if h.Ttl < ttlMin {
				ttlMin = h.Ttl
			}
			if h.Ttl > ttlMax {
				ttlMax = h.Ttl
			}
		}

		// Copy the RR so the input is not modified.
		rrCopy := Copy(rr)
		ch := rrCopy.Header()

		// Canonicalize the owner.
		owner, err := canonicalSummaryName(ch.Name)
		if err != nil {
			return RRsetSummary{}, err
		}
		ch.Name = owner

		// Canonicalize domain-type RDATA.
		if err := canonicalizeSummaryRdata(rrCopy); err != nil {
			return RRsetSummary{}, err
		}

		// Zero the TTL so it does not affect the content identity.
		ch.Ttl = 0

		// Pack to wire format (uncompressed).
		buf := make([]byte, Len(rrCopy)+1)
		off, err := PackRR(rrCopy, buf, 0, nil, false)
		if err != nil {
			return RRsetSummary{}, err
		}
		wires = append(wires, buf[:off])
	}

	// Sort and deduplicate by wire format.
	sort.Slice(wires, func(i, j int) bool {
		return bytes.Compare(wires[i], wires[j]) < 0
	})
	wires = dedupSummaryWires(wires)

	// Compute the content digest.
	h := sha256.New()
	for _, wire := range wires {
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(wire)))
		h.Write(lenBuf[:])
		h.Write(wire)
	}

	return RRsetSummary{
		owner:  key.owner,
		rrtype: key.rrtype,
		class:  key.class,
		ttlMin: ttlMin,
		ttlMax: ttlMax,
		digest: h.Sum(nil),
	}, nil
}

// canonicalizeSummaryRdata canonicalizes domain-type RDATA in rr. The
// owner is handled separately. TXT bytes are preserved and not
// canonicalized.
func canonicalizeSummaryRdata(rr RR) error {
	switch x := rr.(type) {
	case *A, *AAAA:
		// No domain names in RDATA.
	case *NS:
		name, err := canonicalSummaryName(x.Ns)
		if err != nil {
			return err
		}
		x.Ns = name
	case *CNAME:
		name, err := canonicalSummaryName(x.Target)
		if err != nil {
			return err
		}
		x.Target = name
	case *MX:
		name, err := canonicalSummaryName(x.Mx)
		if err != nil {
			return err
		}
		x.Mx = name
	case *SRV:
		name, err := canonicalSummaryName(x.Target)
		if err != nil {
			return err
		}
		x.Target = name
	case *SOA:
		name, err := canonicalSummaryName(x.Ns)
		if err != nil {
			return err
		}
		x.Ns = name
		if name, err = canonicalSummaryName(x.Mbox); err != nil {
			return err
		}
		x.Mbox = name
	case *TXT:
		// TXT bytes are preserved verbatim; no canonicalization.
	default:
		return &Error{err: fmt.Sprintf("unsupported RR type for summary: %T", rr)}
	}
	return nil
}

// canonicalSummaryName returns the canonical form of a domain name for
// summarization. The name is fully qualified and all label bytes are
// lowercased (A-Z to a-z), including bytes expressed as escape sequences
// such as \065. This matches DNS case semantics where case is not
// significant.
func canonicalSummaryName(s string) (string, error) {
	fqdn := Fqdn(s)
	buf := make([]byte, maxDomainNameWireOctets+1)
	off, err := PackDomainName(fqdn, buf, 0, nil, false)
	if err != nil {
		return "", err
	}
	wire := buf[:off]
	lowerSummaryLabelBytes(wire)
	canonical, _, err := UnpackDomainName(wire, 0)
	if err != nil {
		return "", err
	}
	return canonical, nil
}

// lowerSummaryLabelBytes lowercases A-Z bytes in each label of a
// wire-format domain name. The wire must be uncompressed (no pointers).
func lowerSummaryLabelBytes(wire []byte) {
	off := 0
	for off < len(wire) {
		l := int(wire[off])
		if l == 0 {
			return // end of name
		}
		off++
		for i := 0; i < l && off < len(wire); i++ {
			if wire[off] >= 'A' && wire[off] <= 'Z' {
				wire[off] += 'a' - 'A'
			}
			off++
		}
	}
}

// dedupSummaryWires removes duplicate wire-format records, preserving
// the first occurrence. wires must be sorted.
func dedupSummaryWires(wires [][]byte) [][]byte {
	if len(wires) == 0 {
		return wires
	}
	out := wires[:1]
	for _, wire := range wires[1:] {
		if !bytes.Equal(out[len(out)-1], wire) {
			out = append(out, wire)
		}
	}
	return out
}
