package dns

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
)

// RRsetDigest is a stable, content-based summary of a small RRset, intended
// for cache comparison: two RRsets that serve the same data produce the same
// digest regardless of record order or the case used in domain names.
//
// The digest is computed over a canonical wire-like form: the owner name and
// every domain name inside the RDATA are lowercased per DNS case-insensitive
// semantics (ASCII letters only, escape sequences such as \065 are decoded
// first), RDATA is sorted and deduplicated, and the TTL is deliberately
// excluded from the content identity. The TTL is reported separately as
// MinTTL/MaxTTL.
//
// Only the following record types are supported: A, AAAA, NS, CNAME, MX,
// SRV, SOA and TXT. Any other type is rejected with an error. TXT character
// strings are compared byte-for-byte: changing the case of TXT data changes
// the digest.
//
// Note: this is a read-only helper for comparing cached data. It is NOT an
// implementation of the DNSSEC canonical RR form (RFC 4034) and MUST NOT be
// used to generate or validate DNSSEC signatures.
type RRsetDigest struct {
	Owner   string            // canonical (lowercased, fully qualified) owner name
	Type    uint16            // RR type shared by the whole set
	Class   uint16            // class shared by the whole set
	Records int               // number of distinct RRs after deduplication
	MinTTL  uint32            // smallest TTL seen in the input
	MaxTTL  uint32            // largest TTL seen in the input
	Sum     [sha256.Size]byte // SHA-256 over the canonical content
}

// Hex returns the digest Sum as a lowercase hexadecimal string, suitable for
// reports and logs.
func (d RRsetDigest) Hex() string { return hex.EncodeToString(d.Sum[:]) }

// digestableTypes lists the RR types DigestRRset is willing to summarize.
var digestableTypes = map[uint16]bool{
	TypeA:     true,
	TypeAAAA:  true,
	TypeNS:    true,
	TypeCNAME: true,
	TypeMX:    true,
	TypeSRV:   true,
	TypeSOA:   true,
	TypeTXT:   true,
}

// DigestRRset computes a stable content digest for the RRset rrset. All RRs
// in rrset must share the same owner name (compared with DNS case
// semantics), type and class; a mixed set is rejected. RR types outside the
// supported list (A, AAAA, NS, CNAME, MX, SRV, SOA, TXT) are rejected with
// an error.
//
// The function is read-only: the input RRs, including their TTLs, are never
// modified.
func DigestRRset(rrset []RR) (RRsetDigest, error) {
	if len(rrset) == 0 {
		return RRsetDigest{}, &Error{err: "dns: DigestRRset: empty RRset"}
	}

	hdr := rrset[0].Header()
	d := RRsetDigest{
		Type:   hdr.Rrtype,
		Class:  hdr.Class,
		MinTTL: hdr.Ttl,
		MaxTTL: hdr.Ttl,
	}
	if !digestableTypes[d.Type] {
		return RRsetDigest{}, &Error{err: "dns: DigestRRset: unsupported type " + TypeToString[d.Type]}
	}

	ownerWire, err := packNameLower(hdr.Name)
	if err != nil {
		return RRsetDigest{}, &Error{err: "dns: DigestRRset: bad owner name: " + err.Error()}
	}

	seen := make(map[string]struct{}, len(rrset))
	rdatas := make([][]byte, 0, len(rrset))
	for i, rr := range rrset {
		h := rr.Header()
		if h.Rrtype != d.Type || h.Class != d.Class {
			return RRsetDigest{}, &Error{err: fmt.Sprintf("dns: DigestRRset: mixed type/class at record %d", i)}
		}
		w, err := packNameLower(h.Name)
		if err != nil {
			return RRsetDigest{}, &Error{err: "dns: DigestRRset: bad owner name: " + err.Error()}
		}
		if !bytes.Equal(w, ownerWire) {
			return RRsetDigest{}, &Error{err: fmt.Sprintf("dns: DigestRRset: mixed owner at record %d", i)}
		}
		if h.Ttl < d.MinTTL {
			d.MinTTL = h.Ttl
		}
		if h.Ttl > d.MaxTTL {
			d.MaxTTL = h.Ttl
		}

		rd, err := canonicalRdata(rr)
		if err != nil {
			return RRsetDigest{}, err
		}
		if _, dup := seen[string(rd)]; dup {
			continue
		}
		seen[string(rd)] = struct{}{}
		rdatas = append(rdatas, rd)
	}

	sort.Slice(rdatas, func(i, j int) bool { return bytes.Compare(rdatas[i], rdatas[j]) < 0 })
	d.Records = len(rdatas)

	owner, _, err := UnpackDomainName(ownerWire, 0)
	if err != nil {
		return RRsetDigest{}, &Error{err: "dns: DigestRRset: bad owner name: " + err.Error()}
	}
	d.Owner = owner

	h := sha256.New()
	h.Write(ownerWire)
	var tmp [4]byte
	binary.BigEndian.PutUint16(tmp[:2], d.Type)
	binary.BigEndian.PutUint16(tmp[2:], d.Class)
	h.Write(tmp[:])
	for _, rd := range rdatas {
		binary.BigEndian.PutUint16(tmp[:2], uint16(len(rd)))
		h.Write(tmp[:2])
		h.Write(rd)
	}
	copy(d.Sum[:], h.Sum(nil))
	return d, nil
}

// packNameLower packs name into its wire format and lowercases ASCII letters
// inside each label, implementing DNS case-insensitive comparison semantics.
// Escape sequences (e.g. \065 for 'A') are decoded by the packing step, so
// they are normalized as well.
func packNameLower(name string) ([]byte, error) {
	buf := make([]byte, 256)
	n, err := packDomainName(name, buf, 0, compressionMap{}, false)
	if err != nil {
		return nil, err
	}
	buf = buf[:n]
	for i := 0; i < len(buf) && buf[i] != 0; {
		l := int(buf[i])
		for j := i + 1; j <= i+l && j < len(buf); j++ {
			if c := buf[j]; c >= 'A' && c <= 'Z' {
				buf[j] = c + ('a' - 'A')
			}
		}
		i += l + 1
	}
	return buf, nil
}

// appendNameLower appends the canonical (lowercased) wire form of name to b.
func appendNameLower(b []byte, name string) ([]byte, error) {
	w, err := packNameLower(name)
	if err != nil {
		return nil, err
	}
	return append(b, w...), nil
}

// canonicalRdata returns the canonical content bytes of rr's RDATA: domain
// names lowercased per DNS case semantics, TXT strings preserved byte for
// byte, and no TTL. Unsupported types yield an error.
func canonicalRdata(rr RR) ([]byte, error) {
	var b []byte
	var tmp [20]byte
	put16 := func(v uint16) { binary.BigEndian.PutUint16(tmp[:2], v); b = append(b, tmp[:2]...) }
	put32 := func(v uint32) { binary.BigEndian.PutUint32(tmp[:4], v); b = append(b, tmp[:4]...) }

	switch t := rr.(type) {
	case *A:
		ip := t.A.To4()
		if ip == nil {
			return nil, &Error{err: "dns: DigestRRset: invalid A address"}
		}
		b = append(b, ip...)
	case *AAAA:
		ip := t.AAAA.To16()
		if ip == nil || t.AAAA.To4() != nil {
			return nil, &Error{err: "dns: DigestRRset: invalid AAAA address"}
		}
		b = append(b, ip...)
	case *NS:
		return appendNameLower(b, t.Ns)
	case *CNAME:
		return appendNameLower(b, t.Target)
	case *MX:
		put16(t.Preference)
		return appendNameLower(b, t.Mx)
	case *SRV:
		put16(t.Priority)
		put16(t.Weight)
		put16(t.Port)
		return appendNameLower(b, t.Target)
	case *SOA:
		var err error
		if b, err = appendNameLower(b, t.Ns); err != nil {
			return nil, err
		}
		if b, err = appendNameLower(b, t.Mbox); err != nil {
			return nil, err
		}
		put32(t.Serial)
		put32(t.Refresh)
		put32(t.Retry)
		put32(t.Expire)
		put32(t.Minttl)
	case *TXT:
		for _, s := range t.Txt {
			if len(s) > 255 {
				return nil, &Error{err: "dns: DigestRRset: TXT string too long"}
			}
			b = append(b, byte(len(s)))
			b = append(b, s...)
		}
	default:
		return nil, &Error{err: "dns: DigestRRset: unsupported type " + TypeToString[rr.Header().Rrtype]}
	}
	return b, nil
}
