package dns

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ZoneSnapshot is an immutable in-memory snapshot of a zone's contents at a
// specific SOA serial. It is the input and output of IXFR delta application:
// the network side of a transfer is handled by Transfer, while ZoneSnapshot
// validates the received increments and produces a new snapshot.
//
// A ZoneSnapshot is never modified after creation; all methods are safe for
// concurrent use.
type ZoneSnapshot struct {
	soa *SOA
	rrs map[string]RR // canonical key -> RR, excludes the SOA record
}

// NewZoneSnapshot builds an immutable snapshot from the zone's records. The
// records must contain exactly one SOA record.
func NewZoneSnapshot(rrs []RR) (*ZoneSnapshot, error) {
	z := &ZoneSnapshot{rrs: make(map[string]RR, len(rrs))}
	for _, rr := range rrs {
		if rr == nil {
			return nil, errors.New("dns: nil RR in zone snapshot")
		}
		if soa, ok := rr.(*SOA); ok {
			if z.soa != nil {
				return nil, errors.New("dns: multiple SOA records in zone snapshot")
			}
			z.soa = Copy(soa).(*SOA)
			continue
		}
		z.rrs[zoneSnapshotKey(rr)] = Copy(rr)
	}
	if z.soa == nil {
		return nil, errors.New("dns: zone snapshot has no SOA record")
	}
	return z, nil
}

// Serial returns the SOA serial of the snapshot.
func (z *ZoneSnapshot) Serial() uint32 { return z.soa.Serial }

// SOA returns a copy of the snapshot's SOA record.
func (z *ZoneSnapshot) SOA() *SOA { return Copy(z.soa).(*SOA) }

// Records returns copies of all records in the snapshot: the SOA first,
// followed by the remaining records sorted by their canonical form.
func (z *ZoneSnapshot) Records() []RR {
	keys := make([]string, 0, len(z.rrs))
	for k := range z.rrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]RR, 0, len(keys)+1)
	out = append(out, Copy(z.soa))
	for _, k := range keys {
		out = append(out, Copy(z.rrs[k]))
	}
	return out
}

// Hash returns a digest over the snapshot's canonical content. It can be used
// to verify that a snapshot was left untouched by a failed ApplyIXFR call.
func (z *ZoneSnapshot) Hash() [32]byte {
	h := sha256.New()
	for _, rr := range z.Records() {
		h.Write([]byte(zoneSnapshotKey(rr)))
		h.Write([]byte{0})
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// ApplyIXFR applies an ordered RR stream, as received from an IXFR (or an
// AXFR fallback) response, to the snapshot and returns the resulting new
// snapshot. The receiver is never modified; if any delta in the stream is
// invalid an error is returned and no snapshot is produced.
//
// The stream must follow RFC 1995: a leading SOA with the final serial, then
// one or more deltas, each consisting of the old-serial SOA, the deleted
// records, the new-serial SOA and the added records, and finally a closing
// copy of the leading SOA. Multiple deltas may be concatenated; they are
// validated and committed atomically. If the server fell back to AXFR (the
// leading SOA is followed by zone data instead of an older SOA), the stream
// is treated as a full zone replacement.
func (z *ZoneSnapshot) ApplyIXFR(stream []RR) (*ZoneSnapshot, error) {
	if len(stream) < 2 {
		return nil, errors.New("dns: ixfr: stream too short")
	}
	first, ok := stream[0].(*SOA)
	if !ok {
		return nil, errors.New("dns: ixfr: stream does not start with an SOA record")
	}
	if !strings.EqualFold(first.Hdr.Name, z.soa.Hdr.Name) {
		return nil, fmt.Errorf("dns: ixfr: SOA owner %q does not match zone %q", first.Hdr.Name, z.soa.Hdr.Name)
	}
	// AXFR fallback: the record after the leading SOA is not an SOA carrying
	// an older serial, so the server sent a full zone transfer instead of
	// deltas.
	if second, ok := stream[1].(*SOA); !ok || second.Serial == first.Serial {
		return z.applyAXFR(stream, first)
	}
	return z.applyDeltas(stream, first)
}

// applyAXFR treats the stream as a full zone transfer: a leading SOA, the
// zone's records and a closing SOA with the same serial.
func (z *ZoneSnapshot) applyAXFR(stream []RR, first *SOA) (*ZoneSnapshot, error) {
	last, ok := stream[len(stream)-1].(*SOA)
	if !ok || last.Serial != first.Serial {
		return nil, errors.New("dns: axfr fallback: missing closing SOA record")
	}
	rrs := make([]RR, 0, len(stream)-1)
	rrs = append(rrs, first)
	for _, rr := range stream[1 : len(stream)-1] {
		if _, ok := rr.(*SOA); ok {
			return nil, errors.New("dns: axfr fallback: unexpected SOA record in zone body")
		}
		rrs = append(rrs, rr)
	}
	return NewZoneSnapshot(rrs)
}

// applyDeltas validates and applies the concatenated IXFR deltas in stream.
// All deltas are applied to a private working copy; only when the complete
// stream checks out is a new snapshot assembled, so a malformed or
// non-applicable delta can never leak a partial result.
func (z *ZoneSnapshot) applyDeltas(stream []RR, first *SOA) (*ZoneSnapshot, error) {
	finalSerial := first.Serial
	work := make(map[string]RR, len(z.rrs))
	for k, v := range z.rrs {
		work[k] = v
	}
	serial := z.soa.Serial

	i := 1
	for {
		if i >= len(stream) {
			return nil, errors.New("dns: ixfr: unexpected end of stream, expected old-serial SOA")
		}
		oldSOA, ok := stream[i].(*SOA)
		if !ok {
			return nil, fmt.Errorf("dns: ixfr: expected old-serial SOA at position %d, got %s", i, TypeToString[stream[i].Header().Rrtype])
		}
		if oldSOA.Serial != serial {
			return nil, fmt.Errorf("dns: ixfr: delta starts at serial %d, but zone is at serial %d", oldSOA.Serial, serial)
		}
		i++

		var dels []RR
		for i < len(stream) && stream[i].Header().Rrtype != TypeSOA {
			dels = append(dels, stream[i])
			i++
		}
		if i >= len(stream) {
			return nil, errors.New("dns: ixfr: unexpected end of stream, expected new-serial SOA")
		}
		newSOA := stream[i].(*SOA)
		i++
		if !serialAhead(newSOA.Serial, oldSOA.Serial) {
			return nil, fmt.Errorf("dns: ixfr: serial %d does not follow %d in RFC 1982 serial number arithmetic", newSOA.Serial, oldSOA.Serial)
		}

		var adds []RR
		for i < len(stream) && stream[i].Header().Rrtype != TypeSOA {
			adds = append(adds, stream[i])
			i++
		}

		for _, rr := range dels {
			k := zoneSnapshotKey(rr)
			if _, ok := work[k]; !ok {
				return nil, fmt.Errorf("dns: ixfr: delta deletes non-existent record %q", rr.String())
			}
			delete(work, k)
		}
		for _, rr := range adds {
			work[zoneSnapshotKey(rr)] = rr
		}
		serial = newSOA.Serial
		if serial == finalSerial {
			break
		}
	}

	if i >= len(stream) {
		return nil, errors.New("dns: ixfr: missing closing SOA record")
	}
	closing, ok := stream[i].(*SOA)
	if !ok || closing.Serial != finalSerial {
		return nil, errors.New("dns: ixfr: missing closing SOA record")
	}
	if i != len(stream)-1 {
		return nil, errors.New("dns: ixfr: trailing records after closing SOA")
	}

	nz := &ZoneSnapshot{soa: Copy(first).(*SOA), rrs: make(map[string]RR, len(work))}
	for k, v := range work {
		nz.rrs[k] = Copy(v)
	}
	return nz, nil
}

// serialAhead reports whether new follows old in RFC 1982 serial number
// arithmetic. A difference of exactly 2^31 is ambiguous (the half-space
// boundary) and is not considered ahead, nor is a serial that lies behind.
func serialAhead(new, old uint32) bool {
	return new != old && new-old < 1<<31
}

// zoneSnapshotKey returns the canonical identity of an RR used for set
// membership inside a snapshot.
func zoneSnapshotKey(rr RR) string {
	return strings.ToLower(rr.String())
}
