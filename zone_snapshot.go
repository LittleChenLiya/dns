package dns

import (
	"errors"
	"fmt"
)

var (
	// ErrZoneSnapshot is returned when a zone snapshot is malformed.
	ErrZoneSnapshot = errors.New("invalid zone snapshot")
	// ErrIXFR is returned when an ordered IXFR RR stream is malformed or cannot be applied.
	ErrIXFR = errors.New("invalid IXFR")
)

// ZoneSnapshot is an immutable in-memory zone snapshot. The records are the
// complete zone, including its SOA record.
type ZoneSnapshot struct {
	records []RR
}

// NewZoneSnapshot returns an immutable snapshot containing records.
// Records are deep-copied, so later changes to records do not affect it.
func NewZoneSnapshot(records []RR) (*ZoneSnapshot, error) {
	return newZoneSnapshot(cloneRRs(records))
}

func newZoneSnapshot(records []RR) (*ZoneSnapshot, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("%w: no records", ErrZoneSnapshot)
	}
	if records[0] == nil {
		return nil, fmt.Errorf("%w: nil record", ErrZoneSnapshot)
	}
	if _, ok := records[0].(*SOA); !ok {
		return nil, fmt.Errorf("%w: first record is not SOA", ErrZoneSnapshot)
	}

	zoneName := CanonicalName(records[0].Header().Name)
	sets := make(map[string][]RR, len(records))
	soaCount := 0
	for _, rr := range records {
		if rr == nil {
			return nil, fmt.Errorf("%w: nil record", ErrZoneSnapshot)
		}
		header := rr.Header()
		if !IsSubDomain(zoneName, CanonicalName(header.Name)) {
			return nil, fmt.Errorf("%w: record %q is outside zone %q", ErrZoneSnapshot, header.Name, zoneName)
		}
		if _, ok := rr.(*SOA); ok {
			soaCount++
		}
		if findDuplicateRR(sets, rr) != nil {
			return nil, fmt.Errorf("%w: duplicate record %q", ErrZoneSnapshot, rr.String())
		}
		addRR(sets, rr)
	}
	if soaCount != 1 {
		return nil, fmt.Errorf("%w: expected one SOA record, got %d", ErrZoneSnapshot, soaCount)
	}

	return &ZoneSnapshot{records: records}, nil
}

// Records returns a deep-copy of all records in the snapshot.
func (s *ZoneSnapshot) Records() []RR {
	if s == nil {
		return nil
	}
	return cloneRRs(s.records)
}

// SOA returns a deep-copy of the snapshot SOA.
func (s *ZoneSnapshot) SOA() *SOA {
	if s == nil {
		return nil
	}
	return Copy(s.records[0]).(*SOA)
}

// ApplyIXFR validates rrs as an ordered IXFR response for old and, when every
// delta is valid, returns the resulting immutable snapshot. An IXFR response
// containing a complete AXFR is accepted as well. The old snapshot is never
// modified.
func ApplyIXFR(old *ZoneSnapshot, rrs []RR) (*ZoneSnapshot, error) {
	if old == nil {
		return nil, fmt.Errorf("%w: nil snapshot", ErrZoneSnapshot)
	}
	if len(old.records) == 0 || old.records[0] == nil {
		return nil, fmt.Errorf("%w: snapshot has no SOA", ErrZoneSnapshot)
	}
	if len(rrs) == 0 {
		return nil, fmt.Errorf("%w: no records", ErrIXFR)
	}

	current := &ZoneSnapshot{records: cloneRRs(old.records)}
	stream := cloneRRs(rrs)
	if err := applyTransferStream(current, stream); err != nil {
		return nil, err
	}
	return newZoneSnapshot(current.records)
}

func applyTransferStream(snapshot *ZoneSnapshot, stream []RR) error {
	for _, rr := range stream {
		if rr == nil {
			return fmt.Errorf("%w: nil record", ErrIXFR)
		}
	}
	firstSOA, ok := stream[0].(*SOA)
	if !ok {
		return fmt.Errorf("%w: transfer must start with SOA", ErrIXFR)
	}
	lastSOA, ok := stream[len(stream)-1].(*SOA)
	if !ok {
		return fmt.Errorf("%w: transfer must end with SOA", ErrIXFR)
	}
	if !sameSOA(firstSOA, lastSOA) {
		return fmt.Errorf("%w: outer SOA records do not match", ErrIXFR)
	}

	if len(stream) == 1 {
		if !sameSOA(snapshot.records[0].(*SOA), firstSOA) {
			return fmt.Errorf("%w: single SOA does not match snapshot", ErrIXFR)
		}
		return nil
	}

	if countSOA(stream) == 2 {
		return applyAXFR(snapshot, firstSOA, stream[1:len(stream)-1])
	}
	return applyIXFRDeltas(snapshot, stream)
}

func applyAXFR(snapshot *ZoneSnapshot, newSOA *SOA, records []RR) error {
	if !serialGreater(newSOA.Serial, snapshot.records[0].(*SOA).Serial) {
		return fmt.Errorf("%w: AXFR serial must be greater than snapshot serial", ErrIXFR)
	}
	result := make([]RR, 0, len(records)+1)
	result = append(result, Copy(newSOA))
	result = append(result, cloneRRs(records)...)
	valid, err := newZoneSnapshot(result)
	if err != nil {
		return err
	}
	snapshot.records = valid.records
	return nil
}

func applyIXFRDeltas(snapshot *ZoneSnapshot, stream []RR) error {
	position := 1
	for position < len(stream)-1 {
		oldSOA, ok := stream[position].(*SOA)
		if !ok {
			return fmt.Errorf("%w: missing delta old SOA", ErrIXFR)
		}
		if !sameSOA(snapshot.records[0].(*SOA), oldSOA) {
			return fmt.Errorf("%w: delta old SOA does not match current snapshot", ErrIXFR)
		}

		newPosition := nextSOAIndex(stream, position+1)
		if newPosition < 0 {
			return fmt.Errorf("%w: missing delta new SOA", ErrIXFR)
		}
		newSOA := stream[newPosition].(*SOA)
		if !serialGreater(newSOA.Serial, oldSOA.Serial) {
			return fmt.Errorf("%w: serial %d does not succeed %d", ErrIXFR, newSOA.Serial, oldSOA.Serial)
		}

		deletes := stream[position+1 : newPosition]
		endPosition := nextSOAIndex(stream, newPosition+1)
		if endPosition < 0 {
			return fmt.Errorf("%w: missing final SOA", ErrIXFR)
		}
		endSOA := stream[endPosition].(*SOA)
		if !sameSOA(endSOA, newSOA) {
			return fmt.Errorf("%w: delta boundary SOA records do not match", ErrIXFR)
		}
		adds := stream[newPosition+1 : endPosition]

		if err := applyDelta(snapshot, deletes, adds, newSOA); err != nil {
			return err
		}
		if endPosition == len(stream)-1 {
			return nil
		}
		position = endPosition
	}
	return fmt.Errorf("%w: incomplete delta", ErrIXFR)
}

func applyDelta(snapshot *ZoneSnapshot, deletes, adds []RR, newSOA *SOA) error {
	indexSets := make(map[string][]int, len(snapshot.records))
	for _, rr := range snapshot.records[1:] {
		indexSets[rrSetKey(rr)] = append(indexSets[rrSetKey(rr)], len(indexSets[rrSetKey(rr)]))
	}
	deleted := make(map[int]struct{}, len(deletes))

	for _, rr := range deletes {
		if _, ok := rr.(*SOA); ok {
			return fmt.Errorf("%w: SOA must only appear as a delta boundary", ErrIXFR)
		}
		index, ok := findRRIndex(indexSets, deleted, snapshot.records[1:], rr)
		if !ok {
			return fmt.Errorf("%w: deleted record %q does not exist", ErrIXFR, rr.String())
		}
		deleted[index] = struct{}{}
	}

	for addIndex, rr := range adds {
		if _, ok := rr.(*SOA); ok {
			return fmt.Errorf("%w: SOA must only appear as a delta boundary", ErrIXFR)
		}
		key := rrSetKey(rr)
		for _, index := range indexSets[key] {
			if _, isDeleted := deleted[index]; isDeleted {
				continue
			}
			if IsDuplicate(snapshot.records[index+1], rr) {
				return fmt.Errorf("%w: added record %q already exists", ErrIXFR, rr.String())
			}
		}
		for previous := 0; previous < addIndex; previous++ {
			if rrSetKey(adds[previous]) == key && IsDuplicate(adds[previous], rr) {
				return fmt.Errorf("%w: duplicate added record %q", ErrIXFR, rr.String())
			}
		}
	}

	ordered := make([]RR, 0, 1+len(snapshot.records)-1-len(deleted)+len(adds))
	ordered = append(ordered, Copy(newSOA))
	for i, rr := range snapshot.records[1:] {
		if _, ok := deleted[i]; !ok {
			ordered = append(ordered, Copy(rr))
		}
	}
	ordered = append(ordered, cloneRRs(adds)...)

	valid, err := newZoneSnapshot(ordered)
	if err != nil {
		return err
	}
	snapshot.records = valid.records
	return nil
}

func nextSOAIndex(rrs []RR, start int) int {
	for i := start; i < len(rrs); i++ {
		if _, ok := rrs[i].(*SOA); ok {
			return i
		}
	}
	return -1
}

func countSOA(rrs []RR) int {
	n := 0
	for _, rr := range rrs {
		if _, ok := rr.(*SOA); ok {
			n++
		}
	}
	return n
}

func sameSOA(a, b *SOA) bool {
	return a != nil && b != nil && sameRR(a, b)
}

// serialGreater implements RFC 1982 serial number arithmetic. Equal serials
// and the ambiguous half-space boundary are not greater.
func serialGreater(new, old uint32) bool {
	diff := new - old
	return diff > 0 && diff < 1<<31
}

func rrSetKey(rr RR) string {
	header := rr.Header()
	return fmt.Sprintf("%s/%d/%d", CanonicalName(header.Name), header.Class, header.Rrtype)
}

func sameRR(a, b RR) bool {
	return IsDuplicate(a, b) && a.Header().Ttl == b.Header().Ttl
}

func findDuplicateRR(sets map[string][]RR, rr RR) RR {
	for _, existing := range sets[rrSetKey(rr)] {
		if IsDuplicate(existing, rr) {
			return existing
		}
	}
	return nil
}

func addRR(sets map[string][]RR, rr RR) {
	key := rrSetKey(rr)
	sets[key] = append(sets[key], rr)
}

func findRRIndex(indexSets map[string][]int, deleted map[int]struct{}, records []RR, rr RR) (int, bool) {
	for _, index := range indexSets[rrSetKey(rr)] {
		if _, ok := deleted[index]; ok {
			continue
		}
		if sameRR(records[index], rr) {
			return index, true
		}
	}
	return 0, false
}

func cloneRRs(rrs []RR) []RR {
	copied := make([]RR, len(rrs))
	for i, rr := range rrs {
		if rr != nil {
			copied[i] = Copy(rr)
		}
	}
	return copied
}
