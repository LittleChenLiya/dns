package dns

import (
	"fmt"
	"testing"
)

func ixfrTestSOA(serial uint32) *SOA {
	rr, err := NewRR(fmt.Sprintf("example. 3600 IN SOA ns1.example. hostmaster.example. %d 3600 600 604800 3600", serial))
	if err != nil {
		panic(err)
	}
	return rr.(*SOA)
}

func ixfrTestRR(s string) RR {
	rr, err := NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}

func ixfrTestZone(t *testing.T, serial uint32, records ...RR) *ZoneSnapshot {
	t.Helper()
	z, err := NewZoneSnapshot(append([]RR{ixfrTestSOA(serial)}, records...))
	if err != nil {
		t.Fatalf("NewZoneSnapshot: %v", err)
	}
	return z
}

// ixfrDelta builds one delta section: old SOA, deletions, new SOA, additions.
func ixfrDelta(oldSerial, newSerial uint32, dels, adds []RR) []RR {
	out := []RR{ixfrTestSOA(oldSerial)}
	out = append(out, dels...)
	out = append(out, ixfrTestSOA(newSerial))
	out = append(out, adds...)
	return out
}

// ixfrStream assembles a full IXFR stream from concatenated deltas.
func ixfrStream(finalSerial uint32, deltas ...[]RR) []RR {
	out := []RR{ixfrTestSOA(finalSerial)}
	for _, d := range deltas {
		out = append(out, d...)
	}
	return append(out, ixfrTestSOA(finalSerial))
}

func snapshotHas(z *ZoneSnapshot, rr RR) bool {
	key := zoneSnapshotKey(rr)
	for _, have := range z.Records() {
		if zoneSnapshotKey(have) == key {
			return true
		}
	}
	return false
}

func TestIXFRApplySingleDelta(t *testing.T) {
	a := ixfrTestRR("a.example. 3600 IN A 192.0.2.1")
	b := ixfrTestRR("b.example. 3600 IN A 192.0.2.2")
	zone := ixfrTestZone(t, 10, a)

	stream := ixfrStream(11, ixfrDelta(10, 11, []RR{a}, []RR{b}))
	nz, err := zone.ApplyIXFR(stream)
	if err != nil {
		t.Fatalf("ApplyIXFR: %v", err)
	}
	if nz.Serial() != 11 {
		t.Errorf("expected serial 11, got %d", nz.Serial())
	}
	if !snapshotHas(nz, b) {
		t.Error("new snapshot does not contain b")
	}
	if snapshotHas(nz, a) {
		t.Error("new snapshot still contains deleted record a")
	}
	if got := len(nz.Records()); got != 2 { // SOA + b
		t.Errorf("expected 2 records in new snapshot, got %d", got)
	}
	// The input snapshot must be untouched.
	if zone.Serial() != 10 || !snapshotHas(zone, a) {
		t.Error("input snapshot was modified")
	}
}

func TestIXFRApplyMultipleDeltas(t *testing.T) {
	a := ixfrTestRR("a.example. 3600 IN A 192.0.2.1")
	b := ixfrTestRR("b.example. 3600 IN A 192.0.2.2")
	d := ixfrTestRR("d.example. 3600 IN A 192.0.2.4")
	zone := ixfrTestZone(t, 10, a)

	stream := ixfrStream(12,
		ixfrDelta(10, 11, []RR{a}, []RR{b}),
		ixfrDelta(11, 12, []RR{b}, []RR{d}),
	)
	nz, err := zone.ApplyIXFR(stream)
	if err != nil {
		t.Fatalf("ApplyIXFR: %v", err)
	}
	if nz.Serial() != 12 {
		t.Errorf("expected serial 12, got %d", nz.Serial())
	}
	if !snapshotHas(nz, d) || snapshotHas(nz, a) || snapshotHas(nz, b) {
		t.Errorf("unexpected snapshot contents: %v", nz.Records())
	}
}

func TestIXFRApplyDeleteMissing(t *testing.T) {
	a := ixfrTestRR("a.example. 3600 IN A 192.0.2.1")
	b := ixfrTestRR("b.example. 3600 IN A 192.0.2.2")
	c := ixfrTestRR("c.example. 3600 IN A 192.0.2.3")
	zone := ixfrTestZone(t, 10, a)
	before := zone.Hash()

	// The second delta deletes c, which does not exist at that point: the
	// whole stream must be rejected.
	stream := ixfrStream(12,
		ixfrDelta(10, 11, []RR{a}, []RR{b}),
		ixfrDelta(11, 12, []RR{c}, nil),
	)
	if _, err := zone.ApplyIXFR(stream); err == nil {
		t.Fatal("expected error for deletion of non-existent record")
	}
	if zone.Hash() != before {
		t.Error("input snapshot hash changed after failed ApplyIXFR")
	}
	if zone.Serial() != 10 || !snapshotHas(zone, a) {
		t.Error("input snapshot was modified")
	}
}

func TestIXFRApplySerialWrap(t *testing.T) {
	a := ixfrTestRR("a.example. 3600 IN A 192.0.2.1")
	b := ixfrTestRR("b.example. 3600 IN A 192.0.2.2")
	zone := ixfrTestZone(t, 4294967295, a)

	stream := ixfrStream(0, ixfrDelta(4294967295, 0, []RR{a}, []RR{b}))
	nz, err := zone.ApplyIXFR(stream)
	if err != nil {
		t.Fatalf("ApplyIXFR: %v", err)
	}
	if nz.Serial() != 0 {
		t.Errorf("expected serial 0 after wrap, got %d", nz.Serial())
	}
	if !snapshotHas(nz, b) || snapshotHas(nz, a) {
		t.Errorf("unexpected snapshot contents: %v", nz.Records())
	}
}

func TestIXFRApplySerialHalfSpace(t *testing.T) {
	a := ixfrTestRR("a.example. 3600 IN A 192.0.2.1")
	zone := ixfrTestZone(t, 0, a)

	// A difference of exactly 2^31 is ambiguous per RFC 1982.
	ambiguous := ixfrStream(1<<31, ixfrDelta(0, 1<<31, nil, nil))
	if _, err := zone.ApplyIXFR(ambiguous); err == nil {
		t.Error("expected error for half-space ambiguous serial")
	}

	// A serial lying behind the current one is not a valid increment.
	zone10 := ixfrTestZone(t, 10, a)
	behind := ixfrStream(5, ixfrDelta(10, 5, nil, nil))
	if _, err := zone10.ApplyIXFR(behind); err == nil {
		t.Error("expected error for serial going backwards")
	}
}

func TestIXFRApplyAXFRFallback(t *testing.T) {
	a := ixfrTestRR("a.example. 3600 IN A 192.0.2.1")
	x := ixfrTestRR("x.example. 3600 IN A 192.0.2.10")
	y := ixfrTestRR("y.example. 3600 IN A 192.0.2.11")
	zone := ixfrTestZone(t, 10, a)

	// Server answered the IXFR query with a full zone transfer.
	stream := []RR{ixfrTestSOA(11), x, y, ixfrTestSOA(11)}
	nz, err := zone.ApplyIXFR(stream)
	if err != nil {
		t.Fatalf("ApplyIXFR: %v", err)
	}
	if nz.Serial() != 11 {
		t.Errorf("expected serial 11, got %d", nz.Serial())
	}
	if !snapshotHas(nz, x) || !snapshotHas(nz, y) || snapshotHas(nz, a) {
		t.Errorf("unexpected snapshot contents: %v", nz.Records())
	}
}

func TestIXFRApplyParseBoundaries(t *testing.T) {
	a := ixfrTestRR("a.example. 3600 IN A 192.0.2.1")
	zone := ixfrTestZone(t, 10, a)

	tests := []struct {
		name   string
		stream []RR
	}{
		{"empty", nil},
		{"too short", []RR{ixfrTestSOA(11)}},
		{"no leading SOA", []RR{a, ixfrTestSOA(11)}},
		{"owner mismatch", []RR{
			ixfrTestRR("other. 3600 IN SOA ns1.other. h.other. 11 3600 600 604800 3600"),
			ixfrTestSOA(10), ixfrTestSOA(11), ixfrTestSOA(11),
		}},
		{"delta for wrong serial", ixfrStream(11, ixfrDelta(9, 11, nil, nil))},
		{"missing new-serial SOA", []RR{ixfrTestSOA(11), ixfrTestSOA(10), a}},
		{"missing closing SOA", []RR{ixfrTestSOA(11), ixfrTestSOA(10), ixfrTestSOA(11)}},
		{"trailing garbage", append(ixfrStream(11, ixfrDelta(10, 11, nil, nil)), a)},
		{"unterminated chain", []RR{
			ixfrTestSOA(12), ixfrTestSOA(10), ixfrTestSOA(11), ixfrTestSOA(12),
		}},
		{"axfr missing closing SOA", []RR{ixfrTestSOA(11), a}},
		{"axfr stray SOA in body", []RR{ixfrTestSOA(11), a, ixfrTestSOA(11), a, ixfrTestSOA(11)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := zone.ApplyIXFR(tc.stream); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestZoneSnapshotImmutability(t *testing.T) {
	a := ixfrTestRR("a.example. 3600 IN A 192.0.2.1")
	b := ixfrTestRR("b.example. 3600 IN A 192.0.2.2")
	zone := ixfrTestZone(t, 10, a)

	// Mutating the records handed to NewZoneSnapshot must not affect it.
	a.(*A).A = []byte{192, 0, 2, 99}
	if snapshotHas(zone, a) {
		t.Error("snapshot changed after mutating input RR")
	}
	a.(*A).A = []byte{192, 0, 2, 1}

	nz, err := zone.ApplyIXFR(ixfrStream(11, ixfrDelta(10, 11, []RR{a}, []RR{b})))
	if err != nil {
		t.Fatalf("ApplyIXFR: %v", err)
	}
	// Mutating the returned records must not affect the snapshot.
	for _, rr := range nz.Records() {
		if arec, ok := rr.(*A); ok {
			arec.A = []byte{192, 0, 2, 99}
		}
	}
	if !snapshotHas(nz, b) {
		t.Error("snapshot changed after mutating returned records")
	}
}
