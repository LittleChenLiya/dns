package dns

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func testSnapshotSOA(serial uint32) *SOA {
	return testRR(fmt.Sprintf("example. 3600 IN SOA ns.example. hostmaster.example. %d 60 60 60 3600", serial)).(*SOA)
}

func testSnapshotA(name, addr string) RR {
	return testRR(fmt.Sprintf("%s 3600 IN A %s", name, addr))
}

func mustNewZoneSnapshot(t *testing.T, records []RR) *ZoneSnapshot {
	t.Helper()
	snapshot, err := NewZoneSnapshot(records)
	if err != nil {
		t.Fatalf("NewZoneSnapshot() error: %v", err)
	}
	return snapshot
}

func snapshotHash(t *testing.T, snapshot *ZoneSnapshot) [32]byte {
	t.Helper()
	h := sha256.New()
	for _, rr := range snapshot.Records() {
		h.Write([]byte(rr.String()))
		h.Write([]byte{0})
	}
	return [32]byte(h.Sum(nil))
}

func assertSnapshotRecords(t *testing.T, snapshot *ZoneSnapshot, serial uint32, addrs map[string]string) {
	t.Helper()
	if got := snapshot.SOA().Serial; got != serial {
		t.Fatalf("SOA serial = %d, want %d", got, serial)
	}
	got := make(map[string]string)
	for _, rr := range snapshot.Records() {
		if a, ok := rr.(*A); ok {
			got[a.Hdr.Name] = a.A.String()
		}
	}
	if len(got) != len(addrs) {
		t.Fatalf("A records = %v, want %v", got, addrs)
	}
	for name, addr := range addrs {
		if got[name] != addr {
			t.Fatalf("A record %q = %q, want %q", name, got[name], addr)
		}
	}
}

func TestApplyIXFRSingleDelta(t *testing.T) {
	old := mustNewZoneSnapshot(t, []RR{testSnapshotSOA(10), testSnapshotA("a.example.", "192.0.2.1")})
	rrs := []RR{
		testSnapshotSOA(11),
		testSnapshotSOA(10),
		testSnapshotA("a.example.", "192.0.2.1"),
		testSnapshotSOA(11),
		testSnapshotA("b.example.", "192.0.2.2"),
		testSnapshotSOA(11),
	}

	updated, err := ApplyIXFR(old, rrs)
	if err != nil {
		t.Fatalf("ApplyIXFR() error: %v", err)
	}
	assertSnapshotRecords(t, updated, 11, map[string]string{"b.example.": "192.0.2.2"})
	assertSnapshotRecords(t, old, 10, map[string]string{"a.example.": "192.0.2.1"})
}

func TestApplyIXFRMultipleDeltas(t *testing.T) {
	old := mustNewZoneSnapshot(t, []RR{testSnapshotSOA(10), testSnapshotA("a.example.", "192.0.2.1")})
	rrs := []RR{
		testSnapshotSOA(12),
		testSnapshotSOA(10),
		testSnapshotA("a.example.", "192.0.2.1"),
		testSnapshotSOA(11),
		testSnapshotA("b.example.", "192.0.2.2"),
		testSnapshotSOA(11),
		testSnapshotA("b.example.", "192.0.2.2"),
		testSnapshotSOA(12),
		testSnapshotA("c.example.", "192.0.2.3"),
		testSnapshotSOA(12),
	}

	updated, err := ApplyIXFR(old, rrs)
	if err != nil {
		t.Fatalf("ApplyIXFR() error: %v", err)
	}
	assertSnapshotRecords(t, updated, 12, map[string]string{"c.example.": "192.0.2.3"})
}

func TestApplyIXFRInvalidDeltaKeepsSnapshot(t *testing.T) {
	old := mustNewZoneSnapshot(t, []RR{testSnapshotSOA(10), testSnapshotA("a.example.", "192.0.2.1")})
	before := snapshotHash(t, old)
	rrs := []RR{
		testSnapshotSOA(12),
		testSnapshotSOA(10),
		testSnapshotA("a.example.", "192.0.2.1"),
		testSnapshotSOA(11),
		testSnapshotA("b.example.", "192.0.2.2"),
		testSnapshotSOA(11),
		testSnapshotA("c.example.", "192.0.2.3"),
		testSnapshotSOA(12),
		testSnapshotA("d.example.", "192.0.2.4"),
		testSnapshotSOA(12),
	}

	if _, err := ApplyIXFR(old, rrs); err == nil {
		t.Fatal("ApplyIXFR() error = nil, want missing delete error")
	}
	if after := snapshotHash(t, old); after != before {
		t.Fatalf("input snapshot changed after invalid IXFR: before %x, after %x", before, after)
	}
}

func TestApplyIXFRSerialWrap(t *testing.T) {
	old := mustNewZoneSnapshot(t, []RR{testSnapshotSOA(4294967295), testSnapshotA("a.example.", "192.0.2.1")})
	rrs := []RR{
		testSnapshotSOA(0),
		testSnapshotSOA(4294967295),
		testSnapshotA("a.example.", "192.0.2.1"),
		testSnapshotSOA(0),
		testSnapshotA("b.example.", "192.0.2.2"),
		testSnapshotSOA(0),
	}

	updated, err := ApplyIXFR(old, rrs)
	if err != nil {
		t.Fatalf("ApplyIXFR() error: %v", err)
	}
	assertSnapshotRecords(t, updated, 0, map[string]string{"b.example.": "192.0.2.2"})
}

func TestApplyIXFRSerialHalfSpace(t *testing.T) {
	old := mustNewZoneSnapshot(t, []RR{testSnapshotSOA(0)})
	updated, err := ApplyIXFR(old, []RR{
		testSnapshotSOA(1 << 31),
		testSnapshotSOA(0),
		testSnapshotSOA(1 << 31),
		testSnapshotSOA(1 << 31),
	})
	if err == nil {
		t.Fatalf("ApplyIXFR() = %v, want half-space ambiguity error", updated)
	}
}

func TestApplyIXFRTTLChange(t *testing.T) {
	old := mustNewZoneSnapshot(t, []RR{testSnapshotSOA(10), testSnapshotA("a.example.", "192.0.2.1")})
	newA := testRR("a.example. 1800 IN A 192.0.2.1")
	rrs := []RR{
		testSnapshotSOA(11),
		testSnapshotSOA(10),
		testSnapshotA("a.example.", "192.0.2.1"),
		testSnapshotSOA(11),
		newA,
		testSnapshotSOA(11),
	}

	updated, err := ApplyIXFR(old, rrs)
	if err != nil {
		t.Fatalf("ApplyIXFR() error: %v", err)
	}
	if got := updated.Records()[1].Header().Ttl; got != 1800 {
		t.Fatalf("A TTL = %d, want 1800", got)
	}
}

func TestApplyIXFRAXFRFallback(t *testing.T) {
	old := mustNewZoneSnapshot(t, []RR{testSnapshotSOA(10), testSnapshotA("a.example.", "192.0.2.1")})
	rrs := []RR{
		testSnapshotSOA(11),
		testSnapshotA("b.example.", "192.0.2.2"),
		testSnapshotA("c.example.", "192.0.2.3"),
		testSnapshotSOA(11),
	}

	updated, err := ApplyIXFR(old, rrs)
	if err != nil {
		t.Fatalf("ApplyIXFR() error: %v", err)
	}
	assertSnapshotRecords(t, updated, 11, map[string]string{
		"b.example.": "192.0.2.2",
		"c.example.": "192.0.2.3",
	})
}

func TestZoneSnapshotImmutable(t *testing.T) {
	a := testSnapshotA("a.example.", "192.0.2.1")
	old := mustNewZoneSnapshot(t, []RR{testSnapshotSOA(10), a})
	a.(*A).A = nil
	records := old.Records()
	records[0].(*SOA).Serial = 99
	records[1].(*A).A = nil

	if got := old.SOA().Serial; got != 10 {
		t.Fatalf("snapshot serial = %d, want 10", got)
	}
	if got := old.Records()[1].(*A).A.String(); got != "192.0.2.1" {
		t.Fatalf("snapshot A record = %q, want 192.0.2.1", got)
	}
}

func TestNewZoneSnapshotValidation(t *testing.T) {
	tests := []struct {
		name    string
		records []RR
	}{
		{name: "empty", records: nil},
		{name: "SOA not first", records: []RR{testSnapshotA("a.example.", "192.0.2.1"), testSnapshotSOA(10)}},
		{name: "duplicate SOA", records: []RR{testSnapshotSOA(10), testSnapshotSOA(10)}},
		{name: "outside zone", records: []RR{testSnapshotSOA(10), testSnapshotA("a.example.net.", "192.0.2.1")}},
		{name: "duplicate RR", records: []RR{testSnapshotSOA(10), testSnapshotA("a.example.", "192.0.2.1"), testSnapshotA("a.example.", "192.0.2.1")}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewZoneSnapshot(test.records); err == nil {
				t.Fatalf("NewZoneSnapshot() error = nil, want error")
			}
		})
	}
}

func TestApplyIXFRInvalidBoundaries(t *testing.T) {
	old := mustNewZoneSnapshot(t, []RR{testSnapshotSOA(10), testSnapshotA("a.example.", "192.0.2.1")})
	tests := []struct {
		name string
		rrs  []RR
	}{
		{
			name: "missing final SOA",
			rrs: []RR{
				testSnapshotSOA(11),
				testSnapshotSOA(10),
				testSnapshotA("a.example.", "192.0.2.1"),
				testSnapshotSOA(11),
				testSnapshotA("b.example.", "192.0.2.2"),
			},
		},
		{
			name: "wrong old SOA",
			rrs: []RR{
				testSnapshotSOA(11),
				testSnapshotSOA(9),
				testSnapshotA("a.example.", "192.0.2.1"),
				testSnapshotSOA(11),
				testSnapshotA("b.example.", "192.0.2.2"),
				testSnapshotSOA(11),
			},
		},
		{
			name: "outer SOA mismatch",
			rrs: []RR{
				testSnapshotSOA(12),
				testSnapshotSOA(10),
				testSnapshotA("a.example.", "192.0.2.1"),
				testSnapshotSOA(11),
				testSnapshotA("b.example.", "192.0.2.2"),
				testSnapshotSOA(11),
			},
		},
		{
			name: "add already exists",
			rrs: []RR{
				testSnapshotSOA(11),
				testSnapshotSOA(10),
				testSnapshotSOA(11),
				testSnapshotA("a.example.", "192.0.2.1"),
				testSnapshotSOA(11),
			},
		},
		{
			name: "nil record",
			rrs:  []RR{nil},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ApplyIXFR(old, test.rrs); err == nil {
				t.Fatalf("ApplyIXFR() error = nil, want error")
			}
		})
	}
}
