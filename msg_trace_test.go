package dns

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// Example: a small DNS message carrying two names. The first name
// "foo.example.com." sits at offset 0; the second name is a compression
// pointer back to offset 0. Unpacking the second name must show the jump.
func ExampleUnpackDomainNameTrace() {
	msg := []byte{
		3, 'f', 'o', 'o',
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
		0xC0, 0x00,
	}

	name, off, err, trace := UnpackDomainNameTrace(msg, 17)
	fmt.Printf("name=%q off=%d err=%v\n", name, off, err)
	for _, step := range trace.Steps {
		if step.Kind == DomainNameTracePointer {
			fmt.Printf("pointer at [%d,%d) -> target %d\n", step.Offset, step.End, step.PointerTarget)
		}
	}
	// Output:
	// name="foo.example.com." off=19 err=<nil>
	// pointer at [17,19) -> target 0
}

func TestUnpackDomainNameTracePointerJump(t *testing.T) {
	msg := []byte{
		3, 'f', 'o', 'o',
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
		0xC0, 0x00,
	}

	name, off, err, trace := UnpackDomainNameTrace(msg, 17)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "foo.example.com."; name != want {
		t.Errorf("name = %q, want %q", name, want)
	}
	if want := 19; off != want {
		t.Errorf("off = %d, want %d", off, want)
	}

	var pointers []DomainNameTraceStep
	var labels []DomainNameTraceStep
	for _, step := range trace.Steps {
		switch step.Kind {
		case DomainNameTracePointer:
			pointers = append(pointers, step)
		case DomainNameTraceLabel:
			labels = append(labels, step)
		}
	}
	if len(pointers) != 1 {
		t.Fatalf("got %d pointer steps, want 1", len(pointers))
	}
	p := pointers[0]
	if p.Offset != 17 || p.End != 19 || p.PointerTarget != 0 {
		t.Errorf("pointer step = [%d,%d) target %d, want [17,19) target 0",
			p.Offset, p.End, p.PointerTarget)
	}
	if len(labels) != 3 {
		t.Fatalf("got %d label steps, want 3", len(labels))
	}
	wantLabels := []struct {
		offset, end, wire int
		label             string
	}{
		{0, 4, 3, "foo"},
		{4, 12, 7, "example"},
		{12, 16, 3, "com"},
	}
	for i, want := range wantLabels {
		got := labels[i]
		if got.Offset != want.offset || got.End != want.end ||
			got.WireLength != want.wire || got.Label != want.label {
			t.Errorf("label %d = [%d,%d) wire=%d label=%q, want [%d,%d) wire=%d label=%q",
				i, got.Offset, got.End, got.WireLength, got.Label,
				want.offset, want.end, want.wire, want.label)
		}
	}
}

func TestUnpackDomainNameTraceSpecialBytes(t *testing.T) {
	msg := []byte{3, 'a', 0x01, 'b', 0}

	name, off, err, trace := UnpackDomainNameTrace(msg, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "a\x5c001b."; name != want {
		t.Errorf("name = %q, want %q", name, want)
	}
	if want := 5; off != want {
		t.Errorf("off = %d, want %d", off, want)
	}

	var label *DomainNameTraceStep
	for i := range trace.Steps {
		if trace.Steps[i].Kind == DomainNameTraceLabel {
			label = &trace.Steps[i]
			break
		}
	}
	if label == nil {
		t.Fatal("no label step recorded")
	}
	if label.WireLength != 3 {
		t.Errorf("WireLength = %d, want 3 (original byte count)", label.WireLength)
	}
	if label.Label != "a\x5c001b" {
		t.Errorf("Label = %q, want %q", label.Label, "a\x5c001b")
	}
	if len(label.Label) == label.WireLength {
		t.Errorf("escaped display length %d should differ from wire byte count %d",
			len(label.Label), label.WireLength)
	}
}

func TestUnpackDomainNameTraceSelfPointer(t *testing.T) {
	msg := []byte{0xC0, 0x00}

	type result struct {
		name string
		off  int
		err  error
		tr   *DomainNameTrace
	}
	done := make(chan result, 1)
	go func() {
		name, off, err, tr := UnpackDomainNameTrace(msg, 0)
		done <- result{name, off, err, tr}
	}()
	select {
	case res := <-done:
		if res.err == nil {
			t.Errorf("expected error for self-pointer, got name=%q", res.name)
		}
		if res.off != len(msg) {
			t.Errorf("off = %d, want %d", res.off, len(msg))
		}
		if len(res.tr.Steps) == 0 {
			t.Fatal("trace is empty, want incomplete trace ending at failure node")
		}
		last := res.tr.Steps[len(res.tr.Steps)-1]
		if last.Err == nil {
			t.Errorf("last step has no error; failure node not marked: %+v", last)
		}
		if last.Kind != DomainNameTracePointer {
			t.Errorf("last step kind = %v, want pointer", last.Kind)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("self-pointer hung")
	}
}

func TestUnpackDomainNameTraceOutOfBounds(t *testing.T) {
	msg := []byte{3, 'f', 'o', 'o', 0xC0, 0xFF, 0xFF}

	name, off, err, trace := UnpackDomainNameTrace(msg, 0)
	if err == nil {
		t.Fatalf("expected error for out-of-bounds pointer, got name=%q", name)
	}
	if off != len(msg) {
		t.Errorf("off = %d, want %d", off, len(msg))
	}
	if len(trace.Steps) == 0 {
		t.Fatal("trace is empty, want incomplete trace ending at failure node")
	}
	last := trace.Steps[len(trace.Steps)-1]
	if last.Err == nil {
		t.Errorf("last step has no error; failure node not marked: %+v", last)
	}
	if last.Kind != DomainNameTraceError {
		t.Errorf("last step kind = %v, want error", last.Kind)
	}
}

func TestUnpackDomainNameTraceMixed(t *testing.T) {
	msg := []byte{
		3, 'f', 'o', 'o',
		0,
		3, 'b', 'a', 'r',
		0xC0, 0x00,
		0,
	}

	name, off, err, trace := UnpackDomainNameTrace(msg, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "bar.foo."; name != want {
		t.Errorf("name = %q, want %q", name, want)
	}
	if want := 11; off != want {
		t.Errorf("off = %d, want %d", off, want)
	}

	var fragments strings.Builder
	var kinds []DomainNameTraceKind
	for _, step := range trace.Steps {
		kinds = append(kinds, step.Kind)
		if step.Kind == DomainNameTraceLabel {
			fragments.WriteString(step.Fragment)
		}
	}
	if fragments.String() != name {
		t.Errorf("concatenated fragments = %q, want %q", fragments.String(), name)
	}
	wantKinds := []DomainNameTraceKind{
		DomainNameTraceLabel,
		DomainNameTracePointer,
		DomainNameTraceLabel,
		DomainNameTraceRoot,
	}
	if len(kinds) != len(wantKinds) {
		t.Fatalf("got %d steps %v, want %d steps %v", len(kinds), kinds, len(wantKinds), wantKinds)
	}
	for i := range wantKinds {
		if kinds[i] != wantKinds[i] {
			t.Errorf("step %d kind = %v, want %v", i, kinds[i], wantKinds[i])
		}
	}
}

func TestUnpackDomainNameTraceParallel(t *testing.T) {
	msg := []byte{
		3, 'f', 'o', 'o',
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
		0xC0, 0x00,
	}

	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name, off, err, trace := UnpackDomainNameTrace(msg, 17)
			if err != nil {
				errs <- err
				return
			}
			if name != "foo.example.com." || off != 19 {
				errs <- fmt.Errorf("name=%q off=%d", name, off)
				return
			}
			pointers, labels := 0, 0
			for _, step := range trace.Steps {
				switch step.Kind {
				case DomainNameTracePointer:
					pointers++
				case DomainNameTraceLabel:
					labels++
				}
			}
			if pointers != 1 || labels != 3 {
				errs <- fmt.Errorf("pointers=%d labels=%d, want 1/3", pointers, labels)
				return
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestUnpackDomainNameTraceOnlyGivenOffset(t *testing.T) {
	msg := []byte{
		0xAA, 0xBB, 0xCC,
		3, 'f', 'o', 'o',
		0,
	}

	name, off, err, trace := UnpackDomainNameTrace(msg, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "foo."; name != want {
		t.Errorf("name = %q, want %q", name, want)
	}
	if want := 8; off != want {
		t.Errorf("off = %d, want %d", off, want)
	}
	if len(trace.Steps) == 0 {
		t.Fatal("trace is empty")
	}
	first := trace.Steps[0]
	if first.Offset != 3 {
		t.Errorf("first step offset = %d, want 3 (caller offset)", first.Offset)
	}
}

func TestUnpackDomainNameTraceMatchesUnpackDomainName(t *testing.T) {
	cases := [][]byte{
		{0},
		{3, 'f', 'o', 'o', 0},
		{3, 'f', 'o', 'o', 3, 'b', 'a', 'r', 0},
		{3, 'f', 'o', 'o', 0xC0, 0x00},
		{0xC0, 0x00},
		{3, 'f', 'o', 'o', 0xC0, 0xFF, 0xFF},
		{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x80},
		{3, 'a', 0x01, 'b', 0},
		{},
	}
	for i, msg := range cases {
		wantName, wantOff, wantErr := UnpackDomainName(msg, 0)
		gotName, gotOff, gotErr, _ := UnpackDomainNameTrace(msg, 0)
		if gotName != wantName || gotOff != wantOff ||
			(gotErr == nil) != (wantErr == nil) ||
			(gotErr != nil && gotErr.Error() != wantErr.Error()) {
			t.Errorf("case %d: UnpackDomainName=(%q,%d,%v) Trace=(%q,%d,%v)",
				i, wantName, wantOff, wantErr, gotName, gotOff, gotErr)
		}
	}
}

func TestUnpackDomainNameTraceString(t *testing.T) {
	msg := []byte{
		3, 'f', 'o', 'o',
		0,
		0xC0, 0x00,
	}
	_, _, _, trace := UnpackDomainNameTrace(msg, 5)
	s := trace.String()
	if !strings.Contains(s, "pointer") || !strings.Contains(s, "target 0") {
		t.Errorf("trace string missing pointer jump:\n%s", s)
	}
	if !strings.Contains(s, "label") || !strings.Contains(s, "foo") {
		t.Errorf("trace string missing label:\n%s", s)
	}
}
