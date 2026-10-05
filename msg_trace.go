package dns

import (
	"fmt"
	"strings"
)

// DomainNameTraceKind identifies the kind of a single step recorded by
// UnpackDomainNameTrace while unpacking a domain name.
type DomainNameTraceKind int

const (
	// DomainNameTraceLabel is a literal label read from the message.
	DomainNameTraceLabel DomainNameTraceKind = iota
	// DomainNameTracePointer is a compression pointer followed to a new offset.
	DomainNameTracePointer
	// DomainNameTraceRoot is the zero-length label terminating the name.
	DomainNameTraceRoot
	// DomainNameTraceError marks the step at which unpacking failed.
	DomainNameTraceError
)

// String returns a short name for the step kind.
func (k DomainNameTraceKind) String() string {
	switch k {
	case DomainNameTraceLabel:
		return "label"
	case DomainNameTracePointer:
		return "pointer"
	case DomainNameTraceRoot:
		return "root"
	case DomainNameTraceError:
		return "error"
	default:
		return fmt.Sprintf("unknown(%d)", int(k))
	}
}

// DomainNameTraceStep is a single recorded step in the unpacking of a
// domain name. The trace is built during the single parse pass, so the
// offsets and spans reflect the real bytes walked in the message rather
// than a re-scan of the result.
type DomainNameTraceStep struct {
	// Kind identifies what kind of step this is.
	Kind DomainNameTraceKind

	// Offset is the position in msg where this step began. For a label
	// it is the position of the length byte; for a pointer it is the
	// position of the first pointer byte; for the root it is the
	// position of the zero byte.
	Offset int

	// End is the position in msg immediately after this step. For a
	// label it is just past the label bytes; for a pointer it is just
	// past the second pointer byte; for the root it is just past the
	// zero byte.
	End int

	// WireLength is the number of label data bytes on the wire (labels
	// only). This is the original byte count, not the length of the
	// escaped presentation form held in Label. The two deliberately
	// differ: escaping a special byte expands it to several characters
	// while the wire span stays the same.
	WireLength int

	// Label is the escaped presentation form of the label without the
	// trailing dot (labels only).
	Label string

	// PointerTarget is the offset the compression pointer points at
	// (pointers only).
	PointerTarget int

	// Fragment is the piece of the final name contributed by this
	// step. For a label it is the escaped label plus its trailing dot;
	// the final name is the concatenation of every label fragment in
	// trace order.
	Fragment string

	// Err is the error that terminated unpacking (error steps, or the
	// failing pointer step, only).
	Err error
}

// DomainNameTrace is a complete, per-call record of how a domain name
// was unpacked. Each UnpackDomainNameTrace call allocates its own trace,
// so multiple goroutines may unpack in parallel without sharing or
// mutating common report state.
type DomainNameTrace struct {
	// Steps is the ordered list of steps taken while unpacking. On a
	// failed unpack the list is incomplete: it ends at the real failure
	// node (the step whose Err is set).
	Steps []DomainNameTraceStep
}

// addLabel records a successfully read literal label.
func (t *DomainNameTrace) addLabel(offset, end, wireLength int, label, fragment string) {
	if t == nil {
		return
	}
	t.Steps = append(t.Steps, DomainNameTraceStep{
		Kind:       DomainNameTraceLabel,
		Offset:     offset,
		End:        end,
		WireLength: wireLength,
		Label:      label,
		Fragment:   fragment,
	})
}

// addPointer records a successfully followed compression pointer.
func (t *DomainNameTrace) addPointer(offset, end, target int) {
	if t == nil {
		return
	}
	t.Steps = append(t.Steps, DomainNameTraceStep{
		Kind:          DomainNameTracePointer,
		Offset:        offset,
		End:           end,
		PointerTarget: target,
	})
}

// addRoot records the zero-length label that terminates the name.
func (t *DomainNameTrace) addRoot(offset, end int) {
	if t == nil {
		return
	}
	t.Steps = append(t.Steps, DomainNameTraceStep{
		Kind:   DomainNameTraceRoot,
		Offset: offset,
		End:    end,
	})
}

// addError records the step at which unpacking failed.
func (t *DomainNameTrace) addError(offset, end int, err error) {
	if t == nil {
		return
	}
	t.Steps = append(t.Steps, DomainNameTraceStep{
		Kind:   DomainNameTraceError,
		Offset: offset,
		End:    end,
		Err:    err,
	})
}

// failLast marks the most recently recorded step as the failure node.
// This is used when a step itself succeeded (for example a pointer jump)
// but the parse can no longer continue.
func (t *DomainNameTrace) failLast(err error) {
	if t == nil || len(t.Steps) == 0 {
		return
	}
	t.Steps[len(t.Steps)-1].Err = err
}

// String returns a human-readable explanation of the trace: each step
// with its wire span, the pointer jumps, and how the final name is built
// from the label fragments.
func (t *DomainNameTrace) String() string {
	if t == nil {
		return "<nil>"
	}
	var b strings.Builder
	for i, step := range t.Steps {
		fmt.Fprintf(&b, "  step %d: %s", i, step.Kind)
		switch step.Kind {
		case DomainNameTraceLabel:
			fmt.Fprintf(&b, " at [%d,%d) wire=%d bytes label=%q fragment=%q",
				step.Offset, step.End, step.WireLength, step.Label, step.Fragment)
		case DomainNameTracePointer:
			fmt.Fprintf(&b, " at [%d,%d) -> target %d",
				step.Offset, step.End, step.PointerTarget)
		case DomainNameTraceRoot:
			fmt.Fprintf(&b, " at [%d,%d)", step.Offset, step.End)
		case DomainNameTraceError:
			fmt.Fprintf(&b, " at [%d,%d)", step.Offset, step.End)
		}
		if step.Err != nil {
			fmt.Fprintf(&b, " error=%v", step.Err)
		}
		b.WriteByte('\n')
	}
	return b.String()
}
