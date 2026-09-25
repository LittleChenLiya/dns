package dns

import (
	"errors"
	"fmt"
	"math"
)

// Errors returned by ChaseCNAME. Use errors.Is to test for them.
var (
	// ErrCNAMEConflict is returned when the answer section contains two
	// CNAME records for the same owner name with different targets.
	ErrCNAMEConflict = errors.New("dns: conflicting CNAME targets")
	// ErrCNAMELoop is returned when following the CNAME chain revisits a
	// name that is already part of the chain.
	ErrCNAMELoop = errors.New("dns: CNAME loop detected")
	// ErrCNAMETooManyHops is returned when the CNAME chain is longer than
	// the caller-provided hop limit.
	ErrCNAMETooManyHops = errors.New("dns: CNAME chain exceeds hop limit")
)

// CNAMEChase is the result of an offline CNAME chain analysis performed by
// ChaseCNAME. It never reflects data from outside the answer section of the
// response message.
type CNAMEChase struct {
	// Chain lists every name visited while following the chain, starting
	// with the question name and ending with the final name reached. Each
	// name after the first is the target of a CNAME owned by the previous
	// name.
	Chain []string
	// RRset holds the records of the requested type found at the final
	// name. It is nil when the chain does not terminate in an answer.
	RRset []RR
	// MinTTL is the minimum TTL over all records participating in the
	// chain: the CNAMEs followed and the final RRset. It is zero when no
	// records participated.
	MinTTL uint32
	// Complete is true when the chain ends in an RRset of the requested
	// type. When false, the response contained (partial) aliases but no
	// final answer; this is not an NXDOMAIN indication.
	Complete bool
	// Rcode and Truncated are copied from the response message so the
	// caller can judge the server status without re-inspecting it.
	Rcode     int
	Truncated bool
}

// FinalName returns the last name reached while following the chain.
func (c *CNAMEChase) FinalName() string {
	if len(c.Chain) == 0 {
		return ""
	}
	return c.Chain[len(c.Chain)-1]
}

// ChaseCNAME performs an offline CNAME chain analysis: starting from the
// question name in q, it follows CNAME records in the answer section of r
// and returns the RRset of the question's type at the final name together
// with the aliases traversed. It performs no network queries and does not
// modify q or r. Only the answer section of r is consulted; unrelated
// records in the authority or additional sections are never used to
// complete a chain.
//
// Name comparison follows the DNS case-insensitivity rules. If the same
// owner name has CNAME records pointing at different targets, if the chain
// forms a loop, or if following the chain needs more than maxHops CNAME
// hops, an error wrapping ErrCNAMEConflict, ErrCNAMELoop or
// ErrCNAMETooManyHops is returned respectively.
//
// If the response contains aliases but no record of the requested type at
// the final name, the returned CNAMEChase has Complete set to false and
// FinalName reports the last name reached; this is not treated as an
// NXDOMAIN. The response's rcode and truncation flag are preserved in the
// result for the caller to interpret.
func ChaseCNAME(q, r *Msg, maxHops int) (*CNAMEChase, error) {
	if q == nil || len(q.Question) == 0 {
		return nil, errors.New("dns: question message has no question section")
	}
	if r == nil {
		return nil, errors.New("dns: response message is nil")
	}
	qtype := q.Question[0].Qtype
	res := &CNAMEChase{
		Rcode:     r.Rcode,
		Truncated: r.Truncated,
	}
	minTTL := uint32(math.MaxUint32)
	seen := make(map[string]bool)
	current := CanonicalName(q.Question[0].Name)
	for hops := 0; ; {
		if seen[current] {
			return res, fmt.Errorf("%w at %s", ErrCNAMELoop, current)
		}
		seen[current] = true
		res.Chain = append(res.Chain, current)

		var target string
		for _, rr := range r.Answer {
			cn, ok := rr.(*CNAME)
			if !ok || CanonicalName(cn.Hdr.Name) != current {
				continue
			}
			t := CanonicalName(cn.Target)
			if target == "" {
				target = t
			} else if t != target {
				return res, fmt.Errorf("%w for %s: %s and %s", ErrCNAMEConflict, current, target, t)
			}
			if cn.Hdr.Ttl < minTTL {
				minTTL = cn.Hdr.Ttl
			}
		}
		if target == "" {
			break
		}
		hops++
		if hops > maxHops {
			return res, fmt.Errorf("%w: %d hops needed, limit is %d", ErrCNAMETooManyHops, hops, maxHops)
		}
		current = target
	}

	for _, rr := range r.Answer {
		if rr.Header().Rrtype != qtype || CanonicalName(rr.Header().Name) != current {
			continue
		}
		res.RRset = append(res.RRset, rr)
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}
	if minTTL != math.MaxUint32 {
		res.MinTTL = minTTL
	}
	res.Complete = len(res.RRset) > 0
	return res, nil
}
