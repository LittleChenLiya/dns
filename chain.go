package dns

import (
	"errors"
	"fmt"
	"strings"
)

// Errors returned by FollowCNAMEChain.
var (
	// ErrCNAMEChainLoop is returned when the CNAME chain in the response
	// loops back to a name that was already visited.
	ErrCNAMEChainLoop = errors.New("dns: cname chain contains a loop")
	// ErrCNAMEChainConflict is returned when the same owner name carries
	// CNAME records with different targets.
	ErrCNAMEChainConflict = errors.New("dns: conflicting cname targets for the same name")
	// ErrCNAMEChainTooLong is returned when following the chain requires
	// more hops than the caller supplied limit allows.
	ErrCNAMEChainTooLong = errors.New("dns: cname chain exceeds the maximum number of hops")
)

// CNAMEChain is the result of an offline CNAME chain analysis performed by
// FollowCNAMEChain.
type CNAMEChain struct {
	// Chain lists every name that was traversed, starting with the
	// question name and followed by each CNAME target in the order they
	// were walked. Chain[1:] are the aliases that were followed.
	Chain []string
	// RRset holds the records of the requested type found at the final
	// name of the chain. It is nil when Complete is false.
	RRset []RR
	// LastName is the last name reached while walking the chain. When
	// Complete is false this is the name for which no answer of the
	// requested type was present in the response.
	LastName string
	// Complete reports whether the chain ended in an RRset of the
	// requested type. A false value means the response only contained
	// (valid) aliases but no final answer; it is not an NXDOMAIN
	// indication, check Rcode for that.
	Complete bool
	// TTL is the minimum TTL of all records participating in the chain:
	// every followed CNAME plus the final RRset. It is 0 when no records
	// participated.
	TTL uint32
	// Rcode is the rcode of the response message, kept for the caller.
	Rcode int
	// Truncated is the TC flag of the response message, kept for the
	// caller.
	Truncated bool
}

// FollowCNAMEChain performs an offline analysis of the CNAME chain in the
// response message resp for the question q. Starting at q.Name it follows
// CNAME records one hop at a time and returns the RRset of type q.Qtype
// found at the final name, together with the aliases that were walked. No
// network queries are performed and neither q nor resp is modified.
//
// Only records from the answer section of resp are considered; unrelated
// additional (or authority) records are never used to complete the chain.
// Owner name comparison follows the DNS case-insensitivity rules.
//
// maxHops bounds the number of CNAME hops that may be followed; a negative
// value disables the limit. If the same owner name carries CNAME records
// with different targets ErrCNAMEChainConflict is returned, a chain that
// revisits a name yields ErrCNAMEChainLoop, and exceeding maxHops yields
// ErrCNAMEChainTooLong.
func FollowCNAMEChain(q Question, resp *Msg, maxHops int) (*CNAMEChain, error) {
	if resp == nil {
		return nil, errors.New("dns: nil response message")
	}
	chain := &CNAMEChain{
		Rcode:     resp.Rcode,
		Truncated: resp.Truncated,
		TTL:       ^uint32(0),
	}
	name := canonicalName(q.Name)
	chain.Chain = append(chain.Chain, Fqdn(q.Name))
	visited := map[string]bool{name: true}
	hops := 0
	for {
		target, ok, err := chain.cnameTarget(resp, name)
		if err != nil {
			return nil, err
		}
		if !ok {
			chain.LastName = chain.Chain[len(chain.Chain)-1]
			for _, rr := range resp.Answer {
				h := rr.Header()
				if h.Rrtype != q.Qtype || canonicalName(h.Name) != name {
					continue
				}
				chain.RRset = append(chain.RRset, rr)
				chain.noteTTL(rr)
			}
			chain.Complete = len(chain.RRset) > 0
			break
		}
		if visited[canonicalName(target)] {
			return nil, fmt.Errorf("%w: %s was already visited", ErrCNAMEChainLoop, target)
		}
		hops++
		if maxHops >= 0 && hops > maxHops {
			return nil, fmt.Errorf("%w: more than %d hops needed at %s", ErrCNAMEChainTooLong, maxHops, target)
		}
		visited[canonicalName(target)] = true
		chain.Chain = append(chain.Chain, target)
		name = canonicalName(target)
	}
	if chain.TTL == ^uint32(0) {
		chain.TTL = 0
	}
	return chain, nil
}

// cnameTarget returns the target of the CNAME record(s) owned by name in
// the answer section of resp. Multiple CNAME records at the same name are
// only tolerated when they agree on the target. The TTL of every matching
// record is folded into the chain result.
func (c *CNAMEChain) cnameTarget(resp *Msg, name string) (string, bool, error) {
	var target string
	found := false
	for _, rr := range resp.Answer {
		h := rr.Header()
		if h.Rrtype != TypeCNAME || canonicalName(h.Name) != name {
			continue
		}
		t := rr.(*CNAME).Target
		if found && canonicalName(t) != canonicalName(target) {
			return "", false, fmt.Errorf("%w: %s points to both %s and %s", ErrCNAMEChainConflict, name, target, t)
		}
		found = true
		target = t
		c.noteTTL(rr)
	}
	return target, found, nil
}

func (c *CNAMEChain) noteTTL(rr RR) {
	if ttl := rr.Header().Ttl; ttl < c.TTL {
		c.TTL = ttl
	}
}

// canonicalName returns name in the canonical form used for DNS
// case-insensitive owner name comparison: fully qualified and lowercased.
func canonicalName(name string) string {
	return strings.ToLower(Fqdn(name))
}
