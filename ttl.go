package dns

import (
	"errors"
	"time"
)

// ErrNegativeElapsed is returned by Msg.Age when the elapsed duration is negative.
var ErrNegativeElapsed = errors.New("dns: negative elapsed duration")

// TtlSummary summarizes the remaining TTLs of the resource records of an aged
// message.
//
// MinTtl is the smallest remaining TTL (in seconds) across the Answer, Ns and
// Extra sections, after aging. OPT pseudo-records are excluded because their
// header TTL field carries EDNS(0) extended information rather than a TTL.
// If the message contains no eligible resource records, MinTtl is 0.
//
// Expired reports whether at least one eligible resource record's TTL has
// reached 0, meaning the aged answer must not be published.
type TtlSummary struct {
	MinTtl  uint32
	Expired bool
}

// Age returns a deep copy of dns in which the TTL of every resource record in
// the Answer, Ns and Extra sections is reduced by the number of seconds in
// elapsed, saturating at 0. The original message dns is never modified.
//
// elapsed is truncated toward zero to a whole number of seconds before it is
// applied. A negative elapsed duration results in an error wrapping
// ErrNegativeElapsed and no output message.
//
// OPT pseudo-records are copied unchanged: their header TTL field carries
// EDNS(0) extended information (the extended-RCODE/version/flags word), not a
// TTL. RRSIG records have their header TTL aged like any other record while
// their OrigTtl field, which carries the original TTL of the signed RRset
// (RFC 4034, Section 3.1), is left untouched.
//
// The returned TtlSummary reports the minimum remaining TTL among the aged
// records and whether any of them has expired. Callers can use it to refuse
// publishing an expired answer.
func (dns *Msg) Age(elapsed time.Duration) (*Msg, TtlSummary, error) {
	seconds := elapsed / time.Second // truncates toward zero
	if seconds < 0 {
		return nil, TtlSummary{}, ErrNegativeElapsed
	}

	aged := dns.Copy()

	summary := TtlSummary{MinTtl: 0}
	count := 0

	ageSection := func(rrs []RR) {
		for _, r := range rrs {
			hdr := r.Header()
			if hdr.Rrtype == TypeOPT {
				continue
			}
			remaining := hdr.Ttl
			if uint64(seconds) < uint64(remaining) {
				remaining -= uint32(seconds)
			} else {
				remaining = 0
			}
			hdr.Ttl = remaining
			if count == 0 || remaining < summary.MinTtl {
				summary.MinTtl = remaining
			}
			if remaining == 0 {
				summary.Expired = true
			}
			count++
		}
	}

	ageSection(aged.Answer)
	ageSection(aged.Ns)
	ageSection(aged.Extra)

	return aged, summary, nil
}
