package dns

import (
	"fmt"
	"math"
	"time"
)

// AgeSummary summarizes the remaining TTLs of a message after TTL aging.
//
// It lets a cache caller decide whether a cached response is still fresh
// enough to be published. A response whose Expired field is true must not be
// served from cache.
type AgeSummary struct {
	// MinTTL is the smallest remaining TTL, in whole seconds, among the
	// message's resource records. OPT pseudo-records are excluded because
	// their TTL field carries extended RCODE, version and flags rather than
	// a cache TTL; RRSIG OriginalTtl fields are likewise not considered.
	// When the message contains no ageable records, MinTTL is 0.
	MinTTL uint32

	// Expired reports whether at least one resource record's TTL has reached
	// 0. A caller should reject publishing an aged answer when Expired is
	// true.
	Expired bool
}

// AgeTTL returns a deep copy of msg with every resource-record TTL decreased
// by elapsed seconds, saturating at 0. The original message is never
// modified, so it is safe to keep serving it from cache.
//
// All three record sections (Answer, Ns and Extra) are aged. OPT
// pseudo-records are left untouched: their TTL field carries extended RCODE,
// version and flags, not a cache TTL. RRSIG records are aged like any other
// record, but their OriginalTtl field is preserved.
//
// Elapsed time is converted to whole seconds by truncating the sub-second
// part (i.e. rounding down to the nearest whole second). elapsed must not be
// negative. A duration larger than any TTL saturates every TTL to 0.
func AgeTTL(msg *Msg, elapsed time.Duration) (*Msg, AgeSummary, error) {
	if msg == nil {
		return nil, AgeSummary{}, &Error{err: "nil message"}
	}
	if elapsed < 0 {
		return nil, AgeSummary{}, fmt.Errorf("dns: negative TTL aging duration %s", elapsed)
	}

	// Truncate sub-seconds; elapsed is non-negative so this rounds down.
	secs := uint64(elapsed / time.Second)

	aged := msg.Copy()

	summary := AgeSummary{MinTTL: math.MaxUint32}
	ageable := false

	age := func(rr RR) {
		if rr == nil {
			return
		}
		// The OPT TTL field is not a cache TTL, leave it as-is.
		if _, ok := rr.(*OPT); ok {
			return
		}
		hdr := rr.Header()
		if hdr == nil {
			return
		}
		ageable = true
		if secs >= uint64(hdr.Ttl) {
			hdr.Ttl = 0
			summary.Expired = true
		} else {
			hdr.Ttl -= uint32(secs)
		}
		if hdr.Ttl < summary.MinTTL {
			summary.MinTTL = hdr.Ttl
		}
	}

	for _, rr := range aged.Answer {
		age(rr)
	}
	for _, rr := range aged.Ns {
		age(rr)
	}
	for _, rr := range aged.Extra {
		age(rr)
	}

	if !ageable {
		summary.MinTTL = 0
	}

	return aged, summary, nil
}
