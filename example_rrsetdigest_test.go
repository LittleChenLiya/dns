package dns_test

import (
	"fmt"

	"github.com/miekg/dns"
)

// DigestRRset summarizes a small RRset for cache comparison: the hex digest
// identifies the content, while TTLs are reported separately.
func ExampleDigestRRset() {
	rrset := make([]dns.RR, 0, 2)
	for _, s := range []string{
		"WWW.Example.COM. 3600 IN A 192.0.2.2",
		"www.example.com. 60 IN A 192.0.2.1", // TTL and case differ, content does not
	} {
		rr, err := dns.NewRR(s)
		if err != nil {
			panic(err)
		}
		rrset = append(rrset, rr)
	}

	d, err := dns.DigestRRset(rrset)
	if err != nil {
		panic(err)
	}
	fmt.Printf("owner=%s type=%s records=%d ttl=%d-%d\n", d.Owner, dns.TypeToString[d.Type], d.Records, d.MinTTL, d.MaxTTL)
	fmt.Printf("digest=%s\n", d.Hex())
	// Output:
	// owner=www.example.com. type=A records=2 ttl=60-3600
	// digest=de32abc675d93240d0ba3a9944bcfba67fc8e1598e9dd28eb1ad7b7b3a696ad1
}
