package dnsclient

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// RawDNS is a Client instance resolving using an operating systems configured DNS
type RawDNS struct {
}

// Lookup performs a DNS lookup using UDP DNS
func (c *RawDNS) Lookup(name string, rType uint16) Response {

	// We set the TTL & Status here cause this lookup is really dumb.
	// Whatever.
	resp := Response{
		TTL:    0,
		Status: "NOERROR",
	}

	switch rType {
	case dns.TypeA:
		a, err := net.LookupHost(name)
		if err != nil {
			fmt.Printf("Failed to lookup host: %s\n", err)
			return resp
		}

		// Ensure we get a v4 response
		for _, ip := range a {
			if strings.Contains(ip, ":") {
				continue
			}

			resp.Data = ip
			break
		}

		break

	case dns.TypeTXT:
		a, err := net.LookupTXT(name)
		if err != nil {
			fmt.Printf("Failed to lookup host: %s\n", err)
			return resp
		}

		if len(a) > 0 {
			// In the case of our C2, we will only reply with a single TXT answer.
			resp.Data = a[0]
		}

		break
	}

	return resp
}
