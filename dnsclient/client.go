package dnsclient

// Client is an interface all clients should conform to.
type Client interface {
	Lookup(name string, rType uint16) Response
}

// NewGoogleDNS starts a new Google DNS-over-HTTPS resolver Client
func NewGoogleDNS() *GoogleDNS {
	return &GoogleDNS{BaseURL: "https://dns.google.com/resolve"}
}

// NewGoogleFrontDNS starts a new Google DNS-over-HTTPS resolver Client
// The Host header for this request is updated in the client itself
func NewGoogleFrontDNS() *GoogleFrontDNS {
	return &GoogleFrontDNS{BaseURL: "https://www.google.com/resolve"}
}

// NewCloudFlareDNS starts a new Cloudflare DNS-over-HTTPS resolver Client
func NewCloudFlareDNS() *CloudflareDNS {
	return &CloudflareDNS{BaseURL: "https://cloudflare-dns.com/dns-query"}
}

// NewQuad9DNS starts a new Quad9 DNS-over-HTTPS resolver Client
func NewQuad9DNS() *Quad9DNS {
	// Use the unfiltered URL.
	return &Quad9DNS{BaseURL: "https://dns10.quad9.net/dns-query"}
}

// NewRawDNS starts a new client making use of traditional DNS
func NewRawDNS() *RawDNS {
	return &RawDNS{}
}

// Lookup is used by the rest of the commands to resolve names
func Lookup(c Client, name string, rType uint16) Response {
	return c.Lookup(name, rType)
}
