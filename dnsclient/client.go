package dnsclient

// Client is an interface all clients should conform to.
type Client interface {
	Lookup(name string, rType uint16) Response
}

// NewGoogleDNS starts a new Google DNS-over-HTTPS resolver Client
func NewGoogleDNS(useragent string) *GoogleDNS {
	return &GoogleDNS{BaseURL: "https://dns.google.com/resolve", UserAgent: useragent}
}

// NewGoogleFrontDNS starts a new Google DNS-over-HTTPS resolver Client
// The Host header for this request is updated in the client itself
func NewGoogleFrontDNS(useragent string) *GoogleFrontDNS {
	return &GoogleFrontDNS{BaseURL: "https://www.google.com/resolve", UserAgent: useragent}
}

// NewCloudFlareDNS starts a new Cloudflare DNS-over-HTTPS resolver Client
func NewCloudFlareDNS(useragent string) *CloudflareDNS {
	return &CloudflareDNS{BaseURL: "https://cloudflare-dns.com/dns-query", UserAgent: useragent}
}

// NewQuad9DNS starts a new Quad9 DNS-over-HTTPS resolver Client
func NewQuad9DNS(useragent string) *Quad9DNS {
	// Use the unfiltered URL.
	return &Quad9DNS{BaseURL: "https://dns10.quad9.net:5053/dns-query", UserAgent: useragent}
}

// Blokada starts a new Blokada DNS-over-HTTPS resolver Client
func NewBlokadaDNS(useragent string) *Blokada {
	// Use the unfiltered URL.
	return &Blokada{BaseURL: "https://dns.blokada.org/dns-query", UserAgent: useragent}
}

// NextDNS starts a new NextDNS DNS-over-HTTPS resolver Client
func NewNextDNS(useragent string) *NextDNS {
	// Use the unfiltered URL.
	return &NextDNS{BaseURL: "https://dns.nextdns.io/dns-query", UserAgent: useragent}
}

// NewRawDNS starts a new client making use of traditional DNS
func NewRawDNS() *RawDNS {
	return &RawDNS{}
}

// Lookup is used by the rest of the commands to resolve names
func Lookup(c Client, name string, rType uint16) Response {
	return c.Lookup(name, rType)
}
