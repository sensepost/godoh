package dnsclient

// Client is an interface all clients should conform to.
type Client interface {
	Lookup(name string, rType uint16) Response
}

// NewGoogleDNS starts a new Google DNS-over-HTTPS resolver Client
func NewGoogleDNS() *GoogleDNS {
	return &GoogleDNS{BaseURL: "https://dns.google.com/resolve"}
}

// NewCloudFlareDNS starts a new Cloudflare DNS-over-HTTPS resolver Client
func NewCloudFlareDNS() *CloudflareDNS {
	return &CloudflareDNS{BaseURL: "https://cloudflare-dns.com/dns-query"}
}

func NewRawDNS() *RawDNS {
	return &RawDNS{}
}

// Lookup is used by the rest of the commands to resolve names
func Lookup(c Client, name string, rType uint16) Response {
	return c.Lookup(name, rType)
}
