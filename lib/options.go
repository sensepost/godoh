package lib

import (
	"crypto/tls"
	"errors"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"github.com/sensepost/godoh/dnsclient"
)

// Options are options
type Options struct {
	// Logging
	Logger         *zerolog.Logger
	Debug          bool
	DisableLogging bool

	// Domains
	Domain       string
	ProviderName string
	Provider     dnsclient.Client

	// TLS config
	ValidateTLS bool

	// AES Key
	AESKey string

	// 	User-Agent
	UserAgent string
}

// NewOptions returns a new options struct
func NewOptions() *Options {
	return &Options{}
}

// SetTLSValidation configures the appropriate TLS validation setup
func (o *Options) SetTLSValidation() {

	if !o.ValidateTLS {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
}

// validateDomain validates the domain configured
func (o *Options) validateDomain() (err error) {
	if o.Domain == "" {
		return errors.New("a dns domain is required. either set one at runtime or compile time")
	}

	if strings.HasPrefix(o.Domain, ".") {
		return errors.New("the dns domain should be the base fqdn (without a leading dot)")
	}

	return
}

// GetDNSClient get's the DNS client to use
func (o *Options) GetDNSClient() (dnsclient.Client, error) {

	if err := o.validateDomain(); err != nil {
		return nil, err
	}

	if o.Provider != nil {
		return o.Provider, nil
	}

	log := o.Logger

	switch o.ProviderName {
	case "googlefront":
		log.Warn().Msg(`WARNING: Domain fronting dns.google.com via www.google.com no longer works. ` +
			`A redirect to dns.google.com will be returned. See: https://twitter.com/leonjza/status/1187002742553923584`)
		o.Provider = dnsclient.NewGoogleFrontDNS(o.UserAgent)
		break
	case "google":
		o.Provider = dnsclient.NewGoogleDNS(o.UserAgent)
		break
	case "cloudflare":
		o.Provider = dnsclient.NewCloudFlareDNS(o.UserAgent)
		break
	case "quad9":
		o.Provider = dnsclient.NewQuad9DNS(o.UserAgent)
		break
	case "blokada":
		o.Provider = dnsclient.NewBlokadaDNS(o.UserAgent)
		break
	case "nextdns":
		o.Provider = dnsclient.NewNextDNS(o.UserAgent)
		break
	case "raw":
		o.Provider = dnsclient.NewRawDNS()
		break
	default:
		return nil, errors.New("invalid dns provider")
	}

	return o.Provider, nil
}
