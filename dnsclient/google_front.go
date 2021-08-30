package dnsclient

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/miekg/dns"
)

// GoogleFrontDNS is a Client instance resolving using Googles DNS-over-HTTPS service,
// fronted using www.google.com
type GoogleFrontDNS struct {
	BaseURL   string
	UserAgent string
}

// Lookup performs a DNS lookup using Google
func (c *GoogleFrontDNS) Lookup(name string, rType uint16) Response {

	client := http.Client{
		Timeout: time.Second * 20,
	}

	req, err := http.NewRequest("GET", c.BaseURL, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Update the Host client header to dns.google.com
	// Ref: https://twitter.com/vysecurity/status/1058947074392125440
	req.Host = "dns.google.com"
	req.Header.Set("User-Agent", c.UserAgent)

	q := req.URL.Query()
	q.Add("name", name)
	q.Add("type", strconv.Itoa(int(rType)))
	q.Add("cd", "false") // ignore DNSSEC
	// TODO: add random_padding
	req.URL.RawQuery = q.Encode()

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	dnsRequestResponse := requestResponse{}
	err = json.Unmarshal(body, &dnsRequestResponse)
	if err != nil {
		log.Fatal(err)
	}

	fout := Response{}

	if len(dnsRequestResponse.Answer) <= 0 {
		return fout
	}

	fout.TTL = dnsRequestResponse.Answer[0].TTL
	fout.Data = dnsRequestResponse.Answer[0].Data
	fout.Status = dns.RcodeToString[dnsRequestResponse.Status]

	return fout
}
