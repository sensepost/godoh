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

// Quad9DNS is a Client instance resolving using Quad9's DNS-over-HTTPS service
type Quad9DNS struct {
	BaseURL   string
	UserAgent string
}

// Lookup performs a DNS lookup using Quad9
func (c *Quad9DNS) Lookup(name string, rType uint16) Response {

	client := http.Client{
		Timeout: time.Second * 20,
	}

	req, err := http.NewRequest("GET", c.BaseURL, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("User-Agent", c.UserAgent)

	q := req.URL.Query()
	q.Add("name", name)
	q.Add("type", strconv.Itoa(int(rType)))
	q.Add("cd", "false") // ignore DNSSEC
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
