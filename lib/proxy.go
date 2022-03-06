package lib

import (
	"bufio"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func ProxySetup(conn net.Conn, targetAddr string, username string, password string, useragent string) error {

	hdr := make(http.Header)
	basicAuth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	hdr.Set("User-Agent", useragent)
	hdr.Set("Proxy-Authorization", "Basic "+basicAuth)
	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: targetAddr},
		Host:   targetAddr,
		Header: hdr,
	}
	connectReq.Write(conn)

	// Read response.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		f := strings.SplitN(resp.Status, " ", 2)
		return errors.New(f[1])
	}

	return nil
}
