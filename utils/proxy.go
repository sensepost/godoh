package utils

// Originally from  github.com/anynines/go-ntlm-client-using-dialcontext/ntlm,
// reimplemented to add support for credentials being passed by commandline

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	 _ "unsafe"

	ntlmauth "github.com/sensepost/godoh/utils/go-ntlm-auth/ntlm"
)

func ProxySetup(conn net.Conn, targetAddr string, username string, password string) error {
	var auth ntlmauth.NtlmAuthenticator
	var authOk bool
	if username == "" {
		auth, authOk = ntlmauth.GetDefaultCredentialsAuth()
	} else	{
		auth, authOk = ntlmauth.GetAuth(username,password,"","")
		}

		if !authOk {
			return errors.New("Failed to set NTLM auth")
		}

	negotiateMessageBytes, err := auth.GetNegotiateBytes()
	if err != nil {
		return errors.New("Failed to get NTLM negotiaten bytes")
	}
	defer auth.ReleaseContext()

	negotiateMsg := base64.StdEncoding.EncodeToString(negotiateMessageBytes)

	hdr := make(http.Header)
	hdr.Set("Proxy-Connection", "Keep-Alive")
	hdr.Set("Proxy-Authorization", "NTLM "+negotiateMsg)
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
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode != 407 {
		f := strings.SplitN(resp.Status, " ", 2)
		return errors.New(f[1])
	}

	// decode challenge
	challengeMessage, err := ntlmauth.ParseChallengeResponse(resp.Header.Get("Proxy-Authenticate"))
	if err != nil {
		return err
	}

	challengeBytes, err := auth.GetResponseBytes(challengeMessage)
	if err != nil {
		return err
	}

	authMsg := base64.StdEncoding.EncodeToString(challengeBytes)
	hdr.Set("Proxy-Authorization", "NTLM "+authMsg)
	connectReq = &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: targetAddr},
		Host:   targetAddr,
		Header: hdr,
	}
	connectReq.Write(conn)

	// Read response.
	resp, err = http.ReadResponse(br, connectReq)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		f := strings.SplitN(resp.Status, " ", 2)
		return errors.New(f[1])
	}

	return nil
}
