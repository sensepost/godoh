package ntlm

import (
	"encoding/base64"
	"fmt"
)

func ParseChallengeResponse(header string) ([]byte, error) {
	if len(header) < 6 {
		return nil, fmt.Errorf("Invalid NTLM challenge response: %q", header)
	}

	//parse out the "NTLM " at the beginning of the response
	challenge := header[5:]
	val, err := base64.StdEncoding.DecodeString(challenge)

	if err != nil {
		return nil, err
	}
	return []byte(val), nil
}
