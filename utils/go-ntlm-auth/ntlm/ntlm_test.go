package ntlm

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNtlmHeaderParseValid(t *testing.T) {
	header := "NTLM " + base64.StdEncoding.EncodeToString([]byte("Some data"))
	bytes, err := ParseChallengeResponse(header)

	if err != nil {
		t.Fatalf("Unexpected exception!")
	}

	// Check NTLM has been stripped from response
	if strings.HasPrefix(string(bytes), "NTLM") {
		t.Fatalf("Response contains NTLM prefix!")
	}
}

func TestNtlmHeaderParseInvalidLength(t *testing.T) {
	header := "NTL"
	ret, err := ParseChallengeResponse(header)
	if ret != nil {
		t.Errorf("Unexpected challenge response: %v", ret)
	}

	if err == nil {
		t.Errorf("Expected error, got none!")
	}
}

func TestNtlmHeaderParseInvalid(t *testing.T) {
	header := base64.StdEncoding.EncodeToString([]byte("NTLM I am a moose"))
	_, err := ParseChallengeResponse(header)

	if err == nil {
		t.Fatalf("Expected error, got none!")
	}
}
