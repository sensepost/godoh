package protocol

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"os"

	"github.com/sensepost/godoh/lib"
)

// File represents a file to be send over DNS.
type File struct {
	Size        int64   `json:"size"`
	Shasum      string  `json:"shasum"`
	Name        string  `json:"name"`
	Destination string  `json:"destination"`
	Data        *[]byte `json:"data"`
	Identifier  string  `json:"identifier"`
}

// Prepare configures the File struct with relevant data.
func (fc *File) Prepare(data *[]byte, fileInfo os.FileInfo) {

	// prepare a shasum instance
	h := sha1.New()
	h.Write(*data)

	fc.Size = fileInfo.Size()
	fc.Shasum = hex.EncodeToString(h.Sum(nil))
	fc.Name = fileInfo.Name()
	fc.Data = data
	fc.Identifier = lib.RandomString(5)
}

// GetARequests returns the hostnames to lookup as part of a file
// transfer operation via A records.
func (fc *File) GetARequests() ([]string, string) {

	var b bytes.Buffer
	lib.GobPress(fc, &b)

	requests := ARequestify(b.Bytes(), FileProtocol)

	return requests, SuccessDNSResponse
}

// GetTXTRequests returns the TXT record contents to return as
// part of a file transfer operation via TXT records
func (fc *File) GetTXTRequests() []string {
	var b bytes.Buffer
	lib.GobPress(fc, &b)

	requests := TXTRequestify(b.Bytes(), FileProtocol)

	return requests
}
