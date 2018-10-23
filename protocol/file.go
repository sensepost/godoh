package protocol

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"os"

	"github.com/sensepost/godoh/utils"
)

// File represents a file to be send over DNS.
type File struct {
	Size       int64
	Shasum     string
	Name       string
	Data       *[]byte
	identifier string
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
	fc.identifier = utils.RandomString(5)
}

// GetRequests returns the hostnames to lookup as part of a file
// transfer operation.
func (fc *File) GetRequests() ([]string, string) {

	var b bytes.Buffer
	utils.GobPress(fc, &b)

	requests := Requestify(b.Bytes(), FileProtocol)

	return requests, SuccessDNSResponse
}
