package protocol

import (
	"crypto/rand"
	"fmt"
	"hash/crc32"
	"log"

	"github.com/sensepost/godoh/lib"
)

// Requestify generates hostnames for DNS lookups
//
// A full conversation with the server will involve multiple DNS lookups.
// Requestifying assumes that the client will be sending data to the server.
// Each request normally requires the server to respond with a specific IP
// address indicating success, failure or other scenarios. Checking these is
// up to the caller to verify, but something to keep in mind.
//
// Generically speaking, hostnames for lookups will have multiple labels. ie:
//	Structure:
//		ident.type.seq.crc32.proto.datalen.data.data.data
//
//	ident: 		the identifier for this specific stream
//	type:		stream status indicator. ie: start, sending, stop
//	seq:		a sequence number to track request count
//	crc32:		checksum value
//	proto:		the protocol this transaction is for. eg: file transfer/cmd
// 	datalen:	how much data does this packet have
//	data:		the labels containing data. max of 3 but can have only one too
//
//	Size: 4 + 2 + 16 + 8 + 2 + 2 + 60 + 60 + 60 for a maximum size of 214
//  Sample:
//		0000.00.0000000000000000.00000000.00.00.60.60.60
//
// Note: Where the label lenths may be something like 60, a byte takes two of
// those, meaning that each data label is only 30 bytes for a total of 90
// bytes per request, excluding ident, seq and crc32.
func Requestify(data []byte, protocol int) []string {
	var requests []string

	seq := 1
	ident := make([]byte, 2)
	if _, err := rand.Read(ident); err != nil {
		log.Fatal(err)
	}

	var emptyBytes []byte
	// Start stream / end stream bytes.
	// initBytes := []byte{0x00, 0x00, 0x00}
	// destuctBytes := []byte{0xff, 0xff, 0xff}
	// destuctBytes := []byte{0x01, 0x01, 0x01}

	// blankBytes := initBytes

	// initialization request to start this stream
	initRequest := fmt.Sprintf("%x.%x.%d.%02x.%x.%x.%x.%x.%x",
		ident, StreamStart, seq-1, crc32.ChecksumIEEE(emptyBytes), protocol, 0, 0x00, 0x00, 0x00)
	requests = append(requests, initRequest)

	for _, s := range lib.ByteSplit(data, 90) {
		labelSplit := lib.ByteSplit(s, 30)

		// Having the data split into 3 labels, prepare the data label
		// that will be used in the request.
		var dataLabel string
		switch len(labelSplit) {
		case 1:
			dataLabel = fmt.Sprintf("%x.%x.%x", labelSplit[0], 0x00, 0x00)
			break
		case 2:
			dataLabel = fmt.Sprintf("%x.%x.%x", labelSplit[0], labelSplit[1], 0x00)
			break
		case 3:
			dataLabel = fmt.Sprintf("%x.%x.%x", labelSplit[0], labelSplit[1], labelSplit[2])
			break
		}

		request := fmt.Sprintf("%x.%x.%d.%02x.%x.%x.%s",
			ident, StreamData, seq, crc32.ChecksumIEEE(s), protocol, len(labelSplit), dataLabel)
		requests = append(requests, request)

		// increment the sequence number
		seq++
	}

	destructRequest := fmt.Sprintf("%x.%x.%d.%02x.%x.%x.%x.%x.%x",
		ident, StreamEnd, seq, crc32.ChecksumIEEE(emptyBytes), protocol, 0, 0x00, 0x00, 0x00)
	requests = append(requests, destructRequest)

	return requests
}

// Textify creates a TXT record response
func Textify(data []byte, protocol int) string {
	return ""
}
