package cmd

import (
	"strconv"

	"github.com/miekg/dns"
	"github.com/sensepost/godoh/dnsserver"
	"github.com/sensepost/godoh/protocol"
	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"
)

// receiveCmd represents the receive command
var receiveCmd = &cobra.Command{
	Use:   "receive",
	Short: "Receive a file via DoH",
	Long: `Receive a file via DoH.
Starts a DNS server to receive files. Files received will be dumped to the 
current working directory using the original file name the target file had.

Example:
	godoh --domain example.com receive`,
	Run: func(cmd *cobra.Command, args []string) {

		srv := &dns.Server{Addr: ":" + strconv.Itoa(53), Net: "udp"}
		srv.Handler = &dnsserver.Handler{
			StreamSpool: make(map[string]protocol.DNSBuffer),
		}
		log.Info("Serving DNS")
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Failed to set udp listener %s\n", err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(receiveCmd)
}
