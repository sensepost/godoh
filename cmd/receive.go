package cmd

import (
	"strconv"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	"github.com/sensepost/godoh/dnsserver"
	"github.com/sensepost/godoh/protocol"
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

		log := options.Logger

		srv := &dns.Server{Addr: ":" + strconv.Itoa(53), Net: "udp"}
		srv.Handler = &dnsserver.Handler{
			StreamSpool: make(map[string]protocol.DNSBuffer),
		}
		log.Info().Msg("starting dns server")
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal().Err(err).Msg("failed to start dns server")
		}
	},
}

func init() {
	rootCmd.AddCommand(receiveCmd)
}
