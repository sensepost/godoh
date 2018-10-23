package cmd

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	"github.com/sensepost/godoh/dnsclient"
)

var testCmdName string
var testCmdRecordType string

// testCmd represents the test command
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Test DNS communications",
	Long: `Tests communications to all of the known DNS-over-HTTPS communications providers.
For example:

	godoh test --name google.com --type TXT
	godoh test -n duckduckgo.com --type A`,
	Run: func(cmd *cobra.Command, args []string) {
		if testCmdName == "" {
			log.Fatal("Please use a --name to lookup!")
		}
		if testCmdRecordType == "" {
			log.Fatal("Please set a type to lookup!")
		}

		var dnsType uint16
		switch testCmdRecordType {
		case "A":
			dnsType = dns.TypeA
			break
		case "TXT":
			dnsType = dns.TypeTXT
			break
		default:
			fmt.Printf("Unrecognized type `%s`, defaulting to A record\n", testCmdRecordType)
			dnsType = dns.TypeA
			break
		}

		c := dnsclient.NewGoogleDNS()
		values := dnsclient.Lookup(c, testCmdName, dnsType)
		fmt.Printf("Status: %s, Result: %s, TTL: %d\n", values.Status, values.Data, values.TTL)

		d := dnsclient.NewCloudFlareDNS()
		values = dnsclient.Lookup(d, testCmdName, dnsType)
		fmt.Printf("Status: %s, Result: %s, TTL: %d\n", values.Status, values.Data, values.TTL)

		e := dnsclient.NewRawDNS()
		values = dnsclient.Lookup(e, testCmdName, dnsType)
		fmt.Printf("Status: %s, Result: %s, TTL: %d\n", values.Status, values.Data, values.TTL)
	},
}

func init() {
	rootCmd.AddCommand(testCmd)

	testCmd.Flags().StringVarP(&testCmdName, "name", "n", "", "Name to lookup.")
	testCmd.Flags().StringVarP(&testCmdRecordType, "type", "t", "A", "Record type to lookup.")
}
