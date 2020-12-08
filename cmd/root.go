package cmd

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/sensepost/godoh/lib"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/spf13/cobra"
)

var (
	// Version is the current version
	Version string

	// CompileTimeDomain is the domain set with `make dnsDomain=foo.com`
	CompileTimeDomain string

	// options are CLI options
	options = lib.NewOptions()
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "godoh",
	Short: "A DNS (over-HTTPS) C2",
	Long: `A DNS (over-HTTPS) C2
    Version: ` + Version + `
	By @leonjza from @sensepost`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {

		rand.Seed(time.Now().UTC().UnixNano())

		// configure the TLS validation setup
		options.SetTLSValidation()

		// Setup the logger to use
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "02 Jan 2006 15:04:05"})
		if options.Debug {
			log.Logger = log.Logger.Level(zerolog.DebugLevel)
			log.Logger = log.With().Caller().Logger()
			log.Debug().Msg("debug logging enabed")
		} else {
			log.Logger = log.Logger.Level(zerolog.InfoLevel)
		}
		if options.DisableLogging {
			log.Logger = log.Logger.Level(zerolog.Disabled)
		}

		options.Logger = &log.Logger

		// if we have a compile time domain, use that if one is not set via CLI
		if (options.Domain == "") && (CompileTimeDomain != "") {
			log.Debug().Str("domain", CompileTimeDomain).Msg("using compile time domain")
			options.Domain = CompileTimeDomain
		} else {
			log.Debug().Str("domain", options.Domain).Msg("using flag domain")
		}

	},
	Run: func(cmd *cobra.Command, args []string) {

		// by default, start in agent mode
		if len(args) == 0 {
			agentCmd.Run(cmd, args)
			os.Exit(0)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {

	// logging
	rootCmd.PersistentFlags().BoolVar(&options.Debug, "debug", false, "enable debug logging")
	rootCmd.PersistentFlags().BoolVar(&options.DisableLogging, "disable-logging", false, "disable all logging")

	// if the DNS domain was configured at compile time, remove the flag
	if options.Domain == "" {
		rootCmd.PersistentFlags().StringVarP(&options.Domain, "domain", "d", "", "DNS Domain to use. (ie: example.com)")
	}

	rootCmd.PersistentFlags().StringVarP(&options.ProviderName, "provider", "p", "google", "Preferred DNS provider to use. [possible: googlefront, google, cloudflare, quad9, raw]")
	rootCmd.PersistentFlags().BoolVarP(&options.ValidateTLS, "validate-certificate", "K", false, "Validate DoH provider SSL certificates")
}
