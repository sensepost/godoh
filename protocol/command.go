package protocol

import (
	"bytes"
	"time"

	"github.com/sensepost/godoh/utils"
)

// Command represents a command to be send over DNS.
type Command struct {
	Exec       string
	Data       []byte
	ExecTime   time.Time
	identifier string
}

// Prepare configures the File struct with relevant data.
func (c *Command) Prepare(cmd string) {

	c.Exec = cmd
	c.identifier = utils.RandomString(5)
}

// GetOutgoing returns the hostnames to lookup as part of a file
// transfer operation.
func (c *Command) GetOutgoing() string {

	return c.Exec
}

// GetRequests returns the hostnames to lookup as part of a command
// output operation.
func (c *Command) GetRequests() ([]string, string) {

	var b bytes.Buffer
	utils.GobPress(c, &b)

	requests := Requestify(b.Bytes(), CmdProtocol)

	return requests, SuccessDNSResponse
}
