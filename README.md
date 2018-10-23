<h1 align="center">
  <br>
  <a href="https://github.com/sensepost/goDoH">
    godoh
  </a>
  <br>
  <br>
</h1>

<h4 align="center">A DNS-over-HTTPS Command & Control Proof of Concept</h4>
<br>

## introduction

`godoh` is a proof of concept Command and Control framework, written in Golang, that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google, Cloudflare but also contains the ability to use traditional DNS.

## installation

All you would need are the `godoh` binaries themselves. Binaries are available for download from the [releases](https://github.com/sensepost/goDoH/releases) page as part of tagged releases.

To build `godoh` from source, follow the following steps:

* Ensure you have [dep](https://github.com/golang/dep) installed (`go get -v -u github.com/golang/dep/cmd/dep`)
* Clone this repository to your `$GOPATH`'s `src/` directory so that it is in `sensepost/goDoH`
* Run `dep ensure` to resolve dependencies
* Run `make key` to generate a unique encryption key to use for communication
* Use the `go` build tools, or run `make` to build the binaries in the `build/` directory

## usage

```txt
$ godoh -h
A DNS (over-HTTPS) C2

Usage:
  godoh [command]

Available Commands:
  agent       Connect as an Agent to the DoH C2
  c2          Starts the godoh C2 server
  help        Help about any command
  receive     Receive a file via DoH
  send        Send a file via DoH
  test        Test DNS communications

Flags:
  -d, --domain string     DNS Domain to use. (ie: example.com)
  -h, --help              help for godoh
  -p, --provider string   Preferred DNS provider to use. [possible: google, cloudflare, raw] (default "google")

Use "godoh [command] --help" for more information about a command.
```

## license

`godoh` is licensed under a [GNU General Public v3 License](https://www.gnu.org/licenses/gpl-3.0.en.html). Permissions beyond the scope of this license may be available at http://sensepost.com/contact/.
