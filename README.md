<h1 align="center">
  <br>
  <a href="https://github.com/sensepost/goDoH">
    🕳 godoh
  </a>
  <br>
  <br>
</h1>

<h4 align="center">A DNS-over-HTTPS Command & Control Proof of Concept</h4>
<p align="center">
  <a href="https://twitter.com/leonjza"><img src="https://img.shields.io/badge/Twitter-%40leonjza-blue.svg" alt="@leonjza" height="18"></a>
  <a href="https://goreportcard.com/report/github.com/sensepost/goDoH"><img src="https://goreportcard.com/badge/github.com/sensepost/goDoH" alt="Go Report Card" height="18"></a>
</p>
<br>

## The following updates have been implemented from the latest current version of [godoh](https://github.com/sensepost/godoh)

* Added support for HTTP basic authentication proxy
* Added support for specifying a custom "AES key" from command line (used to encrypt data blobs in communications)
* Added support for specifying a custom "User-Agent" (default: Edge 44 on Windows 10) from command line
* Added Blokada & NextDNS providers support
* Fix issues with Quad9 provider

## introduction

`godoh` is a proof of concept Command and Control framework, written in Golang, that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google, Cloudflare but also contains the ability to use traditional DNS.

## installation

All you would need are the `godoh` binaries themselves. Binaries are available for download from the [releases](https://github.com/sensepost/goDoH/releases) page as part of tagged releases.

To build `godoh` from source, follow the following steps:

* Ensure you have Go 1.13+
* Clone this repository with `git clone https://github.com/sensepost/goDoH.git`
* Run `make key` to generate a unique encryption key to use for communication
* Build the project with one of the following options:
  * `go build` which will drop you a new `godoh` binary for the current architecture
  * `make` which will drop binaries in the `build/` directory for various platforms

## usage

```txt
A DNS (over-HTTPS) C2
  By @leonjza from @sensepost

Usage:
  godoh [flags]
  godoh [command]

Available Commands:
  agent       Connect as an Agent to the DoH C2
  c2          Starts the godoh C2 server
  help        Help about any command
  receive     Receive a file via DoH
  send        Send a file via DoH
  test        Test DNS communications

Flags:
  -d, --domain string          DNS Domain to use. (ie: example.com)
  -h, --help                   help for godoh
  -p, --provider string        Preferred DNS provider to use. [possible: googlefront, google, cloudflare, quad9, raw] (default "google")
  -K, --validate-certificate   Validate DoH provider SSL certificates

Use "godoh [command] --help" for more information about a command.
```

## license

`godoh` is licensed under a [GNU General Public v3 License](https://www.gnu.org/licenses/gpl-3.0.en.html). Permissions beyond the scope of this license may be available at http://sensepost.com/contact/.
