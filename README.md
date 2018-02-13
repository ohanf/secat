# secat

Security Enhanced netCAT is a learning experience to build a better version of [cryptcat](http://cryptcat.sourceforge.net/) and/or [netcat](http://nc110.sourceforge.net/)

## Goals
 - Fully compatible with "standard" netcat
 - Retain features of the standard netcat distributions
    - TCP and UDP support
    - Verbose logging available
    - Execute command on connection
    - ...others...
- Eventually add both IPv4 and IPv6 support
- Implement cryptographic wrapper to secure communications
    - AES 256
        - PSK
        - ECDHE
- Learn more about Golang, crypto, socket programming and realtime network communications

## Current Features
 - Basic TCP/UDP client/server functionality
 - Basic verbose option
 - AES with PSK support in both TCP and UDP modes
   - pass both `-c` and `--psk "example key 1234"`
   - psk must be either 16, 24 or 32 bytes (for AES 128, 192 or 256 respectively)
 - AES-256 with (automatic) ECDHE in TCP mode only
   - pass just the `-c` flag

## Usage
```
Usage of ./secat:
  -c    enable encryption (ECDHKE by default)
  -h    This help message
  -l    enable server mode (listen)
  -psk string
        use given preshared key for encryption
  -u    use UDP instead of TCP
  -v    verbose mode
 ```

 ## Build
  - As with any `golang` program all you should have to do is `go build secat.go` followed by `./secat <options>`
    - May need to install the crypto subrepo package curve25519: `go get golang.org/x/crypto/curve25519`

 - Alternitively one use `go run secat.go <options>` in a development environment

 - Note: This utility was built on (Arch) Linux and has no compatibily promises. However, it should work on most Linux based systems

## Pull Requests and Issues
Both are welcome :)

## Contact
Questions about the project or just want to say hi? Reach out to me on [keybase](https://keybase.io/ohan) and mention `secat`!
