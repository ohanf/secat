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

Basic client usage: `./secat 1.1.1.1 12345`

Basic server usage: `./secat -l 12345`

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

 - Alternitively use `go run secat.go <options>` in a development environment

 - Note: This utility was built on (Arch) Linux and has no compatibily promises. However, it should work on most Linux based systems

## Security Notes
 - This tool is under active development, use at your own risk
 - While the contents of the packets are encrypted, there is no padding of the messages
    - Consider side channel attacks and/or metadata leaks
 - Currently there is no HMAC or other message authentication for packets
 - Finally, the current AES mode being used is CTR, which is resistant to corrupted blocks. However, it does require that the blocks be processed in order, 
    reducing the usefulness of UDP communications.
    - Any suggestions to improve this constraint are appreciated.

## Pull Requests and Issues
Both are welcome :)

## Contact
Questions about the project or just want to say hi? Reach out to me on [keybase](https://keybase.io/ohan) and mention `secat`!

## Cryptography Notice

This distribution includes cryptographic software. The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software.
BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, or use, and re-export of encryption software, to see if this is permitted.
See <http://www.wassenaar.org/> for more information.

The U.S. Government Department of Commerce, Bureau of Industry and Security (BIS), has classified this software as Export Commodity Control Number (ECCN) 5D002.C.1, which includes information security software using or performing cryptographic functions with asymmetric algorithms.
The form and manner of this distribution makes it eligible for export under the License Exception ENC Technology Software Unrestricted (TSU) exception (see the BIS Export Administration Regulations, Section 740.13) for both object code and source code.

## License

&copy; 2018 Ohan Fillbach

Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
