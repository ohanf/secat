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

## Pull Requests and Issues
Both are welcome :)
