# secat

Security Enhanced netcAT is a learning experience to build a better version of [cryptcat](http://cryptcat.sourceforge.net/) and/or [netcat](http://nc110.sourceforge.net/)

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

## Pull Requests and Issues
Both are welcome :)