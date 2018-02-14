package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	curve "golang.org/x/crypto/curve25519"
)

// the number of bits for our ECDH seed
const bits = 256

// main is the driver for the program, handles command line arguments
func main() {
	// remember these are pointers
	var serv = flag.Bool("l", false, "enable server mode (listen)")
	var verbose = flag.Bool("v", false, "verbose mode")
	var udp = flag.Bool("u", false, "use UDP instead of TCP")
	var crypto = flag.Bool("c", false, "enable encryption (ECDHKE by default)")
	var psk = flag.String("psk", "", "use given preshared key for encryption")
	var h = flag.Bool("h", false, "This help message")
	flag.Parse()
	args := flag.Args()
	/* end argument parsing */
	if *h {
		flag.Usage()
		os.Exit(0)
	}
	if *psk != "" && len(*psk) != 16 && len(*psk) != 24 && len(*psk) != 32 {
		log.Fatal("Invalid key length\n")
	}
	if *crypto && *psk == "" && *udp {
		log.Fatal("DHKE not supported in UDP mode")
	}
	if *serv {
		server(args, *udp, *crypto, *verbose, *psk)
	} else {
		client(args, *udp, *crypto, *verbose, *psk)
	}
}

// client builds the proper connection type and passes it to the base routine
func client(args []string, udp, crypto, vb bool, psk string) {
	if len(args) < 2 {
		log.Fatal("Error: No ports specified for connection\n")
	}
	// force IPv4 for now
	var proto string
	if udp {
		proto = "udp4"
	} else {
		proto = "tcp4"
	}
	// quick and dirty construction of our network address
	addr := fmt.Sprintf("%s:%s", args[0], args[1])
	conn, err := net.Dial(proto, addr)
	handle(err)
	defer conn.Close()
	if vb {
		log.Printf("Connected to %v\n", conn.RemoteAddr())
	}
	base(conn, crypto, vb, psk)
}

// server builds whichever protocol server we want
// then passes to the proper handler
func server(args []string, udp, crypto, vb bool, psk string) {
	// maybe support random port generation someday
	if len(args) < 1 {
		log.Fatal("Error: No listen port specified\n")
	}
	// going to stick with IPv4 for now
	var proto string
	addr := fmt.Sprintf(":%s", args[0])
	if udp {
		proto = "udp4"
		uaddr, err := net.ResolveUDPAddr(proto, addr)
		handle(err)
		conn, err := net.ListenUDP(proto, uaddr)
		handle(err)
		defer conn.Close()
		if vb {
			log.Printf("Listening on %v", conn.LocalAddr())
		}
		udpServer(*conn, crypto, vb, psk)
	} else {
		proto = "tcp4"
		listener, err := net.Listen(proto, addr)
		handle(err)
		defer listener.Close()
		if vb {
			log.Printf("Listening on %v", listener.Addr())
		}
		conn, err := listener.Accept()
		handle(err)
		defer conn.Close()
		if vb {
			log.Printf("Connection from %v\n", conn.RemoteAddr())
		}
		base(conn, crypto, vb, psk)
	}
}

// base works for TCP client and server, as well as UDP client
func base(conn net.Conn, crypto, vb bool, psk string) {
	var stream cipher.Stream
	iv := []byte("1234567890abcdef")
	if crypto && psk != "" {
		// let's do some crypto!
		key := []byte(psk)
		stream = CTRMode(key, iv)
		if vb {
			log.Println("built stream for PSK")
		}
	}
	firstRead := true
	firstWrite := true
	pubKey, privKey := makePubPriv()
	sharedKey := make(chan [32]byte)
	// and let's do some networking
	connbuf := bufio.NewReader(conn)
	connwr := bufio.NewWriter(conn)
	psRead := bufio.NewReader(os.Stdin)
	psWrite := bufio.NewWriter(os.Stdout)
	// anonymous routine for sending data
	go func() {
		// not sure why this didn't work at the bottom of the loop
		// but it work here, plus it feels like Javascript :)
		send := func(wr *bufio.Writer, d []byte) {
			wr.Write(d)
			wr.Flush()
		}
		for {
			txt := make([]byte, 1024)
			// if we want crypto but have no PSK, wait for the shared key
			if crypto && psk == "" && !firstWrite && stream == nil {
				key := <-sharedKey
				stream = CTRMode(key[:], iv)
			}
			// if we are just starting a connection and want dhke send the
			// key before anything else happens
			if crypto && firstWrite && stream == nil {
				// send hex encoded public key
				txt = []byte(hex.EncodeToString(pubKey[:]))
				firstWrite = false
				// else we are just doing normal communication
				send(connwr, txt)
			} else {
				// using bytes for non-string data support
				n, err := psRead.Read(txt)
				handle(err)
				if crypto {
					// perform encryption and encode for transmission
					txt = doMath(stream, txt[:n])
					txt = []byte(hex.EncodeToString(txt))
					// need to change n because read lenght != decoded/decrypted length
					n = len(txt)
				}
				send(connwr, txt[:n])
			}
			// for reasons unknown, txt failed to retain value here
			// after the DHKE implementation was added
			//connwr.Write(txt)
			//connwr.Flush()
		}
	}()

	kill := make(chan bool)
	// anonymous routine for reading data
	go func() {
		var key [32]byte
		for {
			txt := make([]byte, 1024)
			// can also use ReadSlice to get a []byte
			n, err := connbuf.Read(txt)
			handle(err)
			if crypto {
				// reverse encoding
				dec, err := hex.DecodeString(string(txt[:n]))
				handle(err)
				n = len(dec)
				if firstRead && stream == nil {
					// change the type
					var theirPub [32]byte
					copy(theirPub[:], dec)
					// calculate the shared key
					key = calcShared(theirPub, privKey)
					// send it to the writer so it knows how to encrypt
					sharedKey <- key
					firstRead = false
					stream = CTRMode(key[:], iv)
					// don't write anything on key exchange
					txt = []byte("\x00")
					n = 1
					if vb {
						log.Printf("built stream for DHKE")
					}
				} else if stream != nil {
					txt = doMath(stream, dec)
				}
			}
			psWrite.Write(txt[:n])
			psWrite.Flush()
		}
	}()
	// ghetto block for connection to end
	<-kill
}

// udpServer fufills the special requirements of UDP connectionlessness
func udpServer(conn net.UDPConn, crypto, vb bool, psk string) {
	var stream cipher.Stream
	if crypto && psk != "" {
		// let's do some crypto!
		key := []byte(psk)
		iv := []byte("1234567890abcdef")
		stream = CTRMode(key, iv)
		if vb {
			log.Println("built stream for PSK")
		}
	}
	psRead := bufio.NewReader(os.Stdin)
	psWrite := bufio.NewWriter(os.Stdout)
	haveClient := false
	// start our reader
	for {
		// we need to be able to read more at some point
		b := make([]byte, 1024)
		n, c, e := conn.ReadFromUDP(b)
		handle(e)
		if vb {
			log.Printf("Connection from %v\n", c)
		}
		if crypto {
			dec, err := hex.DecodeString(string(b[:n-1]))
			handle(err)
			b = doMath(stream, dec)
		}
		psWrite.Write(b)
		psWrite.Flush()
		// run once, start writting routine
		if !haveClient {
			// send the address read from to the send routine
			go func(cl *net.UDPAddr) {
				for {
					txt, err := psRead.ReadBytes('\n')
					handle(err)
					if crypto {
						txt = doMath(stream, txt)
						enc := hex.EncodeToString(txt)
						// append byte-wise newline
						txt = append([]byte(enc), 10)
					}
					conn.WriteMsgUDP(txt, nil, c)
				}
			}(c)
			haveClient = true
		}
	}
}

// CTRMode implements the counter mode for AES encryption/decryption
//   on the given data streams
//   inspired from https://golang.org/src/crypto/cipher/example_test.go
// CTR mode is the same for both encryption and decryption, so we can
// also decrypt that ciphertext with NewCTR.
func CTRMode(key, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	// We aren't doing that, instead since we control both client and server
	// we are just going to set it in the source
	return cipher.NewCTR(block, iv)
}

// doMath performs the actual en/decryption
// It's important to remember that ciphertexts must be authenticated
// (i.e. by using crypto/hmac) as well as being encrypted in order to
// be secure.

func doMath(stream cipher.Stream, old []byte) []byte {
	new := make([]byte, len(old))
	stream.XORKeyStream(new, old)
	return new
}

/* calcShared calculates a shared secret using curve25519 */
func calcShared(pub, priv [32]byte) [32]byte {
	var shared [32]byte
	curve.ScalarMult(&shared, &priv, &pub)
	return shared
}

/* makePubPriv creates public and private keys for curve25519 */
func makePubPriv() ([32]byte, [32]byte) {
	// generate a 32-byte Curve25519 secret key, start by generating 32 secret
	// random bytes from a cryptographically safe source
	myPrime, err := rand.Prime(rand.Reader, bits)
	handle(err)
	mine := myPrime.Bytes()
	// then add security with bit modifications
	//fmt.Println(mine)
	mine[0] &= 248
	mine[31] &= 127
	mine[31] |= 64
	var prv [32]byte
	copy(prv[:], mine)
	var pub [32]byte
	curve.ScalarBaseMult(&pub, &prv)
	return pub, prv
}

/* generic error handler */
func handle(e error) {
	if e != nil {
		log.Fatal(e)
	}
}
