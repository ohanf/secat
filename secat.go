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
	var crypto = flag.Bool("c", false, "enable encryption")
	var psk = flag.String("psk", "example key 1234", "preshared key for encryption")
	var h = flag.Bool("h", false, "help / debug")
	flag.Parse()
	args := flag.Args()
	/* end argument parsing */
	if *h {
		test()
		os.Exit(0)
	}
	if len(*psk) != 16 && len(*psk) != 24 && len(*psk) != 32 {
		log.Fatal("Invalid key length\n")
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
	base(conn, crypto, psk)
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
		base(conn, crypto, psk)
	}
}

// base works for TCP client and server, as well as UDP client
func base(conn net.Conn, crypto bool, psk string) {
	var stream cipher.Stream
	if crypto {
		// let's do some crypto!
		key := []byte(psk)
		iv := []byte("1234567890abcdef")
		stream = CTRMode(key, iv)
	}
	// and let's do some networking
	connbuf := bufio.NewReader(conn)
	connwr := bufio.NewWriter(conn)
	psRead := bufio.NewReader(os.Stdin)
	psWrite := bufio.NewWriter(os.Stdout)
	// anonymous routine for sending data
	go func() {
		for {
			// using bytes for non-string data support
			txt, err := psRead.ReadBytes('\n')
			handle(err)
			if crypto {
				// perform encryption and encode for transmission
				txt = doMath(stream, txt)
				enc := hex.EncodeToString(txt)
				// add the newline bytewise
				txt = append([]byte(enc), 10)
			}
			connwr.Write(txt)
			connwr.Flush()
		}
	}()

	kill := make(chan bool)
	// anonymous routine for reading data
	go func() {
		for {
			// can also use ReadSlice to get a []byte
			txt, err := connbuf.ReadBytes('\n')
			handle(err)
			if crypto {
				// reverse encoding and remove extra newline
				dec, err := hex.DecodeString(string(txt[:len(txt)-1]))
				handle(err)
				txt = doMath(stream, dec)
			}
			psWrite.Write(txt)
			psWrite.Flush()
		}
	}()
	// ghetto block for connection to end
	<-kill
}

// udpServer fufills the special requirements of UDP connectionlessness
func udpServer(conn net.UDPConn, crypto, vb bool, psk string) {
	var stream cipher.Stream
	if crypto {
		// let's do some crypto!
		key := []byte(psk)
		iv := []byte("1234567890abcdef")
		stream = CTRMode(key, iv)
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
//
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

// CTR mode is the same for both encryption and decryption, so we can
// also decrypt that ciphertext with NewCTR.
func doMath(stream cipher.Stream, old []byte) []byte {
	new := make([]byte, len(old))
	stream.XORKeyStream(new, old)
	return new
}

func test() {
	myPub, myPriv := makePubPriv()
	hisPub, hisPriv := makePubPriv()
	key1 := calcShared(myPub, hisPriv)
	key2 := calcShared(hisPub, myPriv)
	fmt.Printf("keys the same? %v\n", key1 == key2)
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
