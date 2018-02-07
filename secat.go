package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
)

// the number of bits for our DHKE primes
const bits = 128

func main() {
	// remember this is a pointer
	var serv = flag.Bool("l", false, "enable server mode (listen)")
	// var verbose = flag.Bool("v", false, "verbose mode")
	flag.Parse()
	fmt.Println(flag.Args())
	// eventually factor out to debug flag
	fmt.Println("starting...")
	//CTRMode()
	// define our prime for dhke
	/*
		    myPrime, err := rand.Prime(rand.Reader, bits)
			//handle(err)
			// get the public data to send to server
		    ourPrime, ourMod := genDH()
		    // compute the secret key for use with aes
		    secKey := big.NewInt(0)
		    secKey.Exp(ourPrime, myPrime, ourMod)
		    // we will want to call secKey.Bytes for use as AES key later
		    // debug
		    fmt.Printf("debug: %v %v %v %v\n", myPrime, ourPrime, ourMod, secKey.BitLen())
	*/
	if *serv {
		server()
	} else {
		client()
	}
}

func client() {
	tcpAddr, err := net.ResolveTCPAddr("tcp", "localhost:12345")
	handle(err)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	handle(err)
	defer conn.Close()
	base(conn)
}

func server() {
	listener, err := net.Listen("tcp", "localhost:12345")
	handle(err)
	defer listener.Close()
	conn, err := listener.Accept()
	handle(err)
	defer conn.Close()
	base(conn)
}

func base(conn net.Conn) {
	connbuf := bufio.NewReader(conn)
	connwr := bufio.NewWriter(conn)
	psRead := bufio.NewReader(os.Stdin)
	psWrite := bufio.NewWriter(os.Stdout)
	go func() {
		for {
			txt, err := psRead.ReadString('\n')
			handle(err)
			// can also use Write to write []byte
			connwr.WriteString(txt)
			connwr.Flush()
		}
	}()

	kill := make(chan bool)

	go func() {
		for {
			// can also use ReadSlice to get a []byte
			str, err := connbuf.ReadString('\n')
			if len(str) > 0 {
				psWrite.WriteString(str)
				psWrite.Flush()
			}
			handle(err)
		}
	}()
	// ghetto block for connection to end
	<-kill
}

// CTRMode implements the counter mode for AES encryption/decryption
//   on the given data streams
//   inspired from https://golang.org/src/crypto/cipher/example_test.go
//
func CTRMode() {
	key := []byte("example key 1234")
	plaintext := []byte("some plaintext")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	fmt.Printf("%v\n", hex.EncodeToString(ciphertext[aes.BlockSize:]))

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	// CTR mode is the same for both encryption and decryption, so we can
	// also decrypt that ciphertext with NewCTR.

	plaintext2 := make([]byte, len(plaintext))
	stream = cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext2, ciphertext[aes.BlockSize:])

	fmt.Printf("%s\n", plaintext2)
	// Output: some plaintext
}

/* genDH generates the public base and modulus for DHKE */
func genDH() (*big.Int, *big.Int) {
	// define the public base prime
	ourPrime, err := rand.Prime(rand.Reader, bits)
	handle(err)
	// define the public modulus
	ourMod, err := rand.Prime(rand.Reader, bits)
	handle(err)
	return ourPrime, ourMod
}

/* generic error handler */
func handle(e error) {
	if e != nil {
		log.Fatal(e)
	}
}
