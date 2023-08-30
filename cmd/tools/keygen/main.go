// Command keygen is a simple CLI tool for generating ED25519 key pairs, which
// can be used for issuing (i.e. signing) and verifying JWT tokens.
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/RMI/credential-service/keyutil"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var (
		keyType = flag.String("key_type", "ed25519", "The type of the key pair to generate, currently only 'ed25519' is supported")

		pubKeyFile  = flag.String("public_key_file", "test_server.pub", "The path to write the public key output to.")
		privKeyFile = flag.String("private_key_file", "test_server.key", "The path to write the private key output to.")
	)
	flag.Parse()

	switch *keyType {
	case "ed25519":
		// This is the only one we currently support.
	default:
		return fmt.Errorf("unsupported key type %q", *keyType)
	}

	if err := keyutil.GenerateED25519ToFiles(*pubKeyFile, *privKeyFile); err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	return nil
}
