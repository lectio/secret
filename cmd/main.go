package main

import (
	"fmt"
	"os"

	"github.com/docopt/docopt-go"
	"github.com/lectio/secret"
)

var usage = `Lectio Secrets Management Utility.

Usage:
  secret hash <text>
  secret encrypt text <text> with passwd <passPhrase> [--verbose]
  secret encrypt text <text> with vault <vaultName> [--verbose]
  secret decrypt text <text> with passwd <passPhrase> [--verbose]
  secret decrypt text <text> with vault <vaultName> [--verbose]

Options:
  -h --help     Show this screen.
  -v --verbose  Show verbose messages`

func getUserOptions() *config {
	arguments, pdErr := docopt.ParseDoc(usage)
	if pdErr != nil {
		panic(pdErr)
	}
	options := new(config)
	bindErr := arguments.Bind(options)
	if bindErr != nil {
		fmt.Printf("%+v, %v", options, bindErr)
		panic(pdErr)
	}
	return options
}

type config struct {
	Hash       bool   `docopt:"hash"`
	Encrypt    bool   `docopt:"encrypt"`
	Decrypt    bool   `docopt:"decrypt"`
	Text       bool   `docopt:"text"`
	TextValue  string `docopt:"<text>"`
	With       bool   `docopt:"with"`
	Passwd     bool   `docopt:"passwd"`
	Vault      bool   `docopt:"vault"`
	PassPhrase string `docopt:"<passPhrase>"`
	VaultName  string `docopt:"<vaultName>"`
	Verbose    bool   `docopt:"-v,--verbose"`
}

func main() {
	options := getUserOptions()

	var passPhrase string
	var ok bool
	if options.Passwd {
		passPhrase = options.PassPhrase
		ok = true
	} else if options.Vault {
		passPhrase, ok = os.LookupEnv(options.VaultName)
		if !ok {
			panic("Environment variable " + options.VaultName + " not found.")
		}
	}

	switch {
	case options.Hash:
		fmt.Println(secret.CreateHash(options.TextValue))
	case options.Encrypt:
		encrypted, err := secret.EncryptText(options.TextValue, passPhrase)
		if options.Verbose {
			fmt.Printf("%q encrypted with %q is %q (error: %v)\n", options.TextValue, passPhrase, encrypted, err)
		} else {
			fmt.Printf("%s", encrypted)
			if err != nil {
				panic(err)
			}
		}
	case options.Decrypt:
		decrypted, err := secret.DecryptText(options.TextValue, passPhrase)
		if options.Verbose {
			fmt.Printf("%q decrypted with %q is %q (error: %v)\n", options.TextValue, passPhrase, decrypted, err)
		} else {
			fmt.Printf("%s", decrypted)
			if err != nil {
				panic(err)
			}
		}
	}
}
