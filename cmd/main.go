package main

import (
	"fmt"

	"github.com/docopt/docopt-go"
	"github.com/lectio/secret"
)

var usage = `Lectio Secrets Management Utility.

Usage:
  secret hash <text>
  secret encrypt text <text> with passwd <passPhrase> [--verbose]
  secret encrypt text <text> with vault <vaultURL> [--verbose]
  secret decrypt text <text> with passwd <passPhrase> [--verbose]
  secret decrypt text <text> with vault <vaultURL> [--verbose]

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
	VaultURL  string `docopt:"<vaultURL>"`
	Verbose    bool   `docopt:"-v,--verbose"`
}

func main() {
	options := getUserOptions()

	if options.Passwd {
		options.VaultURL = "passwd://" + options.PassPhrase
	}
	vault, err := secret.Parse(options.VaultURL)
	if err != nil {
		panic(fmt.Sprintf("Vault %q error: %v", options.VaultURL, err))
	}

	switch {
	case options.Hash:
		fmt.Println(secret.CreateHash(options.TextValue))
	case options.Encrypt:
		encrypted, err := vault.EncryptText(options.TextValue)
		if options.Verbose {
			fmt.Printf("%q encrypted with %+v is %q (error: %v)\n", options.TextValue, vault, encrypted, err)
		} else {
			fmt.Printf("%s", encrypted)
			if err != nil {
				panic(err)
			}
		}
	case options.Decrypt:
		decrypted, err := vault.DecryptText(options.TextValue)
		if options.Verbose {
			fmt.Printf("%q decrypted with %+v is %q (error: %v)\n", options.TextValue, vault, decrypted, err)
		} else {
			fmt.Printf("%s", decrypted)
			if err != nil {
				panic(err)
			}
		}
	}
}
