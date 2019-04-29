package secret

import (
	"sync"
	"fmt"
	"os"
	"net/url"
)

var factory sync.Map
var plainTextVault Vault = &nullVault{}

// Vault defines a URL with instructions for how to encrypt/decrypt data
type Vault interface {
	EncryptText(text string) (string, error)
	DecryptText(text string) (string, error) 
}

type nullVault struct {
}

type envVault struct {
	envVarName string
	passPhrase string
}

type passPhraseVault struct {
	passPhrase string
}

// Parse the given text into a Vault instance
func Parse(urlText string) (Vault, error) {
	result, ok := factory.Load(urlText)
	if ok {
		return result.(Vault), nil
	}

	u, err := url.Parse(urlText)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		return nil, fmt.Errorf("url scheme is empty in secret.Parse(%q)", urlText)
	}

	switch u.Scheme {
	case "env":
		vault, newVaultErr := newEnvVault(u.Hostname())
		if newVaultErr != nil {
			return nil, newVaultErr
		}
		factory.Store(urlText, vault)
		return vault, nil
	case "passwd":
		vault := &passPhraseVault{passPhrase: u.Hostname()}
		factory.Store(urlText, vault)
		return vault, nil
	case "plain":
		return plainTextVault, nil
	default:
		return nil, fmt.Errorf("Unable to handle unknown scheme %q in %q", u.Scheme, u.String())
	}
}

// EncryptText does not encrypt, just sends the text back as plaintext
func (v nullVault) EncryptText(text string) (string, error) {
	return text, nil
}

// EncryptText does not decrypt, just sends the text back as plaintext
func (v nullVault) DecryptText(text string) (string, error) {
	return text, nil
}

// String satisfies the stringer interface.
func (v nullVault) String() string {
	return "plain://text"
}

func newEnvVault(envVarName string) (*envVault, error) {
	passPhrase, ok := os.LookupEnv(envVarName)
	if !ok {
		return nil, fmt.Errorf("secret.newEnvVault environment variable %q not set", envVarName)
	}
	return &envVault{envVarName: envVarName, passPhrase: passPhrase}, nil
}

// EncryptText encrypts text using a passphrase given a specific the env variable
func (v envVault) EncryptText(text string) (string, error) {
	return EncryptText(text, v.passPhrase)
}

// DecryptText decrypts text using a passphrase given a specific the env variable
func (v envVault) DecryptText(text string) (string, error) {
	return DecryptText(text, v.passPhrase)
}

// String satisfies the stringer interface.
func (v envVault) String() string {
	return fmt.Sprintf("env://%s", v.envVarName)
}

// EncryptText encrypts text using a literal passphrase
func (v passPhraseVault) EncryptText(text string) (string, error) {
	return EncryptText(text, v.passPhrase)
}

// DecryptText decrypts text using a literal passphrase
func (v passPhraseVault) DecryptText(text string) (string, error) {
	return DecryptText(text, v.passPhrase)
}

// String satisfies the stringer interface.
func (v passPhraseVault) String() string {
	return fmt.Sprintf("passwd://%s", v.passPhrase)
}