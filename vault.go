package secret

import (
	"sync"
	"fmt"
	"os"
	"net/url"
)

var factory sync.Map

// Vault defines a URL with instructions for how to encrypt/decrypt data
type Vault interface {
	EncryptText(text string) (string, error)
	DecryptText(text string) (string, error) 
}

type envVault struct {
	envVar string
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
		vault := &envVault{envVar: u.Hostname()}
		factory.Store(urlText, vault)
		return vault, nil
	case "passwd":
		vault := &passPhraseVault{passPhrase: u.Hostname()}
		factory.Store(urlText, vault)
		return vault, nil
	default:
		return nil, fmt.Errorf("Unable to handle unknown scheme %q in %q", u.Scheme, u.String())
	}
}

// EncryptText encrypts text using instructions given in Vault URL
func (v envVault) EncryptText(text string) (string, error) {
	passPhrase, ok := os.LookupEnv(v.envVar)
	if !ok {
		return "", fmt.Errorf("secret.envVault environment variable %q not set", v.envVar)
	}
	return EncryptText(text, passPhrase)
}

// DecryptText decrypts text using instructions given in Vault URL
func (v envVault) DecryptText(text string) (string, error) {
	passPhrase, ok := os.LookupEnv(v.envVar)
	if !ok {
		return "", fmt.Errorf("secret.envVault environment variable %q not set", v.envVar)
	}
	return DecryptText(text, passPhrase)
}

// String satisfies the stringer interface.
func (v envVault) String() string {
	return fmt.Sprintf("env://%s", v.envVar)
}

// EncryptText encrypts text using instructions given in Vault URL
func (v passPhraseVault) EncryptText(text string) (string, error) {
	return EncryptText(text, v.passPhrase)
}

// DecryptText decrypts text using instructions given in Vault URL
func (v passPhraseVault) DecryptText(text string) (string, error) {
	return DecryptText(text, v.passPhrase)
}

// String satisfies the stringer interface.
func (v passPhraseVault) String() string {
	return fmt.Sprintf("passwd://%s", v.passPhrase)
}