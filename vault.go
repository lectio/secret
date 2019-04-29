package secret

import (
	"fmt"
	"os"
	"errors"
	"net/url"
)

// Vault defines a URL with instructions for how to encrypt/decrypt data
type Vault struct {
	url *url.URL
}

// Parse the given text into a Vault instance
func Parse(urlText string) (*Vault, error) {
	// parse url
	u, err := url.Parse(urlText)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		return nil, errors.New("url scheme is empty")
	}
	return &Vault{url: u}, nil
}

// EncryptText encrypts text using instructions given in Vault URL
func (v Vault) EncryptText(text string) (string, error) {
	switch v.url.Scheme {
	case "env":
		passPhrase, ok := os.LookupEnv(v.url.Hostname())
		if !ok {
			return "", fmt.Errorf("%q environment variable %q not set", v.url.String(), v.url.Hostname())
		}
		return EncryptText(text, passPhrase)
	case "passwd":
		return EncryptText(text, v.url.Hostname())
	default:
		return "", fmt.Errorf("Unable to handle unknown scheme %q in %q", v.url.Scheme, v.url.String())
	}
}

// DecryptText decrypts text using instructions given in Vault URL
func (v Vault) DecryptText(text string) (string, error) {
	switch v.url.Scheme {
	case "env":
		passPhrase, ok := os.LookupEnv(v.url.Hostname())
		if !ok {
			return "", fmt.Errorf("%q environment variable %q not set", v.url.String(), v.url.Hostname())
		}
		return DecryptText(text, passPhrase)
	case "passwd":
		return DecryptText(text, v.url.Hostname())
	default:
		return "", fmt.Errorf("Unable to handle unknown scheme %q in %q", v.url.Scheme, v.url.String())
	}
}

// String satisfies the stringer interface.
func (v Vault) String() string {
	return v.String()
}