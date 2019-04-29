package secret

import (
	"os"
	"errors"
	"net/url"
)

var ErrInvalidVaultScheme = errors.New("Invalid Value Schema in URL")
var ErrUnknownVaultScheme = errors.New("Don't know how to handle Vault Scheme")
var ErrEnvVarNotFound = errors.New("env Vault Scheme's variable not found")

type Vault struct {
	url *url.URL
}

func Parse(urlText string) (*Vault, error) {
	// parse url
	u, err := url.Parse(urlText)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		return nil, ErrInvalidVaultScheme
	}
	return &Vault{url: u}, nil
}

func (v Vault) EncryptText(text string) (string, error) {
	switch v.url.Scheme {
	case "env":
		passPhrase, ok := os.LookupEnv(v.url.Hostname())
		if !ok {
			return "", ErrEnvVarNotFound
		}
		return EncryptText(text, passPhrase)
	case "passwd":
		return EncryptText(text, v.url.Hostname())
	default:
		return "", ErrUnknownVaultScheme
	}
}

func (v Vault) DecryptText(text string) (string, error) {
	switch v.url.Scheme {
	case "env":
		passPhrase, ok := os.LookupEnv(v.url.Hostname())
		if !ok {
			return "", ErrEnvVarNotFound
		}
		return DecryptText(text, passPhrase)
	case "passwd":
		return DecryptText(text, v.url.Hostname())
	default:
		return "", ErrUnknownVaultScheme
	}
}
