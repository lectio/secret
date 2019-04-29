package secret

import (
	"fmt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"io"	
)

func CreateHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func EncryptText(text string, passPhrase string) (string, error) {
	encrypted, err := EncryptData([]byte(text), passPhrase)
	if err != nil {
		return "", err
	}
	encryptedHex := make([]byte, hex.EncodedLen(len(encrypted)))
	hex.Encode(encryptedHex, encrypted)
	return fmt.Sprintf("%s", encryptedHex), nil
}

func EncryptData(data []byte, passPhrase string) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(CreateHash(passPhrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func DecryptText(text string, passPhrase string) (string, error) {
	encrypted := make([]byte, hex.DecodedLen(len([]byte(text))))
	_, err := hex.Decode(encrypted, []byte(text))
	if err != nil {
		return "", err
	}	
	decrypted, err := DecryptData(encrypted, passPhrase)
	if err != nil {
		return "", nil
	}
	return fmt.Sprintf("%s", decrypted), nil
}

func DecryptData(data []byte, passPhrase string) ([]byte, error) {
	key := []byte(CreateHash(passPhrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
