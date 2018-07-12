package ezcrypt

import (
	"crypto/rsa"
	"crypto/rand"
	"crypto/sha256"
)

const (
	bitSize = 2048
)

// Random Number Generator
var rng = rand.Reader

type EZCrypt struct {
	RSAKey *rsa.PrivateKey
}

func (ezc *EZCrypt) GenerateKeys() error {
	var err error

	ezc.RSAKey, err = rsa.GenerateKey(rng, bitSize)
	if err != nil {
		return err
	}

	return nil
}

func (ezc *EZCrypt) Encrypt(data []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rng, &ezc.RSAKey.PublicKey, data, []byte{})
}

func (ezc *EZCrypt) Decrypt(data []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rng, ezc.RSAKey, data, []byte{})
}

func (ezc *EZCrypt) EncryptStr(data string) ([]byte, error) {
	return ezc.Encrypt([]byte(data))
}

func (ezc *EZCrypt) DecryptStr(data []byte) (string, error) {
	decryptedData, err := rsa.DecryptOAEP(sha256.New(), rng, ezc.RSAKey, data, []byte{})

	return string(decryptedData), err
}
