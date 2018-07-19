package ezcrypt

import (
	"crypto/rsa"
	"crypto/rand"
	"math/big"
	"encoding/asn1"
	"gksgsrvr/app/helpers"
	"encoding/binary"
	"bytes"
	"gksgsrvr/config/logging"
)

var logger = logging.Log

const (
	bitSize = 2048
)

// max number of bytes can be encrypted
var maxSizeCanEncrypt = 245

// Random Number Generator
var rng = rand.Reader

// public key struct
type PKCS1PublicKey struct {
	N *big.Int
	E int
}

type EZCrypt struct {
	RSAKey					*rsa.PrivateKey
	ClientRSAPublicKey		*rsa.PublicKey
}

func (ezc *EZCrypt) GenerateKeys() error {
	var err error

	ezc.RSAKey, err = rsa.GenerateKey(rng, bitSize)
	if err != nil {
		return err
	}

	return nil
}

func (ezc *EZCrypt) Encrypt(data []byte, key *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rng, key, data)
}

func (ezc *EZCrypt) Decrypt(data []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rng, ezc.RSAKey, data)
}

//func (ezc *EZCrypt) EncryptStr(data string) (string, error) {
//	encryptedData, err := ezc.Encrypt([]byte(data))

//	return string(encryptedData), err
//}

func (ezc *EZCrypt) DecryptStr(data string) (string, error) {
	decryptedData, err := ezc.Decrypt([]byte(data))

	return string(decryptedData), err
}

// DecodedPublicKey decodes public key to asn1 encoding
func (ezc *EZCrypt) AsnEncodedPublicKey() ([]byte) {
	derBytes, _ := asn1.Marshal(PKCS1PublicKey {
		N: ezc.RSAKey.PublicKey.N,
		E: ezc.RSAKey.PublicKey.E,
	})

	return derBytes
}

// EncryptData encryptes data
func (ezc *EZCrypt) EncryptData(data []byte) (string, error) {
	var length = len(data)
	var encryptedString string
	var err error

	for i := 0; i < len(data); i += maxSizeCanEncrypt {
		var encryptedData []byte

		if length - i < maxSizeCanEncrypt {
			maxSizeCanEncrypt = length - i
		}

		toEncrypt := data[i : i + maxSizeCanEncrypt]
		encryptedData, _ = ezc.Encrypt(toEncrypt, ezc.ClientRSAPublicKey)
		h  := helpers.BytesToHexEncode(encryptedData)

		if encryptedString == "" {
			encryptedString += string(h)
		} else {
			encryptedString = encryptedString + ","+ string(h)
		}
	}

	return encryptedString, err
}

// ParseNGetDecryptedString parses data and returns decrypted string
func (ezc *EZCrypt) ParseNGetDecryptedString(data string) string {
   parts := helpers.SplitEncryptedHex(data)
   var decrypted string
   for i := 0; i < len(parts); i++ {
       bytes, _ := helpers.HexToBytesDecode(parts[i])

       decryptedData, err := ezc.DecryptStr(string(bytes))
       if err != nil {
           logger.Info("Error while decrypting ", err)
           break
       }
       decrypted += decryptedData
   }

   logger.Info("decrypted data in bytes ", decrypted)
   return decrypted
}

// GetKeyFromHexEncryptedClientKey get rsa public key from client encrypted hex encoded string                                                                                                          
func (ezc *EZCrypt) GenerateKeyFromModulusNExponent (modulus []byte, exponent []byte) *rsa.PublicKey {
    n := big.NewInt(0)
    n.SetBytes(modulus)

    var eBytes []byte
    if len(exponent) < 8 {
        eBytes = make([]byte, 8 - len(exponent), 8)
        eBytes = append(eBytes, exponent...)
    } else {
        eBytes = exponent
    }

    eReader := bytes.NewReader(eBytes)

    var e uint64
    err := binary.Read(eReader, binary.BigEndian, &e)
    if err != nil {
        logger.Info("error converting exponent to uint64")
        return nil
    }

	ezc.ClientRSAPublicKey = &rsa.PublicKey{N: n, E: int(e)}

    return ezc.ClientRSAPublicKey
}
