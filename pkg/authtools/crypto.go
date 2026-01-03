package authtools

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

type RSAKeys struct {
	PublicKey  []byte
	PrivateKey []byte
}

// Функция для генерации пары ключей RSA
func GenerateRSAKeys() (*RSAKeys, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	pub := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	privDER := x509.MarshalPKCS1PrivateKey(priv)

	keys := &RSAKeys{
		PublicKey:  pub,
		PrivateKey: privDER,
	}

	return keys, nil
}

func (k *RSAKeys) PublicKeyBegin() ([]byte, error) {
	pubBuff := bytes.NewBuffer([]byte{})
	_, err := pubBuff.WriteString("-----BEGIN PUBLIC KEY-----\n" + base64.StdEncoding.EncodeToString(k.PublicKey) + "\n-----END PUBLIC KEY-----")
	if err != nil {
		return nil, fmt.Errorf("failed write public key to buffer: %w", err)
	}

	return pubBuff.Bytes(), nil
}

func (k *RSAKeys) PrivateKeyBegin() ([]byte, error) {
	privBuff := bytes.NewBuffer([]byte{})
	_, err := privBuff.WriteString("-----BEGIN RSA PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString(k.PrivateKey) + "\n-----END RSA PRIVATE KEY-----")
	if err != nil {
		return nil, fmt.Errorf("failed write private key to buffer: %w", err)
	}

	return privBuff.Bytes(), nil
}

// Функция для шифрования данных с использованием открытого ключа
func EncryptDataRSA(plaintext, publicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key")
	}
	pubInterface, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pubInterface, plaintext)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// Функция для расшифровки данных с использованием закрытого ключа
func DecryptDataRSA(ciphertext, privateKey []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
