package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"regexp"
	"strings"

	rand2 "golang.org/x/exp/rand"
)

// Функция для генерации пары ключей RSA
func GenerateRSAKeys() (map[string][]byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	pub := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	privDER := x509.MarshalPKCS1PrivateKey(priv)

	keys := map[string][]byte{
		"public_key":  pub,
		"private_key": privDER,
	}

	return keys, nil
}

// Функция для шифрования данных с использованием открытого ключа
func EncryptDataRSA(plaintext, publicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
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

func RandomString(n uint) string {
	var letterRunes = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
	b := make([]byte, n)
	for i := range b {
		b[i] = letterRunes[rand2.Intn(len(letterRunes))]
	}
	return string(b)
}
func FilterAlphaNumeric(inputString string) string {
	// Регулярное выражение для поиска всех символов, кроме цифр и латиницы
	reg := regexp.MustCompile(`[^a-zA-Z0-9_]`)

	// Применение регулярного выражения для удаления ненужных символов
	filteredString := reg.ReplaceAllString(inputString, "")

	// Приведение строки к нижнему регистру для унификации
	filteredString = strings.ToLower(filteredString)

	return filteredString
}
