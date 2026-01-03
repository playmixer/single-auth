package authtools

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestDecrypt(t *testing.T) {
	type Case struct {
		Name  string
		Text  []byte
		Error error
	}

	cases := []Case{
		{
			Name:  "simple",
			Text:  []byte("test string"),
			Error: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			keys, err := GenerateRSAKeys()
			if err != nil {
				t.Error(err)
				return
			}
			pubBuff := bytes.NewBuffer([]byte{})
			_, err = pubBuff.WriteString("-----BEGIN PUBLIC KEY-----\n" + base64.StdEncoding.EncodeToString(keys.PublicKey) + "\n-----END PUBLIC KEY-----")
			if err != nil {
				t.Error(err)
				return
			}

			privBuff := bytes.NewBuffer([]byte{})
			_, err = privBuff.WriteString("-----BEGIN RSA PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString(keys.PrivateKey) + "\n-----END RSA PRIVATE KEY-----")
			if err != nil {
				t.Error(err)
				return
			}

			encryptText, err := EncryptDataRSA([]byte(c.Text), pubBuff.Bytes())
			if err != nil {
				t.Error(err, pubBuff.String())
				return
			}
			// fmt.Println(privBuff.String())
			decryptText, err := DecryptDataRSA(encryptText, privBuff.Bytes())
			if err != nil {
				t.Error(err, privBuff.String())
				return
			}
			if string(decryptText) != string(c.Text) {
				t.Error(err)
				return
			}
		})

	}

}

func TestDecryptBegin(t *testing.T) {
	type Case struct {
		Name  string
		Text  []byte
		Error error
	}

	cases := []Case{
		{
			Name:  "simple begin",
			Text:  []byte("test string"),
			Error: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			keys, err := GenerateRSAKeys()
			if err != nil {
				t.Error(err)
				return
			}
			pub, err := keys.PublicKeyBegin()
			if err != nil {
				t.Error(err)
				return
			}
			encryptText, err := EncryptDataRSA([]byte(c.Text), pub)
			if err != nil {
				t.Error(err)
				return
			}
			priv, err := keys.PrivateKeyBegin()
			if err != nil {
				t.Error(err, string(pub))
				return
			}
			decryptText, err := DecryptDataRSA(encryptText, priv)
			if err != nil {
				t.Error(err, string(priv))
				return
			}
			if string(decryptText) != string(c.Text) {
				t.Error(err)
			}
		})

	}

}
