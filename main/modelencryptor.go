package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"io"
)

type ModelEncyptor struct {
	Key string
}

// create key from string
func (c ModelEncyptor) CreateKey() []byte {
	hasher := sha512.New()
	hasher.Write([]byte(c.Key))
	return hasher.Sum(nil)[:32]
}

// encrypt string using AES256 and return base64 encoded string
func (c ModelEncyptor) Encrypt(data string) (string, error) {
	plaintext := []byte(data)

	block, err := aes.NewCipher(c.CreateKey())
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return "ENCRYPTED:" + base64.URLEncoding.EncodeToString(ciphertext), nil
}

// decrypt base64 encoded string using AES256 and return string
func (c ModelEncyptor) Decrypt(data string) (string, error) {
	if len(data) < 10 || data[:10] != "ENCRYPTED:" {
		return "", errors.New("invalid encrypted string")
	}

	ciphertext, _ := base64.URLEncoding.DecodeString(data[10:])

	block, err := aes.NewCipher(c.CreateKey())
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}
