package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"log"
)

func GenerateKey(pass, salt []byte) (key []byte) {
	key = pbkdf2.Key(pass, salt, 4096, 32, sha512.New)

	return key
}

func EncryptData(plaintext, key []byte) (ciphertext []byte, err error) {
	if ciphertext, err = encrypt(plaintext, key); err != nil {
		log.Fatal(err)
	}

	return ciphertext, err
}

func DecryptData(ciphertext, key []byte) (plaintext []byte, err error) {
	if plaintext, err = decrypt(ciphertext, key); err != nil {
		log.Fatal(err)
	}

	return plaintext, err
}

func encrypt(text, key []byte) (ciphertext []byte, err error) {
	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}

	ciphertext = make([]byte, aes.BlockSize+len(string(text)))

	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], text)

	return ciphertext, err
}

func decrypt(ciphertext, key []byte) (plaintext []byte, err error) {
	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return
	}

	if len(ciphertext) < aes.BlockSize {
		err = errors.New("ciphertext too short")
		return
	}

	iv := ciphertext[:aes.BlockSize]

	ciphertext = ciphertext[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)

	plaintext = ciphertext

	return plaintext, err
}
