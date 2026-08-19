package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

func DeriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
}

func Encrypt(plaintext []byte, password string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := DeriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	result := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

func Decrypt(ciphertext []byte, password string) ([]byte, error) {
	if len(ciphertext) < 16+12 {
		return nil, errors.New("ciphertext too short")
	}

	salt := ciphertext[:16]
	nonce := ciphertext[16 : 16+12]
	data := ciphertext[16+12:]

	key := DeriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func EncryptWithKey(plaintext []byte, hexKey string) ([]byte, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	if len(keyBytes) != 32 {
		return nil, errors.New("invalid key length")
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	result := make([]byte, 0, len(nonce)+len(ciphertext))
	result = append(result, nonce...)
	result = append(result, ciphertext...)
	return result, nil
}

func DecryptWithKey(ciphertext []byte, hexKey string) ([]byte, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	if len(keyBytes) != 32 {
		return nil, errors.New("invalid key length")
	}
	if len(ciphertext) < 12 {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:12]
	data := ciphertext[12:]

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aesgcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
