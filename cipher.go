// Package aesgcm offers minimalistic AES-256-GCM authenticated
// encryption with constant-memory, goroutine-safe primitives.
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrKeyInvalid indicates that the encryption key is invalid or improperly formatted.
	ErrKeyInvalid = errors.New("aesgcm: invalid key")

	// ErrEncrypt indicates that the encryption process failed.
	ErrEncrypt = errors.New("aesgcm: encryption failed")

	// ErrDecrypt indicates that the decryption process failed.
	ErrDecrypt = errors.New("aesgcm: decryption failed")
)

// Cipher defines the interface for high-level AES-256-GCM encryption and decryption.
type Cipher interface {
	// Encrypt takes a plaintext string and returns the encrypted data as a byte slice.
	Encrypt(plain string) ([]byte, error)

	// Decrypt takes a byte slice produced by Encrypt and returns the original plaintext string.
	Decrypt(raw []byte) (string, error)
}

// gcmCipher is a concrete implementation of the Cipher interface using AES-256-GCM.
type gcmCipher struct {
	key  []byte
	aead cipher.AEAD
}

// Ensure gcmCipher implements the Cipher interface.
var _ Cipher = (*gcmCipher)(nil)

// New creates a new AES-256-GCM cipher using a base64-encoded 32-byte secret key.
// Returns an instance of Cipher or an error if the key is invalid.
func New(b64Key string) (Cipher, error) {
	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyInvalid, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: key must be 32 bytes, got %d", ErrKeyInvalid, len(key))
	}

	k := make([]byte, 32)
	copy(k, key)

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyInvalid, err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyInvalid, err)
	}

	return &gcmCipher{key: k, aead: aead}, nil
}

// Encrypt encrypts the given plaintext string using AES-256-GCM.
// Returns the resulting ciphertext, including a prepended nonce.
func (c *gcmCipher) Encrypt(plain string) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("%w: nonce: %v", ErrEncrypt, err)
	}

	// Seal appends the encrypted data to nonce and returns it.
	return c.aead.Seal(nonce, nonce, []byte(plain), nil), nil
}

// Decrypt decrypts the given byte slice using AES-256-GCM.
// The input must contain a nonce prepended to the actual ciphertext.
// Returns the original plaintext string or an error if decryption fails.
func (c *gcmCipher) Decrypt(raw []byte) (string, error) {
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return "", fmt.Errorf("%w: ciphertext too short", ErrDecrypt)
	}

	nonce, enc := raw[:ns], raw[ns:]
	plain, err := c.aead.Open(nil, nonce, enc, nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecrypt, err)
	}

	return string(plain), nil
}
