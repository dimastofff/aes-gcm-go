// Package aesgcm provides AES-256-GCM authenticated encryption for whole
// messages using only the Go standard library. A Cipher can be shared by
// concurrent goroutines. Each operation allocates memory proportional to the
// message size; this package does not provide streaming encryption.
//
// Ciphertexts contain a 12-byte random nonce, followed by the encrypted message
// and a 16-byte authentication tag. Associated data, key rotation, and replay
// protection are not provided by this API.
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
// Instances returned by New can be used concurrently. Callers must not modify
// a ciphertext buffer while Decrypt is reading it.
type Cipher interface {
	// Encrypt accepts any string, including empty strings and arbitrary bytes.
	// The binary result is len(plain)+28 bytes long and includes the random nonce
	// and authentication tag. On failure it returns nil and wraps ErrEncrypt.
	// A key must not be used to encrypt more than 2^32 messages in total across
	// all instances and processes, to limit the risk of random nonce collisions.
	Encrypt(plain string) ([]byte, error)

	// Decrypt authenticates and decrypts a ciphertext produced by Encrypt without
	// modifying raw. On failure it returns an empty string and wraps ErrDecrypt.
	// Successful decryption does not establish freshness or an external context
	// such as the user or record to which the message belongs.
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
// The key must be generated from a cryptographically secure random source and
// encoded with base64.StdEncoding. Base64 is an encoding, not a password KDF.
// Invalid Base64 or a decoded length other than 32 bytes returns an error
// wrapping ErrKeyInvalid. Creating another Cipher does not reset a key's
// lifetime encryption limit.
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
