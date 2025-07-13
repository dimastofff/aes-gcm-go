package aesgcm

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

type testHelper interface {
	Fatalf(format string, args ...interface{})
}

// generateValidBase64Key returns a base64-encoded 32-byte random key.
func generateValidBase64Key(tb testHelper) string {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		tb.Fatalf("Failed to generate key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestNew_ValidKey(t *testing.T) {
	key := generateValidBase64Key(t)
	c, err := New(key)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if c == nil {
		t.Fatal("Expected non-nil cipher")
	}
}

func TestNew_InvalidBase64Key(t *testing.T) {
	_, err := New("not-base64-%%%")
	if err == nil || !strings.Contains(err.Error(), "invalid key") {
		t.Errorf("Expected ErrKeyInvalid, got: %v", err)
	}
}

func TestNew_InvalidKeyLength(t *testing.T) {
	shortKey := make([]byte, 16)
	keyStr := base64.StdEncoding.EncodeToString(shortKey)
	_, err := New(keyStr)
	if err == nil || !strings.Contains(err.Error(), "key must be 32 bytes") {
		t.Errorf("Expected invalid key length error, got: %v", err)
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := generateValidBase64Key(t)
	c, err := New(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	plain := "hello world"
	ciphertext, err := c.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("Expected non-empty ciphertext")
	}

	decrypted, err := c.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if decrypted != plain {
		t.Errorf("Expected %q, got %q", plain, decrypted)
	}
}

func TestEncryptDecrypt_EmptyString(t *testing.T) {
	key := generateValidBase64Key(t)
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := c.Encrypt("")
	if err != nil {
		t.Fatalf("Encrypt empty string failed: %v", err)
	}

	decrypted, err := c.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt empty ciphertext failed: %v", err)
	}
	if decrypted != "" {
		t.Errorf("Expected empty string, got %q", decrypted)
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key := generateValidBase64Key(t)
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := c.Encrypt("sensitive data")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err = c.Decrypt(ciphertext)
	if err == nil || !strings.Contains(err.Error(), "decryption failed") {
		t.Errorf("Expected decryption failure, got: %v", err)
	}
}

func TestDecrypt_TruncatedCiphertext(t *testing.T) {
	key := generateValidBase64Key(t)
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	short := []byte("123")
	_, err = c.Decrypt(short)
	if err == nil || !strings.Contains(err.Error(), "decryption failed") {
		t.Errorf("Expected decryption failure due to short input, got: %v", err)
	}
}

func TestDecrypt_NilCiphertext(t *testing.T) {
	key := generateValidBase64Key(t)
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.Decrypt(nil)
	if err == nil || !strings.Contains(err.Error(), "decryption failed") {
		t.Errorf("Expected decryption error for nil input, got: %v", err)
	}
}

func TestEncrypt_ProducesDifferentCiphertexts(t *testing.T) {
	key := generateValidBase64Key(t)
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	plain := "non-unique"
	ct1, err := c.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := c.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if string(ct1) == string(ct2) {
		t.Error("Expected different ciphertexts for same plaintext due to random nonce")
	}
}

func TestDecrypt_ModifiedNonce(t *testing.T) {
	key := generateValidBase64Key(t)
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	plain := "altered nonce"
	ciphertext, err := c.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext[0] ^= 0x01

	_, err = c.Decrypt(ciphertext)
	if err == nil || !strings.Contains(err.Error(), "decryption failed") {
		t.Errorf("Expected error for modified nonce, got: %v", err)
	}
}

func TestNew_KeyReuse(t *testing.T) {
	key := generateValidBase64Key(t)
	c1, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	plain := "shared key message"
	ciphertext, err := c1.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := c2.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if decrypted != plain {
		t.Errorf("Expected %q, got %q", plain, decrypted)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	key := generateValidBase64Key(b)
	c, _ := New(key)
	msg := strings.Repeat("x", 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.Encrypt(msg)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key := generateValidBase64Key(b)
	c, _ := New(key)
	msg := strings.Repeat("x", 1024)
	ct, _ := c.Encrypt(msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.Decrypt(ct)
	}
}
