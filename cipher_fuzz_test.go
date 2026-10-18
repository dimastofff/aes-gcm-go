//go:build go1.18
// +build go1.18

package aesgcm_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"

	aesgcm "github.com/dimastofff/aes-gcm-go"
)

const fuzzMaxInput = 64 * 1024

func FuzzDecrypt(f *testing.F) {
	// A deterministic public test key makes the authenticated seeds reproducible.
	// Fixed ciphertexts are only decrypted, never generated with a reused nonce.
	key := decodeHex(f, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	c := newCipher(f, key)
	block, err := aes.NewCipher(key)
	if err != nil {
		f.Fatal(err)
	}
	standard, err := cipher.NewGCM(block)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{})
	f.Add([]byte("short"))
	f.Add(make([]byte, 12))
	f.Add(make([]byte, 28))
	// NIST no-AAD AES-256-GCM examples, also checked in TestDecryptNISTKnownAnswers.
	f.Add(decodeHex(f, "cafebabefacedbaddecaf888fd2caa16a5832e76aa132c1453eeda7e"))
	f.Add(decodeHex(f, "cafebabefacedbaddecaf888"+
		"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"+
		"8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"+
		"b094dac5d93471bdec1a502270e3cc6c"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > fuzzMaxInput {
			t.Skip()
		}
		before := append([]byte(nil), raw...)
		got, err := c.Decrypt(raw)
		if !bytes.Equal(raw, before) {
			t.Fatal("Decrypt modified its input")
		}
		if len(raw) < 12 {
			if !errors.Is(err, aesgcm.ErrDecrypt) || got != "" {
				t.Fatalf("short input: plaintext length %d, error %v", len(got), err)
			}
			return
		}
		want, standardErr := standard.Open(nil, raw[:12], raw[12:], nil)
		if standardErr != nil {
			if !errors.Is(err, aesgcm.ErrDecrypt) || got != "" {
				t.Fatalf("invalid input: plaintext length %d, error %v", len(got), err)
			}
		} else if err != nil || got != string(want) {
			t.Fatalf("valid input: error %v; plaintext matches: %t", err, got == string(want))
		}
	})
}

func FuzzRoundTrip(f *testing.F) {
	// This test key is public; Encrypt still generates a fresh random nonce.
	c := newCipher(f, make([]byte, 32))
	for _, plain := range []string{"", "hello", "Прывітанне, 世界 👋", "\x00\xff\xfe\x80"} {
		f.Add(plain)
	}
	f.Fuzz(func(t *testing.T, plain string) {
		if len(plain) > fuzzMaxInput {
			t.Skip()
		}
		raw, err := c.Encrypt(plain)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != len(plain)+28 {
			t.Fatalf("wire length = %d, want %d", len(raw), len(plain)+28)
		}
		before := append([]byte(nil), raw...)
		got, err := c.Decrypt(raw)
		if err != nil || got != plain {
			t.Fatalf("round trip failed: %v; plaintext matches: %t", err, got == plain)
		}
		if !bytes.Equal(raw, before) {
			t.Fatal("Decrypt modified its input")
		}
		raw[len(raw)-1] ^= 1
		assertDecryptFailure(t, c, raw)
	})
}
