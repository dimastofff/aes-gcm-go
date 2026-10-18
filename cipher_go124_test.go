//go:build go1.24
// +build go1.24

package aesgcm_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func TestInteropNewGCMWithRandomNonce(t *testing.T) {
	key := randomKey(t)
	c := newCipher(t, key)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	standard, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range plaintextCases() {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := c.Encrypt(tc.plain)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) != len(tc.plain)+28 {
				t.Fatalf("wire length = %d, want %d", len(raw), len(tc.plain)+28)
			}
			got, err := standard.Open(nil, nil, raw, nil)
			if err != nil || string(got) != tc.plain {
				t.Fatalf("standard Open failed: %v; plaintext matches: %t", err, string(got) == tc.plain)
			}

			fromStandard := standard.Seal(nil, nil, []byte(tc.plain), nil)
			before := append([]byte(nil), fromStandard...)
			plain, err := c.Decrypt(fromStandard)
			if err != nil || plain != tc.plain {
				t.Fatalf("Decrypt standard output failed: %v; plaintext matches: %t", err, plain == tc.plain)
			}
			if !bytes.Equal(fromStandard, before) {
				t.Fatal("Decrypt modified standard output")
			}
		})
	}
}
