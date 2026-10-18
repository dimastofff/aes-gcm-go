package aesgcm_test

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	aesgcm "github.com/dimastofff/aes-gcm-go"
)

func Example() {
	// Generate a random 256-bit key and keep it secret. A password is not a key.
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	c, err := aesgcm.New(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		panic(err)
	}

	encrypted, err := c.Encrypt("hello, world")
	if err != nil {
		panic(err)
	}
	decrypted, err := c.Decrypt(encrypted)
	if err != nil {
		panic(err)
	}
	fmt.Println(decrypted)
	// Output: hello, world
}
