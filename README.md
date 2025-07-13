# aes-gcm-go

Minimalistic, zero-dependencies, goroutine-safe, constant-memory AES-256-GCM encryption for Go.

## Features

- 🔐 **AES-256-GCM**: Strong, authenticated encryption
- 🧵 **Goroutine-safe**: Safe to use across concurrent goroutines
- 📦 **Zero-dependencies**: Uses only the Go standard library
- 🔁 **Constant memory**: No allocations per operation beyond nonce and ciphertext

## Installation

```bash
go get github.com/dimastofff/aes-gcm-go
```

## Usage

### Recommended way for key generation
```bash
openssl rand -base64 32
```

### Encrypt and Decrypt

```go
package main

import (
	"fmt"
	"log"

	"github.com/dimastofff/aes-gcm-go"
)

func main() {
	b64Key := "AeDG1FxUDTw9A3fAXgxW3L8+tJ8f4W/oEPSNz373W4g="

	c, err := aesgcm.New(b64Key)
	if err != nil {
		log.Fatalf("Failed to initialize cipher: %v", err)
	}

	// Encrypt
	plaintext := "Hello, AES-256-GCM!"
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("Encrypted: %x\n", ciphertext)

	// Decrypt
	decrypted, err := c.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	fmt.Printf("Decrypted: %s\n", decrypted)
}
```

## API

### `New(b64Key string) (Cipher, error)`

Initializes a new cipher using a base64-encoded 32-byte key. Returns a `Cipher` implementation or an error if the key is invalid.

### `Cipher` Interface

Defines two primary methods:
- `Encrypt(string) ([]byte, error)` for encrypting plaintext
- `Decrypt([]byte) (string, error)` for decrypting ciphertext

### Errors

- `ErrKeyInvalid`: Returned if the provided key is not 32 bytes or is improperly formatted
- `ErrEncrypt`: Indicates a failure during encryption
- `ErrDecrypt`: Indicates a failure during decryption

## How to run tests

```bash
go test -v .
```

## How to run benchmarks

```bash
go test -bench=. ./
```

## License

[MIT](LICENSE)
