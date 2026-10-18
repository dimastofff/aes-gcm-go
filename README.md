# aes-gcm-go

A small, goroutine-safe AES-256-GCM wrapper for Go, using only the standard library.
It encrypts complete strings and returns authenticated binary ciphertext with a
random nonce included.

## Installation

```sh
go get github.com/dimastofff/aes-gcm-go
```

The package remains source-compatible with Go 1.13 and later. For production, use
an up-to-date Go release covered by the [Go release support policy](https://go.dev/doc/devel/release#policy).
Compatibility with an old toolchain does not mean that toolchain receives security fixes.

## Usage

Generate a key from 32 cryptographically random bytes:

```sh
openssl rand -base64 32
```

Store the result in a secret manager or protected configuration and supply it to
the application as `AES_GCM_KEY`. Keep the key to decrypt previously stored data;
generating a new key on every startup would make that data unreadable. The value
must use padded standard base64 (`base64.StdEncoding`), not URL-safe base64. A
password encoded as base64 is not a suitable key; this package does not derive
keys from passwords.

For a local demonstration, save this program as `main.go` in a separate Go module,
install the package with the command above, then run
`AES_GCM_KEY="$(openssl rand -base64 32)" go run .`:

```go
package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"

	aesgcm "github.com/dimastofff/aes-gcm-go"
)

func main() {
	key, ok := os.LookupEnv("AES_GCM_KEY")
	if !ok || key == "" {
		log.Fatal("set AES_GCM_KEY to a base64-encoded 32-byte secret key")
	}

	c, err := aesgcm.New(key)
	if err != nil {
		log.Fatalf("initialize cipher: %v", err)
	}

	raw, err := c.Encrypt("Hello, AES-256-GCM!")
	if err != nil {
		log.Fatalf("encrypt: %v", err)
	}

	// Encode the binary result when storing or transmitting it as text.
	encoded := base64.StdEncoding.EncodeToString(raw)
	fmt.Println("Ciphertext (base64):", encoded)

	stored, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Fatalf("decode ciphertext: %v", err)
	}
	plain, err := c.Decrypt(stored)
	if err != nil {
		if errors.Is(err, aesgcm.ErrDecrypt) {
			log.Fatal("ciphertext could not be authenticated or decrypted")
		}
		log.Fatalf("decrypt: %v", err)
	}
	fmt.Println(plain)
}
```

## API and ciphertext format

```go
func New(b64Key string) (Cipher, error)

type Cipher interface {
	Encrypt(plain string) ([]byte, error)
	Decrypt(raw []byte) (string, error)
}
```

`New` accepts a base64-encoded key that decodes to exactly 32 bytes. A `Cipher` can
be shared across goroutines. Callers must not modify a ciphertext slice while
another goroutine is using it.

`Encrypt` accepts any Go string, including an empty string, NUL bytes, and invalid
UTF-8. `Decrypt` returns the original bytes as a string after successful
authentication and does not modify the input slice. On failure it returns an empty
string and an error; always check the error because empty plaintext is valid.

The v1 ciphertext format is:

```text
nonce (12 bytes) || encrypted plaintext (n bytes) || authentication tag (16 bytes)
```

The result is binary, with length `len(plain) + 28`; empty plaintext produces 28
bytes. There is no version header or key ID. Standard AES-256-GCM implementations
can interoperate using this layout, the same key, and empty additional
authenticated data. Base64 or hex is an application-level encoding around the
complete result, not part of the ciphertext format.

Errors wrap these sentinel values; use `errors.Is`, not error-message matching:

| Sentinel | Meaning |
| --- | --- |
| `ErrKeyInvalid` | The key cannot be decoded or does not contain 32 bytes. |
| `ErrEncrypt` | Encryption failed, for example while obtaining a random nonce. |
| `ErrDecrypt` | The input is too short, malformed, modified, or cannot be authenticated with the key. |

## Security and memory limits

- Each encryption generates a random 96-bit nonce. Use a key for **at most 2^32
  encryptions in total**, counting every cipher instance, process, host, and other
  application sharing that key. Rotate before reaching that limit; the package
  does not track usage. This follows the [Go GCM nonce guidance](https://pkg.go.dev/crypto/cipher#example-NewGCM-Encrypt).
- Key storage and rotation belong to the application. Retain old keys while their
  ciphertexts are needed, and choose the decryption key using a key ID in trusted
  external metadata. This format does not contain or authenticate that metadata.
- The API does not support additional authenticated data (AAD). It does not bind
  ciphertext to a user, record, or purpose, and provides no replay protection,
  ordering, expiration, or freshness check. The application must enforce these
  properties when needed.
- Operations process the entire message in memory and use **O(n) memory**. The
  string API can create plaintext copies during conversions; it is not streaming
  encryption. Set application-level input limits before processing large or
  untrusted messages.
- The package does not promise secure erasure of keys or plaintext from memory.
  Timing behavior depends on the Go implementation and hardware; there is no
  package-level guarantee of constant-time execution on every platform.

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities and the security support scope.

## Development

```sh
go test ./...
go test -run '^$' -bench=. -benchmem ./...
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for compatibility checks, race detection,
fuzzing, and contribution guidance.

## License

[MIT](LICENSE)
