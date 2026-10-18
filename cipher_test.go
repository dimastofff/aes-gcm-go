package aesgcm_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	aesgcm "github.com/dimastofff/aes-gcm-go"
)

func randomKey(tb testing.TB) []byte {
	tb.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	return key
}

func newCipher(tb testing.TB, key []byte) aesgcm.Cipher {
	tb.Helper()
	c, err := aesgcm.New(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		tb.Fatalf("New: %v", err)
	}
	if c == nil {
		tb.Fatal("New returned a nil cipher without an error")
	}
	return c
}

func TestNewRejectsInvalidKeys(t *testing.T) {
	for _, encoded := range []string{"not-base64-%%%", "_w==", strings.Repeat("A", 43)} {
		t.Run("encoding/"+encoded, func(t *testing.T) {
			c, err := aesgcm.New(encoded)
			if !errors.Is(err, aesgcm.ErrKeyInvalid) {
				t.Fatalf("New error = %v, want ErrKeyInvalid", err)
			}
			if c != nil {
				t.Fatal("New returned a cipher for an invalid key")
			}
		})
	}
	for _, size := range []int{0, 1, 15, 16, 24, 31, 33, 64} {
		t.Run(fmt.Sprintf("length/%d", size), func(t *testing.T) {
			c, err := aesgcm.New(base64.StdEncoding.EncodeToString(make([]byte, size)))
			if !errors.Is(err, aesgcm.ErrKeyInvalid) {
				t.Fatalf("New error = %v, want ErrKeyInvalid", err)
			}
			if c != nil {
				t.Fatal("New returned a cipher for an invalid key length")
			}
		})
	}
}

func plaintextCases() []struct{ name, plain string } {
	return []struct{ name, plain string }{
		{"empty", ""},
		{"ascii", "hello world"},
		{"unicode", "Прывітанне, 世界 👋"},
		{"binary", "\x00\xff\xfe\x80\x01\x00"},
		{"15_bytes", strings.Repeat("a", 15)},
		{"16_bytes", strings.Repeat("b", 16)},
		{"17_bytes", strings.Repeat("c", 17)},
		{"1_KiB", strings.Repeat("d", 1024)},
		{"64_KiB", strings.Repeat("e", 64*1024)},
	}
}

func TestRoundTripAndWireLength(t *testing.T) {
	key := randomKey(t)
	encryptor := newCipher(t, key)
	decryptor := newCipher(t, key)
	for _, tc := range plaintextCases() {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := encryptor.Encrypt(tc.plain)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			// The public wire format is a 12-byte nonce, ciphertext, then a 16-byte tag.
			if len(raw) != len(tc.plain)+28 {
				t.Fatalf("wire length = %d, want %d", len(raw), len(tc.plain)+28)
			}
			before := append([]byte(nil), raw...)
			got, err := decryptor.Decrypt(raw)
			if err != nil {
				t.Fatalf("Decrypt with another instance sharing the key: %v", err)
			}
			if got != tc.plain {
				t.Fatal("round trip changed plaintext bytes")
			}
			if !bytes.Equal(raw, before) {
				t.Fatal("Decrypt modified its input")
			}
		})
	}
}

func assertDecryptFailure(t *testing.T, c aesgcm.Cipher, raw []byte) {
	t.Helper()
	before := append([]byte(nil), raw...)
	plain, err := c.Decrypt(raw)
	if !errors.Is(err, aesgcm.ErrDecrypt) {
		t.Errorf("Decrypt error = %v, want ErrDecrypt", err)
	}
	if plain != "" {
		t.Error("Decrypt returned plaintext on failure")
	}
	if !bytes.Equal(raw, before) {
		t.Error("Decrypt modified its input on failure")
	}
}

func TestEncryptOwnsOutput(t *testing.T) {
	c := newCipher(t, randomKey(t))
	plain := strings.Repeat("original plaintext\x00\xff", 32)
	beforePlain := append([]byte(nil), plain...)
	first, err := c.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(plain), beforePlain) {
		t.Fatal("Encrypt modified its plaintext string")
	}
	beforeFirst := append([]byte(nil), first...)
	const secondPlain = "a shorter, independent message"
	second, err := c.Encrypt(secondPlain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, beforeFirst) {
		t.Fatal("a later Encrypt modified an earlier result")
	}
	for i := range first {
		first[i] ^= 0xff
	}
	got, err := c.Decrypt(second)
	if err != nil || got != secondPlain {
		t.Fatalf("modifying one result affected another: %v; plaintext matches: %t", err, got == secondPlain)
	}
}

func TestDecryptOwnsPlaintext(t *testing.T) {
	c := newCipher(t, randomKey(t))
	const want = "retained plaintext\x00\xff"
	raw, err := c.Encrypt(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Decrypt(raw)
	if err != nil || got != want {
		t.Fatalf("Decrypt: %v; plaintext matches: %t", err, got == want)
	}
	for i := range raw {
		raw[i] ^= 0xff
	}
	later, err := c.Encrypt("later plaintext")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decrypt(later); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("ciphertext mutation or later operations changed retained plaintext")
	}
}

func TestDecryptRejectsMalformedCiphertexts(t *testing.T) {
	c := newCipher(t, randomKey(t))
	raw, err := c.Encrypt("a representative message spanning several AES blocks\x00\xff")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("nil", func(t *testing.T) {
		assertDecryptFailure(t, c, nil)
	})
	// Includes empty input, an incomplete nonce, a nonce alone, and partial tags.
	for n := 0; n < len(raw); n++ {
		t.Run(fmt.Sprintf("truncated/%d", n), func(t *testing.T) {
			assertDecryptFailure(t, c, append([]byte(nil), raw[:n]...))
		})
	}
	for i := range raw {
		region := "ciphertext"
		if i < 12 {
			region = "nonce"
		} else if i >= len(raw)-16 {
			region = "tag"
		}
		t.Run(fmt.Sprintf("tampered/%s/%d", region, i), func(t *testing.T) {
			modified := append([]byte(nil), raw...)
			modified[i] ^= 1
			assertDecryptFailure(t, c, modified)
		})
	}
	t.Run("appended_byte", func(t *testing.T) {
		assertDecryptFailure(t, c, append(append([]byte(nil), raw...), 0))
	})
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	key := randomKey(t)
	c := newCipher(t, key)
	key[0] ^= 1 // Ensure the second key differs, without relying on chance.
	wrong := newCipher(t, key)
	raw, err := c.Encrypt("private message")
	if err != nil {
		t.Fatal(err)
	}
	assertDecryptFailure(t, wrong, raw)
}

func TestEncryptUsesFreshNonces(t *testing.T) {
	c := newCipher(t, randomKey(t))
	seen := make(map[string]bool)
	for i := 0; i < 32; i++ {
		raw, err := c.Encrypt("same plaintext")
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) < 12 {
			t.Fatalf("wire length = %d, cannot contain a nonce", len(raw))
		}
		nonce := string(raw[:12])
		if seen[nonce] {
			t.Fatal("Encrypt reused a nonce")
		}
		seen[nonce] = true
	}
}

func TestDecryptNISTKnownAnswers(t *testing.T) {
	// NIST, GCM-AES256 examples #1 and #2, no AAD, 128-bit tags (pp. 21-23):
	// https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/aes_gcm.pdf
	// These literal fixtures are only decrypted; no nonce is reused for encryption.
	key := decodeHex(t, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	c := newCipher(t, key)
	for _, tc := range []struct{ name, plain, wire string }{
		{
			name: "empty",
			wire: "cafebabefacedbaddecaf888fd2caa16a5832e76aa132c1453eeda7e",
		},
		{
			name: "four_blocks",
			plain: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" +
				"1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
			wire: "cafebabefacedbaddecaf888" +
				"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa" +
				"8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad" +
				"b094dac5d93471bdec1a502270e3cc6c",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := decodeHex(t, tc.wire)
			before := append([]byte(nil), raw...)
			got, err := c.Decrypt(raw)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(decodeHex(t, tc.plain)) {
				t.Fatalf("plaintext = %x, want %s", got, tc.plain)
			}
			if !bytes.Equal(raw, before) {
				t.Fatal("Decrypt modified the known-answer input")
			}
		})
	}
}

func decodeHex(tb testing.TB, s string) []byte {
	tb.Helper()
	out, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatalf("invalid test fixture: %v", err)
	}
	return out
}

func TestInteropNewGCM(t *testing.T) {
	key := randomKey(t)
	c := newCipher(t, key)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	standard, err := cipher.NewGCM(block)
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
			got, err := standard.Open(nil, raw[:12], raw[12:], nil)
			if err != nil || string(got) != tc.plain {
				t.Fatalf("standard Open failed: %v; plaintext matches: %t", err, string(got) == tc.plain)
			}

			// Use a new nonce for the reverse direction, not the nonce above.
			nonce := make([]byte, standard.NonceSize())
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				t.Fatal(err)
			}
			fromStandard := standard.Seal(nonce, nonce, []byte(tc.plain), nil)
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

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("test entropy failure")
}

func TestEncryptEntropyFailure(t *testing.T) {
	c := newCipher(t, randomKey(t))
	// rand.Reader is process-wide. This test and its subtests must remain
	// sequential, with no t.Parallel and no background users of rand.Reader.
	original := rand.Reader
	defer func() { rand.Reader = original }()
	for _, tc := range []struct {
		name   string
		reader io.Reader
	}{
		{"immediate", failingReader{}},
		{"partial_nonce", io.MultiReader(bytes.NewReader(make([]byte, 6)), failingReader{})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rand.Reader = tc.reader
			raw, err := c.Encrypt("must not be emitted without a complete nonce")
			if !errors.Is(err, aesgcm.ErrEncrypt) {
				t.Errorf("Encrypt error = %v, want ErrEncrypt", err)
			}
			if raw != nil {
				t.Error("Encrypt returned non-nil output on entropy failure")
			}
		})
	}
}

func TestConcurrentCipher(t *testing.T) {
	c := newCipher(t, randomKey(t))
	const workers, operations = 32, 100
	failures := make(chan error, workers)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for operation := 0; operation < operations; operation++ {
				plain := fmt.Sprintf("worker %d operation %d\x00\xff", worker, operation)
				raw, err := c.Encrypt(plain)
				if err != nil {
					failures <- fmt.Errorf("worker %d Encrypt: %v", worker, err)
					return
				}
				got, err := c.Decrypt(raw)
				if err != nil || got != plain {
					failures <- fmt.Errorf("worker %d Decrypt: %v; plaintext matches: %t", worker, err, got == plain)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}

// Keep benchmark results observable, including allocations for returned values.
var (
	benchmarkCipher     aesgcm.Cipher
	benchmarkCiphertext []byte
	benchmarkPlaintext  string
)

func BenchmarkNew(b *testing.B) {
	key := base64.StdEncoding.EncodeToString(randomKey(b))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		benchmarkCipher, err = aesgcm.New(key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	for _, size := range []int{0, 64, 1024, 64 * 1024} {
		b.Run(fmt.Sprintf("bytes_%d", size), func(b *testing.B) {
			c := newCipher(b, randomKey(b))
			plain := strings.Repeat("x", size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var err error
				benchmarkCiphertext, err = c.Encrypt(plain)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for _, size := range []int{0, 64, 1024, 64 * 1024} {
		b.Run(fmt.Sprintf("bytes_%d", size), func(b *testing.B) {
			c := newCipher(b, randomKey(b))
			raw, err := c.Encrypt(strings.Repeat("x", size))
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var err error
				benchmarkPlaintext, err = c.Decrypt(raw)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
