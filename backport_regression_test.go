/*-
 * Copyright 2026 AccelByte Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jose

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	josecipher "github.com/AccelByte/go-jose/cipher"
)

// Regression tests for malformed input that used to panic. Each case must
// return an error (or, where noted, succeed) without panicking.

var b64url = base64.RawURLEncoding.EncodeToString

func mustNotPanic(t *testing.T, name string, f func() error) error {
	t.Helper()
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("%s: panicked: %v", name, r)
			}
		}()
		err = f()
	}()
	return err
}

func regressionRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestRegressionJWSNullHeaderValues(t *testing.T) {
	key := regressionRSAKey(t)
	payload := b64url([]byte(`{"sub":"x"}`))
	sig := b64url(make([]byte, 256))

	headers := []string{
		`{"alg":null}`,
		`{"alg":null,"kid":"some-kid"}`,
		`{"alg":"RS256","kid":null}`,
		`{"alg":"RS256","jwk":null}`,
		`{"alg":"RS256","crit":null}`,
		`{"alg":"RS256","nonce":null}`,
	}
	for _, h := range headers {
		token := b64url([]byte(h)) + "." + payload + "." + sig
		err := mustNotPanic(t, h, func() error {
			obj, err := ParseSigned(token)
			if err != nil {
				return err
			}
			_, err = obj.Verify(&key.PublicKey)
			return err
		})
		if err == nil {
			t.Errorf("%s: expected an error", h)
		}
	}
}

func TestRegressionCompactSeparatorCount(t *testing.T) {
	cases := map[string]func(string) error{
		"JWS": func(s string) error { _, err := ParseSigned(s); return err },
		"JWE": func(s string) error { _, err := ParseEncrypted(s); return err },
	}
	for name, parse := range cases {
		for _, input := range []string{strings.Repeat(".", 100000), "a.b", "a.b.c.d.e.f"} {
			if err := mustNotPanic(t, name, func() error { return parse(input) }); err == nil {
				t.Errorf("%s: expected an error for %d separators", name, strings.Count(input, "."))
			}
		}
	}
}

func TestRegressionJWENullAlgEnc(t *testing.T) {
	key := regressionRSAKey(t)
	rest := "." + b64url(make([]byte, 256)) + "." + b64url(make([]byte, 16)) + "." + b64url(make([]byte, 32)) + "." + b64url(make([]byte, 16))

	for _, h := range []string{
		`{"alg":null,"enc":"A128CBC-HS256"}`,
		`{"alg":"RSA-OAEP","enc":null}`,
		`{"alg":null,"enc":"A128CBC+HS256"}`,
	} {
		token := b64url([]byte(h)) + rest
		err := mustNotPanic(t, h, func() error {
			obj, err := ParseEncrypted(token)
			if err != nil {
				return err
			}
			_, err = obj.Decrypt(key)
			return err
		})
		if err == nil {
			t.Errorf("%s: expected an error", h)
		}
	}
}

// legacyJWE builds a JWE using the pre-standard "A128CBC+HS256" content
// encryption the way Decrypt expects it, so the legacy path can be exercised
// with chosen IVs, ciphertexts and headers.
func legacyJWE(t *testing.T, pub *rsa.PublicKey, plaintext []byte, ivLen int) (encKey string, iv, ciphertext, tag []byte) {
	t.Helper()
	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}
	wrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, cek, []byte{})
	if err != nil {
		t.Fatal(err)
	}

	kdf := josecipher.NewConcatKDF(crypto.SHA256, append(append([]byte{}, cek...), 0, 0, 0, 128),
		[]byte(A128CBC_HS256_DEPRECATED), []byte{0, 0, 0, 0}, []byte{0, 0, 0, 0}, []byte("Encryption"), []byte{})
	contentKey := make([]byte, 16)
	if _, err := kdf.Read(contentKey); err != nil {
		t.Fatal(err)
	}

	block, err := aes.NewCipher(contentKey)
	if err != nil {
		t.Fatal(err)
	}
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := append(append([]byte{}, plaintext...), bytes.Repeat([]byte{byte(padding)}, padding)...)
	iv = make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	ciphertext = make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	if ivLen != aes.BlockSize {
		iv = make([]byte, ivLen)
	}
	return b64url(wrapped), iv, ciphertext, make([]byte, 32)
}

func TestRegressionLegacyCBCDecrypt(t *testing.T) {
	key := regressionRSAKey(t)
	header := b64url([]byte(`{"alg":"RSA-OAEP","enc":"A128CBC+HS256"}`))
	decrypt := func(token string) ([]byte, error) {
		obj, err := ParseEncrypted(token)
		if err != nil {
			return nil, err
		}
		return obj.Decrypt(key)
	}

	t.Run("well-formed token still decrypts", func(t *testing.T) {
		want := []byte(`{"sub":"x"}`)
		ek, iv, ct, tag := legacyJWE(t, &key.PublicKey, want, 16)
		got, err := decrypt(strings.Join([]string{header, ek, b64url(iv), b64url(ct), b64url(tag)}, "."))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("got %q, %v; want %q", got, err, want)
		}
	})

	for _, ivLen := range []int{0, 8, 15, 17, 32} {
		ivLen := ivLen
		t.Run(fmt.Sprintf("iv length %d", ivLen), func(t *testing.T) {
			ek, iv, ct, tag := legacyJWE(t, &key.PublicKey, []byte("hello"), ivLen)
			token := strings.Join([]string{header, ek, b64url(iv), b64url(ct), b64url(tag)}, ".")
			if err := mustNotPanic(t, "decrypt", func() error { _, err := decrypt(token); return err }); err == nil {
				t.Error("expected an error")
			}
		})
	}

	t.Run("empty ciphertext", func(t *testing.T) {
		ek, iv, _, tag := legacyJWE(t, &key.PublicKey, []byte("hello"), 16)
		token := strings.Join([]string{header, ek, b64url(iv), "", b64url(tag)}, ".")
		if err := mustNotPanic(t, "decrypt", func() error { _, err := decrypt(token); return err }); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("JSON serialization without protected header", func(t *testing.T) {
		ek, iv, ct, tag := legacyJWE(t, &key.PublicKey, []byte("hello"), 16)
		token := fmt.Sprintf(`{"unprotected":{"alg":"RSA-OAEP","enc":"A128CBC+HS256"},"encrypted_key":%q,"iv":%q,"ciphertext":%q,"tag":%q}`,
			ek, b64url(iv), b64url(ct), b64url(tag))
		mustNotPanic(t, "Decrypt", func() error { _, err := decrypt(token); return err })
		mustNotPanic(t, "DecryptMulti", func() error {
			obj, err := ParseEncrypted(token)
			if err != nil {
				return err
			}
			_, _, _, err = obj.DecryptMulti(key)
			return err
		})
	})
}

func TestRegressionStandardJWEBadIV(t *testing.T) {
	key := regressionRSAKey(t)
	for _, enc := range []ContentEncryption{A128GCM, A128CBC_HS256} {
		encrypter, err := NewEncrypter(enc, Recipient{Algorithm: RSA_OAEP, Key: &key.PublicKey}, nil)
		if err != nil {
			t.Fatal(err)
		}
		obj, err := encrypter.Encrypt([]byte("hello"))
		if err != nil {
			t.Fatal(err)
		}
		compact, err := obj.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(compact, ".")
		for _, ivLen := range []int{0, 8, 32} {
			parts[2] = b64url(make([]byte, ivLen))
			token := strings.Join(parts, ".")
			err := mustNotPanic(t, fmt.Sprintf("%s iv=%d", enc, ivLen), func() error {
				parsed, err := ParseEncrypted(token)
				if err != nil {
					return err
				}
				_, err = parsed.Decrypt(key)
				return err
			})
			if err == nil {
				t.Errorf("%s iv=%d: expected an error", enc, ivLen)
			}
		}
	}
}

func TestRegressionDecompressionLimit(t *testing.T) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	encrypter, err := NewEncrypter(A128GCM, Recipient{Algorithm: DIRECT, Key: key}, &EncrypterOptions{Compression: DEFLATE})
	if err != nil {
		t.Fatal(err)
	}

	small := bytes.Repeat([]byte("a"), 1000)
	large := make([]byte, 5*1000*1000) // highly compressible, far above the limit
	for name, tc := range map[string]struct {
		plaintext []byte
		wantErr   bool
	}{
		"within limit": {small, false},
		"over limit":   {large, true},
	} {
		obj, err := encrypter.Encrypt(tc.plaintext)
		if err != nil {
			t.Fatal(err)
		}
		serialized := obj.FullSerialize()

		parsed, err := ParseEncrypted(serialized)
		if err != nil {
			t.Fatal(err)
		}
		got, err := parsed.Decrypt(key)
		if tc.wantErr != (err != nil) {
			t.Errorf("%s: Decrypt err = %v, wantErr %v", name, err, tc.wantErr)
		}
		if !tc.wantErr && !bytes.Equal(got, tc.plaintext) {
			t.Errorf("%s: Decrypt returned wrong plaintext", name)
		}

		parsed, err = ParseEncrypted(serialized)
		if err != nil {
			t.Fatal(err)
		}
		_, _, got, err = parsed.DecryptMulti(key)
		if tc.wantErr != (err != nil) {
			t.Errorf("%s: DecryptMulti err = %v, wantErr %v", name, err, tc.wantErr)
		}
		if !tc.wantErr && !bytes.Equal(got, tc.plaintext) {
			t.Errorf("%s: DecryptMulti returned wrong plaintext", name)
		}
	}
}
