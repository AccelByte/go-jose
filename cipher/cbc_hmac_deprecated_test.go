/*-
 * Copyright 2014 Square Inc.
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

package josecipher

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"io"
	"testing"
)

func TestDeprecatedInvalidKeySize(t *testing.T) {
	for _, size := range []int{0, 16, 32, 47, 49, 64} {
		_, err := NewCBCHMACDeprecated(make([]byte, size), aes.NewCipher)
		if err == nil {
			t.Errorf("should not accept %d byte key", size)
		}
	}
}

func TestDeprecatedRoundtrip(t *testing.T) {
	key := make([]byte, 48)
	_, _ = io.ReadFull(rand.Reader, key)

	aead, err := NewCBCHMACDeprecated(key, aes.NewCipher)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, aead.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)
	aad := []byte("header.encryptedkey")

	for _, plaintext := range [][]byte{{}, []byte("plaintext"), bytes.Repeat([]byte{'a'}, 100)} {
		ciphertext := aead.Seal(nil, nonce, plaintext, aad)

		out, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			t.Fatal("error on open:", err)
		}

		if !bytes.Equal(out, plaintext) {
			t.Error("plaintext does not match output")
		}
	}
}

func TestDeprecatedTamperedInputs(t *testing.T) {
	key := make([]byte, 48)
	_, _ = io.ReadFull(rand.Reader, key)

	aead, err := NewCBCHMACDeprecated(key, aes.NewCipher)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, aead.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)
	aad := []byte("header.encryptedkey")
	ciphertext := aead.Seal(nil, nonce, []byte("amount=100;amount=100;amount=100"), aad)
	tagOffset := len(ciphertext) - 32

	flip := func(in []byte, i int) []byte {
		out := append([]byte{}, in...)
		out[i] ^= 1
		return out
	}

	zeroTag := append([]byte{}, ciphertext...)
	copy(zeroTag[tagOffset:], make([]byte, 32))

	cases := []struct {
		name                   string
		nonce, ciphertext, aad []byte
	}{
		// A flipped IV byte only changes the first plaintext block and keeps
		// the padding valid: exactly the tamper the missing tag check allowed.
		{"iv", flip(nonce, 0), ciphertext, aad},
		{"first block", nonce, flip(ciphertext, 0), aad},
		{"padding block", nonce, flip(ciphertext, tagOffset-17), aad},
		{"tag", nonce, flip(ciphertext, len(ciphertext)-1), aad},
		{"zero tag", nonce, zeroTag, aad},
		{"truncated tag", nonce, ciphertext[:tagOffset+16], aad},
		{"aad", nonce, ciphertext, flip(aad, 0)},
	}

	for _, c := range cases {
		if _, err := aead.Open(nil, c.nonce, c.ciphertext, c.aad); err == nil {
			t.Errorf("%s: tampered input was accepted", c.name)
		}
	}
}

func TestDeprecatedMalformedInputsWithValidTag(t *testing.T) {
	key := make([]byte, 48)
	_, _ = io.ReadFull(rand.Reader, key)

	aead, err := NewCBCHMACDeprecated(key, aes.NewCipher)
	if err != nil {
		panic(err)
	}
	ctx := aead.(*cbcAEADDeprecated)

	nonce := make([]byte, aead.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)
	aad := []byte("header.encryptedkey")
	ciphertext := aead.Seal(nil, nonce, []byte("plaintext"), aad)
	ciphertext = ciphertext[:len(ciphertext)-32]

	// Anyone holding the recipient's public key can choose the CMK and so
	// produce a valid tag; malformed input must still fail without a panic.
	cases := []struct {
		name              string
		nonce, ciphertext []byte
	}{
		{"short nonce", nonce[:8], ciphertext},
		{"long nonce", append(append([]byte{}, nonce...), 0), ciphertext},
		{"empty ciphertext", nonce, []byte{}},
	}

	for _, c := range cases {
		input := append(append([]byte{}, c.ciphertext...), ctx.computeAuthTag(aad, c.nonce, c.ciphertext)...)

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panic: %v", c.name, r)
				}
			}()

			if _, err := aead.Open(nil, c.nonce, input, aad); err == nil {
				t.Errorf("%s: malformed input was accepted", c.name)
			}
		}()
	}
}
