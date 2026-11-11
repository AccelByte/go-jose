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

package jose

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

// Test vector for the pre-standard A128CBC+HS256 (JWE draft-08) produced by an
// independent implementation following Nimbus JOSE LegacyConcatKDF and
// AESCBC.encryptWithConcatKDF: RSA-OAEP key wrap, zip=DEF, 32-byte HMAC-SHA256
// tag over "<header>.<encrypted key>.<iv>.<ciphertext>".
const deprecatedTestKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxYN2D1XO/5dHDwYg4S6/gjnwXTpQOp9tof1rweYt5es1P3tf
uvK77mhujVOACgv0hML60E2GdHEzM4hVuiHTl37FbPQD7+d9k/ZRKgOqYMmbPpHB
m1xuFhhqheDFeMGqqcuutCwMJ7M6v3b89y+cRLGe2HIr57+AIDT5nomGXXI3F3vw
pFr62CRqqmqHmMAwcaJ9xV1p3cyrpQQ0sEJLfXeRbvebQxAoRniVvUarDQ8zBDI+
rtNDCoZwGl0rM6ZUf62rdtIISicHQrZK0X6g+Tql+2GEh+47bbuxNHWCo4C0G1ju
GorHwlvUPCxGdkySYUH0k66vYyd16XlljaMAcwIDAQABAoIBAAKBhfxw0sUEZtbm
dYFV5gEheg68wCrWPf5ZqEXYBUoO/2h0SMUm8kJ2mbx6TDwUZcBPdv4wlZ2hmAw1
1Ryc9EHOTnPw7qHbFolLjUEStdUviaQ0FjhB5nWqTqOvM+Ix1tf7qRZJHshcKkkm
mdQLCxkGBeVqIWt5zwbZlTcxOH60AA917UItrvYmAJwNi1b8eMskGkNOcFqztUon
qv889K5VD1VTXs7F0xY2p5oXkBBAUy2WuAxxUaJLauzBQrTE+/u0QfaenDI8/C8R
nHnsnbs5xKdFqW0C2H9/U+Q9ATVoOzeCHd8o2sRoqr37shv/nJd8uHtw3pWPvhoH
q2AEmD0CgYEA7CIwkAQCm+91CGkd7M7evYeSLmiwt/DaKULSxokJQ6aKWyhvyHbf
dsOdbBsSh3hb6LAXiIcLbZCT3+xuWDPZM9vkhDUgZhk1ls5hVRCBzmHCmvBhTQWi
G4QMiu7efYZS4TLf7J4pmIt9B3useNzZzFfaem9jwySuTAZ9TwRG6k8CgYEA1iF6
kbNMKp8dEAjpChOs3qL53VJMbxKknnFKyItMJNhkTz+xzsBL1HGKZtNCaEt1vJPd
3Q1YDQNmGoRjrPeVelP4qzhH7zULK8f70MwyWGm/0Nd9AAmuBt6AFBY1cG+1Z9jS
eyqRizBFbi/4TwCE6Rqz/nqyq3UFWfxNFsloUp0CgYEAruRzy3bs58nniJ8yht6B
oybyYmUv3k0JiF3x9xIwRmbnOrUsdfF1eWVRB2zVwHiouiMSixBaqn/Wxpc68yET
0pEfI7yljnlFc7jP5k0fl1hY5qD7sCxn8LFRCOX67EW8xQcFSx+p9035AL3c9He+
6NZ4/w3ZegOFBNIZpZipXYkCgYAShpb6IA8I6Pc0ufCfhJBCOstvUH14Zp6Dbr3P
l+2ginAzQwl5H73vxVr6BnEKYOzwwcJCK7NgfNjKloWhI1J1YOp0tcvTcD1lLkol
CGWarJuB0ALqi+vYgEuIcVtyPNfvAh1Dtq0c47I+FDxhaWQWXs8Px0HJ/7fUzzVE
MWyrKQKBgEKED23RGxlEHJYY2llyNX7PuteQo5Xp/ZA7MrtBj4RzF3caIa8H0MhH
qAOpqUL1jcOdt8GDT9oGKQyGctuo06XFNWL2ZboaO75VuUIPUlmmm0ySq37TD4PZ
CYxAQINVcFRhoyZSyRNeq95WsBBOWwaNYAlLeH7aTGA4IX20JghB
-----END RSA PRIVATE KEY-----`

const deprecatedTestToken = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMrSFMyNTYiLCJ6aXAiOiJERUYifQ.UnPafcYRG23Z2yJQlcHQYigevn-UobJ2cnr11RHRC3dQQBL8CcNO_anVyhNCYh5CfKt9oBgFqZ8A_JIiss1xLXissImGxNly-Pmny8zw83GkC4tEg4pYzcvBIpxK55gRqe6UzzPbwv7Py6iDHpfM-u3Oa13CKUcMzACRhUne6PC8ozN5-FyhmtnsduxFU7I96h-KLtyJnje0TH7Ej5yMerwR5PcO4scyEr3BxPE1n8Fc50QXQq4G67YPq9Lt3HGuCrjBG3d7ca1FY6piYgzohFCQq5EQ8qqr5ZlCoODP13HCrbVRT86qWw1B0Xtex3AA5Cba5qxHBKw1XzCY0IZExQ.NpeUJGgxumpsPPEnxSLZaQ.qeiqHgHLgEITb_rY7AzKslIsRGGGsCNr8yHAdLgJSg8olRKIooR0Hr-K1XQ7_IfXjweDlaaF-OmeXfI08e_hWMxsZUJa6rViHIKoqVmMqFw.70Tt5RnSoq6mxbY8qw-Svc7X4_UiPmK--QYWVOvy_Ic"

const deprecatedTestPayload = `{"xid":"2535400000000000","x5u":"https://xsts.auth.xboxlive.com/xsts/certificates/test"}`

func parseDeprecatedTestKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}

	return rsaKey, nil
}

func TestDeprecatedDecrypt(t *testing.T) {
	key, err := parseDeprecatedTestKey([]byte(deprecatedTestKey))
	if err != nil {
		t.Fatal(err)
	}

	obj, err := ParseEncrypted(deprecatedTestToken)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := obj.Decrypt(key)
	if err != nil {
		t.Fatal("error on decrypt:", err)
	}

	if string(plaintext) != deprecatedTestPayload {
		t.Errorf("plaintext does not match payload: %q", plaintext)
	}

	index, _, plaintext, err := obj.DecryptMulti(key)
	if err != nil {
		t.Fatal("error on DecryptMulti:", err)
	}

	if index != 0 || string(plaintext) != deprecatedTestPayload {
		t.Errorf("DecryptMulti returned index %d, plaintext %q", index, plaintext)
	}
}

func TestDeprecatedDecryptRejectsTampering(t *testing.T) {
	key, err := parseDeprecatedTestKey([]byte(deprecatedTestKey))
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(deprecatedTestToken, ".")

	flip := func(segment string, i int) string {
		raw, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil {
			t.Fatal(err)
		}
		if i < 0 {
			i += len(raw)
		}
		raw[i] ^= 1
		return base64.RawURLEncoding.EncodeToString(raw)
	}

	replace := func(index int, segment string) string {
		out := append([]string{}, parts...)
		out[index] = segment
		return strings.Join(out, ".")
	}

	// Same bytes, but the first half of the tag moved into the ciphertext segment
	rawCiphertext, _ := base64.RawURLEncoding.DecodeString(parts[3])
	rawTag, _ := base64.RawURLEncoding.DecodeString(parts[4])
	splitTag := strings.Join([]string{
		parts[0], parts[1], parts[2],
		base64.RawURLEncoding.EncodeToString(append(rawCiphertext, rawTag[:16]...)),
		base64.RawURLEncoding.EncodeToString(rawTag[16:]),
	}, ".")

	cases := map[string]string{
		// Keeps the padding valid; decrypted without error before the tag check.
		"iv bit flip":         replace(2, flip(parts[2], 0)),
		"ciphertext bit flip": replace(3, flip(parts[3], -17)),
		"tag bit flip":        replace(4, flip(parts[4], -1)),
		"zero tag":            replace(4, base64.RawURLEncoding.EncodeToString(make([]byte, 32))),
		"tag split":           splitTag,
		"header without zip": replace(0, base64.RawURLEncoding.EncodeToString(
			[]byte(`{"alg":"RSA-OAEP","enc":"A128CBC+HS256"}`))),
	}

	for name, token := range cases {
		obj, err := ParseEncrypted(token)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if _, err := obj.Decrypt(key); err == nil {
			t.Errorf("%s: tampered token was accepted by Decrypt", name)
		}

		if _, _, _, err := obj.DecryptMulti(key); err == nil {
			t.Errorf("%s: tampered token was accepted by DecryptMulti", name)
		}
	}
}

func TestDeprecatedRejectsAddedAad(t *testing.T) {
	key, err := parseDeprecatedTestKey([]byte(deprecatedTestKey))
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(deprecatedTestToken, ".")
	full := fmt.Sprintf(
		`{"protected":"%s","encrypted_key":"%s","iv":"%s","ciphertext":"%s","tag":"%s","aad":"YWFk"}`,
		parts[0], parts[1], parts[2], parts[3], parts[4])

	obj, err := ParseEncrypted(full)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := obj.Decrypt(key); err == nil {
		t.Error("full serialization with aad was accepted")
	}
}

func TestDeprecatedEncryptUnsupported(t *testing.T) {
	enc, err := NewEncrypter(A128CBC_HS256_DEPRECATED, Recipient{Algorithm: RSA_OAEP, Key: &rsaTestKey.PublicKey}, nil)
	if err != nil {
		return
	}

	if _, err := enc.Encrypt([]byte("plaintext")); err == nil {
		t.Error("encrypting with A128CBC+HS256 should not be supported")
	}
}

// TestDeprecatedRealXSTSToken checks a token minted by Xbox Live, set through
// XSTS_TOKEN (the JWE, with or without the "XBL3.0 x=...;" prefix) and
// XSTS_RP_KEY (path to the relying party private key in PEM). The token must
// use "enc":"A128CBC+HS256"; standard A128CBC-HS256 tokens never reach the
// deprecated code, so they cannot validate it.
func TestDeprecatedRealXSTSToken(t *testing.T) {
	token, keyPath := os.Getenv("XSTS_TOKEN"), os.Getenv("XSTS_RP_KEY")
	if token == "" || keyPath == "" {
		t.Skip("XSTS_TOKEN and XSTS_RP_KEY not set")
	}

	if i := strings.LastIndex(token, ";"); i >= 0 {
		token = token[i+1:]
	}

	keyData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	key, err := parseDeprecatedTestKey(keyData)
	if err != nil {
		t.Fatal(err)
	}

	obj, err := ParseEncrypted(token)
	if err != nil {
		t.Fatal(err)
	}

	if enc := obj.mergedHeaders(nil).getEncryption(); enc != A128CBC_HS256_DEPRECATED {
		t.Fatalf("token uses enc %q, want %q", enc, A128CBC_HS256_DEPRECATED)
	}

	if _, err := obj.Decrypt(key); err != nil {
		t.Fatal("real XSTS token failed to decrypt:", err)
	}

	if _, _, _, err := obj.DecryptMulti(key); err != nil {
		t.Fatal("real XSTS token failed to decrypt with DecryptMulti:", err)
	}

	// The tag check must be what rejects a modified token.
	parts := strings.Split(token, ".")
	rawTag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatal(err)
	}
	rawTag[len(rawTag)-1] ^= 1
	parts[4] = base64.RawURLEncoding.EncodeToString(rawTag)

	tampered, err := ParseEncrypted(strings.Join(parts, "."))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tampered.Decrypt(key); err == nil {
		t.Error("real XSTS token with a modified tag was accepted")
	}
}
