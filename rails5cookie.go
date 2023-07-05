// Copyright 2023 Zane van Iperen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package railscookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1" // #nosec - G505 - Used by Rails 5
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

var (
	errMissingDelimiter          = errors.New("missing '--' delimiter")
	errInvalidBase64             = errors.New("invalid base64 payload")
	errMissingEncryptedDelimiter = errors.New("missing '--' delimiter in encrypted message")
	errDecodingIV                = errors.New("invalid base64 IV payload")
	errDecodingEncryptedData     = errors.New("error decoding encrypted message")
	errInvalidConfiguration      = errors.New("invalid configuration")
)

type rails5CookieDecoder struct {
	signingKey          []byte
	encryptedSigningKey []byte
	encryptionKey       []byte
	rand                io.Reader
}

func NewRails5CookieCoder(cfg Configuration) (CookieCoder, error) {
	if cfg.SignedCookieSalt == "" {
		return nil, errInvalidConfiguration
	}

	if cfg.EncryptedSignedCookieSalt == "" {
		return nil, errInvalidConfiguration
	}

	if cfg.EncryptedCookieSalt == "" {
		return nil, errInvalidConfiguration
	}

	if cfg.RNG == nil {
		return nil, errInvalidConfiguration
	}

	rc := &rails5CookieDecoder{
		signingKey:          pbkdf2.Key([]byte(cfg.SecretKeyBase), []byte(cfg.SignedCookieSalt), 1000, 64, sha1.New),
		encryptedSigningKey: pbkdf2.Key([]byte(cfg.SecretKeyBase), []byte(cfg.EncryptedSignedCookieSalt), 1000, 64, sha1.New),
		encryptionKey:       pbkdf2.Key([]byte(cfg.SecretKeyBase), []byte(cfg.EncryptedCookieSalt), 1000, 64, sha1.New)[0:32],
		rand:                cfg.RNG,
	}

	return rc, nil
}

func verifyAndDecode(secret []byte, s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "%3D", "=")

	parts := strings.SplitN(s, "--", 2)
	if len(parts) != 2 {
		return nil, errMissingDelimiter
	}

	encodedMessage, digest := parts[0], parts[1]

	hash := hmac.New(sha1.New, secret)
	_, _ = hash.Write([]byte(encodedMessage))
	calcDigest := hex.EncodeToString(hash.Sum(nil))

	if digest != calcDigest {
		return nil, fmt.Errorf("invalid digest, expected %v, got %v", digest, calcDigest)
	}

	decodedMessage, err := base64.StdEncoding.DecodeString(encodedMessage)
	if err != nil {
		return nil, errInvalidBase64
	}

	return decodedMessage, nil
}

func encode(secret []byte, data []byte) string {
	msg := base64.StdEncoding.EncodeToString(data)

	hash := hmac.New(sha1.New, secret)
	_, _ = hash.Write([]byte(msg))
	digest := hex.EncodeToString(hash.Sum(nil))

	return strings.ReplaceAll(msg+"--"+digest, "=", "%3D")
}

func (rc *rails5CookieDecoder) Decode(s string) ([]byte, error) {
	return verifyAndDecode(rc.signingKey, s)
}

func (rc *rails5CookieDecoder) Encode(data []byte) string {
	return encode(rc.signingKey, data)
}

func pad(data []byte, blockSize int) []byte {
	neededPadding := blockSize - (len(data) % blockSize)
	if neededPadding == 0 {
		return data
	}

	newData := make([]byte, len(data)+neededPadding)
	for i := 0; i < len(data); i++ {
		newData[i] = data[i]
	}

	for i := 0; i < neededPadding-1; i++ {
		newData[len(data)+i] = 0xFF
	}

	newData[len(data)+neededPadding-1] = byte(neededPadding)
	return newData
}

func (rc *rails5CookieDecoder) Decrypt(s string) ([]byte, error) {
	encryptedData, err := verifyAndDecode(rc.encryptedSigningKey, s)
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(string(encryptedData), "--", 2)
	if len(parts) != 2 {
		return nil, errMissingEncryptedDelimiter
	}

	payload, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errDecodingEncryptedData
	}

	iv, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errDecodingIV
	}

	block, err := aes.NewCipher(rc.encryptionKey)
	if err != nil {
		return nil, err
	}

	dec := cipher.NewCBCDecrypter(block, iv)
	dec.CryptBlocks(payload, payload)

	padding := int(payload[len(payload)-1])
	return payload[0 : len(payload)-padding], nil
}

func (rc *rails5CookieDecoder) Encrypt(data []byte) (string, error) {
	block, err := aes.NewCipher(rc.encryptionKey)
	if err != nil {
		return "", err
	}

	iv := [16]byte{}
	if _, err := rc.rand.Read(iv[:]); err != nil {
		return "", err
	}

	data = pad(data, block.BlockSize())

	dec := cipher.NewCBCEncrypter(block, iv[:])
	dec.CryptBlocks(data, data)

	payload := base64.StdEncoding.EncodeToString(data) + "--" + base64.StdEncoding.EncodeToString(iv[:])
	return encode(rc.encryptedSigningKey, []byte(payload)), nil
}

func DecodeString(cc CookieCoder, s string) (string, error) {
	b, err := cc.Decode(s)
	return string(b), err
}

func EncodeString(cc CookieCoder, s string) string {
	return cc.Encode([]byte(s))
}

func DecryptString(cc CookieCoder, s string) (string, error) {
	b, err := cc.Decrypt(s)
	return string(b), err
}

func EncryptString(cc CookieCoder, s string) (string, error) {
	return cc.Encrypt([]byte(s))
}
