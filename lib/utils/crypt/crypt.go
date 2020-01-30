/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

// code heavily inspired by cryptopasta: https://raw.githubusercontent.com/gtank/cryptopasta/master/encrypt.go

package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Key ...
type Key [32]byte

// NewEncryptionKey generates a random 256-bit key for Encrypt() and
// Decrypt().
// If text is nil or empty, creates a random key. It panics if the source of randomness fails.
// If text is not nil and not empty, and the length of text is lower than 32, the key is completed
// with spaces.
// If text is not nil and not empty, and the length of text us greater than 32, the 32 first bytes
// are used as key.
func NewEncryptionKey(text []byte) (*Key, error) {
	key := Key{}
	nBytes := len(text)
	if len(text) == 0 {
		_, err := io.ReadFull(rand.Reader, key[:])
		if err != nil {
			return nil, fmt.Errorf("cannot read enough random bytes (you should consider to stop using this computer): %v", err)
		}
	} else {
		n := nBytes
		if nBytes > 32 {
			n = 32
		}
		for i := 0; i < n; i++ {
			key[i] = text[i]
		}
		for i := n; i < 32; i++ {
			key[i] = ' '
		}
	}
	return &key, nil
}

// Encrypt encrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Output takes the
// form nonce|ciphertext|tag where '|' indicates concatenation.
func Encrypt(plaintext []byte, key *Key) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Expects input
// form nonce|ciphertext|tag where '|' indicates concatenation.
func Decrypt(ciphertext []byte, key *Key) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("malformed ciphertext")
	}

	return gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
}
