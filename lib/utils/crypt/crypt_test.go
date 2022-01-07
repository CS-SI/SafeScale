/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package crypt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_NewEncryptionKey(t *testing.T) {

	chars := []byte("0123456789")
	key, err := NewEncryptionKey(chars)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	match := false
	for a := range key {
		match = false
		for b := range chars {
			if key[a] == chars[b] || key[a] == 32 {
				match = true
				break
			}
		}
		if !match {
			break
		}
	}

	if !match {
		t.Error("Key is not compsed by given chars")
		t.Fail()
	}

}

func Test_Encrypt(t *testing.T) {

	var source []byte = []byte("This is my entering data")

	key, err := NewEncryptionKey([]byte("0123456789"))
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	encoded, err := Encrypt(source, key)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	decoded, err := Decrypt(encoded, key)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	require.EqualValues(t, source, decoded)

}
