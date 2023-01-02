/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

	key, err := NewEncryptionKey([]byte("")) // nolint
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if len(key) != 32 {
		t.Error("Invalid cyphered key length")
		t.Fail()
	}

	key, err = NewEncryptionKey([]byte("this is one of")) // nolint
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if len(key) != 32 {
		t.Error("Invalid cyphered key length")
		t.Fail()
	}

	key, err = NewEncryptionKey([]byte("this is a really too long one to be valid")) // nolint
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if len(key) != 32 {
		t.Error("Invalid cyphered key length")
		t.Fail()
	}

}

func Test_Encrypt(t *testing.T) {

	var key *Key
	var source = []byte("This is my entering data")
	_, err := Encrypt(source, key)
	if err == nil {
		t.Error("Can't cypher nil Key")
		t.Fail()
	}

	key, err = NewEncryptionKey([]byte("0123456789"))
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

func Test_Decrypt(t *testing.T) {

	var key *Key
	var source = []byte("")

	_, err := Decrypt(source, key)
	if err == nil {
		t.Error("Can't uncypher nil Key")
		t.Fail()
	}

}
