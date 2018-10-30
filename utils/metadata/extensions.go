/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

package metadata

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

// Extensions ...
type Extensions struct {
	encoded []byte
	decoded map[int]interface{}
	changed bool
}

// NewExtensions creates a new instance of Extensions
func NewExtensions(raw []byte) *Extensions {
	return &Extensions{
		encoded: raw,
		decoded: map[int]interface{}{},
	}
}

func (ex *Extensions) decode() error {
	r := bytes.NewReader(ex.encoded)
	err := gob.NewDecoder(r).Decode(&ex.decoded)
	if err != nil {
		return err
	}
	return nil
}

func (ex *Extensions) encode() error {
	var buffer bytes.Buffer
	err := gob.NewEncoder(&buffer).Encode(ex.decoded)
	if err != nil {
		return err
	}
	ex.encoded = buffer.Bytes()
	return nil
}

// Get gets the content of an extension
// When the extension is not found, returns (nil,nil)
func (ex *Extensions) Get(index int) (interface{}, error) {
	if len(ex.encoded) > 0 && len(ex.decoded) == 0 {
		err := ex.decode()
		if err != nil {
			return nil, err
		}
	}
	if anon, ok := ex.decoded[index]; ok {
		return anon, nil
	}
	return nil, fmt.Errorf("extension not found")
}

// Set sets the value of an extension of the host
func (ex *Extensions) Set(index int, data interface{}) error {
	if len(ex.encoded) > 0 && len(ex.decoded) == 0 {
		err := ex.decode()
		if err != nil {
			return err
		}
	}
	ex.changed = true
	ex.decoded[index] = data
	return nil
}

// ToBytes ...
func (ex *Extensions) ToBytes() ([]byte, error) {
	if ex.changed {
		err := ex.encode()
		if err != nil {
			return []byte{}, err
		}
		ex.changed = false
	}
	return ex.encoded, nil
}
