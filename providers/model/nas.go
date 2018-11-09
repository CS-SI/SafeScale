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

package model

// Nas represents a nas definition
type Nas struct {
	ID         string      `json:"id,omitempty"`
	Name       string      `json:"name,omitempty"`
	Host       string      `json:"host,omitempty"`
	Path       string      `json:"path,omitempty"`
	IsServer   bool        `json:"is_server,omitempty"`
	Extensions *Extensions `json:"extensions,omitempty"`
}

// NewNas ...
func NewNas() *Nas {
	return &Nas{
		Extensions: NewExtensions(),
	}
}

// Serialize serializes Host instance into bytes (output json code)
func (n *Nas) Serialize() ([]byte, error) {
	return SerializeToJSON(n)
}

// Deserialize reads json code and reinstanciates an Host
func (n *Nas) Deserialize(buf []byte) error {
	return DeserializeFromJSON(buf, n)
}
