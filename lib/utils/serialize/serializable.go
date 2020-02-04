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

package serialize

import (
	"encoding/json"
)

//go:generate mockgen -destination=../mocks/mock_serializable.go -package=mocks github.com/CS-SI/SafeScale/lib/utils/serialize Serializable

// Serializable is the interface allowing the conversion of satisfying struct to []byte (Serialize())
// and reverse operation (Unserialize())
type Serializable interface {
	Serialize() ([]byte, error)
	Deserialize([]byte) error
}

// ToJSON serializes data into JSON
func ToJSON(data interface{}) ([]byte, error) {
	jsoned, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return jsoned, nil
}

// FromJSON reads json code and restores data
func FromJSON(buf []byte, data interface{}) error {
	err := json.Unmarshal(buf, data)
	return err
}
