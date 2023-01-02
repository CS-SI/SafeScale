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

package json

import (
	"fmt"

	jsoniter "github.com/json-iterator/go"
)

// Marshal is a wrapper around json Marshal
func Marshal(in interface{}) ([]byte, error) {
	res, err := jsoniter.ConfigCompatibleWithStandardLibrary.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("marshaling error: %w", err)
	}
	return res, nil
}

// Unmarshal is a wrapper around json Unmarshal
func Unmarshal(jsoned []byte, out interface{}) error {
	err := jsoniter.ConfigCompatibleWithStandardLibrary.Unmarshal(jsoned, out)
	if err != nil {
		return fmt.Errorf("unmarshaling error: %w", jsoniter.ConfigCompatibleWithStandardLibrary.Unmarshal(jsoned, out))
	}
	return nil
}

// MarshalIndent is a wrapper around json MarshalIndent
func MarshalIndent(in interface{}, prefix, indent string) ([]byte, error) {
	res, err := jsoniter.ConfigCompatibleWithStandardLibrary.MarshalIndent(in, prefix, indent)
	if err != nil {
		return nil, fmt.Errorf("marshaling with indentation error: %w", err)
	}
	return res, nil
}
