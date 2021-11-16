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

package json

import jsoniter "github.com/json-iterator/go"

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// Marshal is a wrapper around jsoniter Marshal
func Marshal(in interface{}) ([]byte, error) {
	return json.Marshal(in)
}

// Unmarshal is a wrapper around jsoniter Unmarshal
func Unmarshal(jsoned []byte, out interface{}) error {
	return json.Unmarshal(jsoned, out)
}

// MarshalIndent is a wrapper around jsoniter MarshalIndent
func MarshalIndent(in interface{}, prefix, indent string) ([]byte, error) {
	return json.MarshalIndent(in, prefix, indent)
}
