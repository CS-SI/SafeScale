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

package clustercomplexity

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnum_String(t *testing.T) {
	if len(stringMap) != len(enumMap) {
		t.Error("Not the same size")
	}

	for k, v := range stringMap {
		if r, ok := enumMap[v]; ok {
			if strings.Compare(strings.ToLower(k), strings.ToLower(r)) != 0 {
				t.Errorf("Value mismatch: %s, %s", k, r)
			}
		} else {
			t.Errorf("Key %s not found: ", k)
		}
	}
}

func Test_Parse(t *testing.T) {

	tests := []struct {
		key    string
		result Enum
		err    bool
	}{
		{
			key:    "Small",
			result: Small,
			err:    false,
		},
		{
			key:    "SMALL",
			result: Small,
			err:    false,
		},
		{
			key:    "small",
			result: Small,
			err:    false,
		},
		{
			key:    "Normal",
			result: Normal,
			err:    false,
		},
		{
			key:    "Large",
			result: Large,
			err:    false,
		},
		{
			key: "Tiny",
			err: true,
		},
		{
			key: "",
			err: true,
		},
	}
	for i := range tests {
		test := tests[i]
		result, err := Parse(test.key)
		require.EqualValues(t, result, test.result)
		require.EqualValues(t, err == nil, !test.err)
	}

}

func Test_String(t *testing.T) {

	tests := []struct {
		key    Enum
		result string
	}{
		{
			key:    Small,
			result: "Small",
		},
		{
			key:    Normal,
			result: "Normal",
		},
		{
			key:    Large,
			result: "Large",
		},
		{
			key:    Enum(42),
			result: "Enum(42)",
		},
	}
	for i := range tests {
		test := tests[i]
		result := test.key.String()
		require.EqualValues(t, test.result, result)
	}

}
