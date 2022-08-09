/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
package clusterflavor

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
			key:    "k8s",
			result: K8S,
			err:    false,
		},
		{
			key:    "K8s",
			result: K8S,
			err:    false,
		},
		{
			key:    "K8S",
			result: K8S,
			err:    false,
		},
		{
			key:    "boh",
			result: BOH,
			err:    false,
		},
		{
			key:    "gke",
			result: Enum(0),
			err:    true,
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
			key:    K8S,
			result: "K8S",
		},
		{
			key:    BOH,
			result: "BOH",
		},
	}
	for i := range tests {
		test := tests[i]
		result := test.key.String()
		require.EqualValues(t, test.result, result)
	}

	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Error("Expect panic")
				t.Fail()
			}
		}()
		_ = Enum(42).String()
	}()

}
