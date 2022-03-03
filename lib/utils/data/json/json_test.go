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

package json

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Marshal(t *testing.T) {

	data := map[string]string{
		"a": "1",
		"b": "2",
		"c": "3",
	}
	encoded, err := Marshal(data)
	var decoded map[string]string
	err = Unmarshal(encoded, &decoded)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	require.EqualValues(t, data, decoded)

	formatted, err := MarshalIndent(data, "", "    ")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	expected := "{\n    \"a\": \"1\",\n    \"b\": \"2\",\n    \"c\": \"3\"\n}"
	require.EqualValues(t, string(formatted), expected)

}
