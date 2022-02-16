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

package empty

import (
	"errors"
	"testing"

	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/stretchr/testify/require"
)

type IsEmptyTest struct {
	value  interface{}
	expect bool
}

func Test_IsEmpty(t *testing.T) {

	var emptyPtrInt error = nil

	tests := []IsEmptyTest{
		{
			value:  nil,
			expect: true,
		},
		{
			value:  true,
			expect: false,
		},
		{
			value:  false,
			expect: true,
		},
		{
			value:  0,
			expect: true,
		},
		{
			value:  42,
			expect: false,
		},
		{
			value:  -42,
			expect: false,
		},
		{
			value:  0.0,
			expect: true,
		},
		{
			value:  42.0,
			expect: false,
		},
		{
			value:  errors.New("any"),
			expect: false,
		},
		{
			value:  emptyPtrInt,
			expect: true,
		},
		{
			value:  []string{},
			expect: true,
		},
		{
			value:  []string{"one"},
			expect: false,
		},
		{
			value:  "one",
			expect: false,
		},
		{
			value:  struct{}{},
			expect: true,
		},
		{
			value: struct {
				any string
			}{
				any: "one",
			},
			expect: false,
		},
	}

	for i := range tests {
		require.EqualValues(t, utils.IsEmpty(tests[i].value), tests[i].expect)
	}

}
