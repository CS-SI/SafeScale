//go:build !generics
// +build !generics

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

package strprocess

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Plural(t *testing.T) {

	res := Plural(0)
	require.EqualValues(t, res, "")

	res = Plural(1)
	require.EqualValues(t, res, "")

	res = Plural(2)
	require.EqualValues(t, res, "s")

	res = Plural(278954)
	require.EqualValues(t, res, "s")
}

func Test_Capitalize(t *testing.T) {

	tests := []struct {
		input  string
		output string
	}{
		{input: "a small story", output: "A small story"},
		{input: "A small Story", output: "A small Story"},
		{input: "it can't be", output: "It can't be"},
		{input: "We\nare numerous,      somewhere\t\na Legion                            .", output: "We are numerous, somewhere a Legion ."},
		{input: "'strings' could be quoted", output: "'strings' could be quoted"},
	}

	for i := range tests {
		require.EqualValues(t, Capitalize(tests[i].input), tests[i].output)
	}

}

func Test_FormatString(t *testing.T) {

	tests := []struct {
		input  []interface{}
		output string
	}{
		{input: []interface{}{}, output: ""},
		{input: []interface{}{nil, "oh", "my"}, output: ""},
		{input: []interface{}{""}, output: ""},
		{input: []interface{}{42}, output: ""},
		{input: []interface{}{"some"}, output: "some"},
		{input: []interface{}{false}, output: ""},
		{input: []interface{}{nil}, output: ""},
		{input: []interface{}{[]string{}}, output: ""},
		{input: []interface{}{"%s %s %s", "toto", "tata", "titi"}, output: "toto tata titi"},
	}
	for i := range tests {
		require.EqualValues(t, FormatStrings(tests[i].input...), tests[i].output)
	}
	require.EqualValues(t, FormatStrings(nil), "")

}
