//go:build generics
// +build generics

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
	val := "a small story"
	res := Capitalize(val)
	require.EqualValues(t, res, "A small story")

	val = "A small Story"
	res = Capitalize(val)
	require.EqualValues(t, res, "A small Story")
}

func Test_FormatString(t *testing.T) {
	res := FormatStrings("%s %s %s", "toto", "tata", "titi")
	require.EqualValues(t, res, "toto tata titi")
}
