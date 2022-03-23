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

package temporal

import (
	"reflect"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/require"
)

func Test_NewTimings(t *testing.T) {
	result := NewTimings()
	require.EqualValues(t, reflect.TypeOf(result).String(), "*temporal.MutableTimings")
}

func Test_NewTimingsToml(t *testing.T) {
	result := NewTimings()
	ct, err := result.ToToml()
	require.Nil(t, err)
	t.Logf(ct)
}

func Test_CarryAfterYou(t *testing.T) {
	type Foo struct {
		Thing MutableTimings
	}

	deepest := &Foo{
		Thing: *NewTimings(),
	}

	barr, err := toml.Marshal(deepest)
	require.Nil(t, err)

	t.Logf(string(barr))
}
