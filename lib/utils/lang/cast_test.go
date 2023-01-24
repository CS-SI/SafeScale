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

package lang

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type langTestInterface interface {
	Toto()
}
type langTest struct{}

func (lt *langTest) Toto() {}

func TestCast(t *testing.T) {
	// untype nil
	casted, err := Cast[langTestInterface](nil)
	require.NotNil(t, err)

	// typed nil
	var lt *langTest
	casted, err = Cast[langTestInterface](lt)
	require.NotNil(t, err)

	casted, err = Cast[langTestInterface](casted)
	require.NotNil(t, err)

	// successful cast
	lt = &langTest{}
	casted, err = Cast[langTestInterface](lt)
	require.Nil(t, err)
}

func BenchmarkLangCast(b *testing.B) {
	lt := new(langTest)
	for i := 0; i < b.N; i++ {
		_, _ = Cast[*langTest](lt)
	}
}

func BenchmarkNativeCast(b *testing.B) {
	lt := new(langTest)
	casted := langTestInterface(lt)
	for i := 0; i < b.N; i++ {
		// Reproduce the workflow of Cast to be fair
		if lt == nil {
			b.Fail()
		}

		_, ok := casted.(*langTest)
		if !ok {
			b.Fail()
		}
	}
}
