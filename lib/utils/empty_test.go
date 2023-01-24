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

package utils

import (
	"errors"
	"testing"

	_ "github.com/quasilyte/go-ruleguard/dsl"
	"github.com/stretchr/testify/require"
)

type NillableInterface interface {
	IsNil() bool
}
type Nillable struct {
	NillableInterface
	isnil bool
}

func (e Nillable) IsNil() bool {
	return e.isnil
}

func Test_IsEmpty(t *testing.T) {

	var emptyPtrInt error = nil

	tests := []struct {
		value  interface{}
		expect bool
	}{
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
			value:  uint8(0),
			expect: true,
		},
		{
			value:  uint8(42),
			expect: false,
		},
		{
			value:  uint(0),
			expect: true,
		},
		{
			value:  uint(42),
			expect: false,
		},
		{
			value:  int32(0),
			expect: true,
		},
		{
			value:  int32(42),
			expect: false,
		},
		{
			value:  int32(-42),
			expect: false,
		},
		{
			value:  float32(0.0),
			expect: true,
		},
		{
			value:  complex64(complex(0, 0)),
			expect: true,
		},
		{
			value:  complex64(complex(2, 7)),
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
			value:  make([]string, 0),
			expect: true,
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
		{
			value:  &Nillable{isnil: false},
			expect: true,
		},
	}

	for i := range tests {
		require.EqualValues(t, IsEmpty(tests[i].value), tests[i].expect)
	}

}
