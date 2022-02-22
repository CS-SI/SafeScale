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

package data

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type NullableInterface interface {
	IsNull() bool
}
type Nullable struct {
	NullableInterface
	isnull bool
}

func (e Nullable) IsNull() bool {
	return e.isnull
}

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

func Test_hasFieldWithNameAndIsNil(t *testing.T) {

	result := hasFieldWithNameAndIsNil(nil, "field")
	require.EqualValues(t, result, false)

	result = hasFieldWithNameAndIsNil(struct {
		a string
		b uint
		c bool
	}{}, "d")
	require.EqualValues(t, result, false)

	result = hasFieldWithNameAndIsNil(struct {
		a string
		b uint
		c bool
		d float64
	}{}, "d")
	require.EqualValues(t, result, false)

	result = hasFieldWithNameAndIsNil(struct {
		a string
		b uint
		c bool
		d *float64
	}{
		d: nil,
	}, "d")
	require.EqualValues(t, result, true)

}

func Test_IsNil(t *testing.T) {

	// @TODO duplicate (lib/utils & lib/utils/valid ) Is_NiL, one is useless

	var a_null Nullable
	var a_nil Nillable
	//var p_null *Nullable = nil
	//var p_nil *Nillable = nil

	require.EqualValues(t, IsNil(nil), true)
	require.EqualValues(t, IsNil(a_null), false)
	//require.EqualValues(t, IsNil(p_null), true)
	require.EqualValues(t, IsNil(Nullable{isnull: true}), true)
	require.EqualValues(t, IsNil(&Nullable{isnull: true}), true)
	require.EqualValues(t, IsNil(Nullable{isnull: false}), false)
	require.EqualValues(t, IsNil(&Nullable{isnull: false}), false)
	require.EqualValues(t, IsNil(a_nil), false)
	//require.EqualValues(t, IsNil(p_nil), true)
	require.EqualValues(t, IsNil(Nillable{isnil: true}), true)
	require.EqualValues(t, IsNil(&Nillable{isnil: true}), true)
	require.EqualValues(t, IsNil(Nillable{isnil: false}), false)
	require.EqualValues(t, IsNil(&Nillable{isnil: false}), false)
	require.EqualValues(t, IsNil("test"), false)
	require.EqualValues(t, IsNil(struct{}{}), false)
	require.EqualValues(t, IsNil(&struct {
		Price  float64
		Symbol string
		Rating uint
	}{
		Price:  5.55,
		Symbol: "€",
		Rating: 4,
	}), false)

}

func Test_IsNull(t *testing.T) {

	// @TODO duplicate (lib/utils & lib/utils/valid ) Is_NiL, one is useless

	var a_null Nullable
	var a_nil Nillable
	//var p_null *Nullable = nil
	//var p_nil *Nillable = nil

	require.EqualValues(t, IsNil(nil), true)
	require.EqualValues(t, IsNil(a_null), false)
	//require.EqualValues(t, IsNil(p_null), true)
	require.EqualValues(t, IsNil(Nullable{isnull: true}), true)
	require.EqualValues(t, IsNil(&Nullable{isnull: true}), true)
	require.EqualValues(t, IsNil(Nullable{isnull: false}), false)
	require.EqualValues(t, IsNil(&Nullable{isnull: false}), false)
	require.EqualValues(t, IsNil(a_nil), false)
	//require.EqualValues(t, IsNil(p_nil), true)
	require.EqualValues(t, IsNil(Nillable{isnil: true}), true)
	require.EqualValues(t, IsNil(&Nillable{isnil: true}), true)
	require.EqualValues(t, IsNil(Nillable{isnil: false}), false)
	require.EqualValues(t, IsNil(&Nillable{isnil: false}), false)
	require.EqualValues(t, IsNil("test"), false)
	require.EqualValues(t, IsNil(struct{}{}), false)
	require.EqualValues(t, IsNil(&struct {
		Price  float64
		Symbol string
		Rating uint
	}{
		Price:  5.55,
		Symbol: "€",
		Rating: 4,
	}), false)

}
