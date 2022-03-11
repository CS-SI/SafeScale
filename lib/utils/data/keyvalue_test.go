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
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyValue_Key(t *testing.T) {

	var v atomic.Value
	v.Store(struct {
		x float64
		y float64
		z float64
	}{0, 0.42, 0.66})

	kv := keyValue{
		name:  "Position",
		value: v,
	}

	require.EqualValues(t, kv.Key(), "Position")

}

func TestKeyValue_Value(t *testing.T) {

	var v atomic.Value
	v.Store(struct {
		x float64
		y float64
		z float64
	}{0, 0.42, 0.66})

	kv := keyValue{
		name:  "Position",
		value: v,
	}
	require.EqualValues(t, v.Load(), kv.Value())

}

func Test_NewImmutableKeyValue(t *testing.T) {

	m := struct {
		x float64
		y float64
		z float64
	}{0, 0.42, 0.66}
	ikv := NewImmutableKeyValue("Position", m)
	require.EqualValues(t, reflect.TypeOf(ikv).String(), "data.ImmutableKeyValue")
	require.EqualValues(t, ikv.Value(), m)

}

func TestImmutableKeyValue_Mutate(t *testing.T) {

	m := struct {
		x float64
		y float64
		z float64
	}{0, 0.42, 0.66}
	ikv := NewImmutableKeyValue("Position", m)
	kv := ikv.Mutate()
	require.EqualValues(t, reflect.TypeOf(kv).String(), "data.KeyValue")
	require.EqualValues(t, kv.Value(), m)

}

func Test_NewKeyValue(t *testing.T) {

	m := struct {
		x float64
		y float64
		z float64
	}{0, 0.42, 0.66}
	kv := NewKeyValue("Position", m)
	require.EqualValues(t, reflect.TypeOf(kv).String(), "data.KeyValue")
	require.EqualValues(t, kv.Value(), m)

}

func TestKeyValue_SetValue(t *testing.T) {

	m1 := struct {
		x float64
		y float64
		z float64
	}{0, 0.42, 0.66}
	m2 := struct {
		x float64
		y float64
		z float64
	}{0.01, 0.43, 0.67}

	var nkv *KeyValue = nil
	nkv.SetValue(m1)
	require.EqualValues(t, reflect.TypeOf(nkv).String(), "*data.KeyValue")

	kv := NewKeyValue("Position", m1)
	kv.SetValue(m2)

	require.EqualValues(t, reflect.TypeOf(kv).String(), "data.KeyValue")
	require.EqualValues(t, kv.Value(), m2)

}
