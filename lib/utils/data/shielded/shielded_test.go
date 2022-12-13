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

package shielded

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	datatests "github.com/CS-SI/SafeScale/v22/lib/utils/data/tests"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type SomeClonable struct {
	data.Clonable
	value string
}

func (e *SomeClonable) IsNull() bool {
	return e.value == ""
}
func (e *SomeClonable) Clone() (data.Clonable, error) {
	return &SomeClonable{value: e.value}, nil
}
func (e *SomeClonable) Replace(data data.Clonable) (data.Clonable, error) {
	e.value = data.(*SomeClonable).value
	return e, nil
}
func (e *SomeClonable) SetValue(value string) {
	e.value = value
}

func (e *SomeClonable) GetValue() string {
	return e.value
}

func Test_NewShileded(t *testing.T) {

	// Expect panic
	func() {
		defer func() {
			r := recover()
			require.NotEqual(t, r, nil)
		}()
		var a *SomeClonable
		_, _ = NewShielded(a)
	}()

	a := &SomeClonable{value: "any"}
	c, err := NewShielded(a)
	require.Nil(t, err)

	err = c.Inspect(func(clonable data.Clonable) fail.Error {

		data, ok := clonable.(*SomeClonable)
		if !ok {
			return fail.InconsistentError("expect SomeClonable data")
		}
		if data.GetValue() != "any" {
			return fail.InconsistentError("expect SomeClonable:value \"any\"")
		}
		return nil
	})
	require.Nil(t, err)

}

func TestShielded_IsNull(t *testing.T) {

	var s *Shielded
	require.EqualValues(t, s.IsNull(), true)

	a := &SomeClonable{}
	c, err := NewShielded(a)
	require.Nil(t, err)
	require.EqualValues(t, c.IsNull(), true)

	a = &SomeClonable{value: "any"}
	c, err = NewShielded(a)
	require.Nil(t, err)
	require.EqualValues(t, c.IsNull(), false)

}

func TestShielded_Clone(t *testing.T) {

	// Expect panic
	func() {
		defer func() {
			r := recover()
			require.NotEqual(t, r, nil)
			fmt.Println(r)
		}()
		var s *Shielded
		_, _ = s.Clone()
	}()

	a := &SomeClonable{value: "any"}
	c, err := NewShielded(a)
	require.Nil(t, err)
	r, err := c.Clone()
	require.Nil(t, err)

	err = c.Alter(func(data data.Clonable) fail.Error {
		v, ok := data.(*SomeClonable)
		if !ok {
			return fail.InconsistentError("Expect SomeClonable data")
		}
		v.SetValue("any 2")
		return nil
	})
	require.Nil(t, err)
	err = c.Inspect(func(data data.Clonable) fail.Error {
		v, ok := data.(*SomeClonable)
		if !ok {
			return fail.InconsistentError("Expect SomeClonable data")
		}
		require.EqualValues(t, v.GetValue(), "any 2")
		return nil
	})
	require.Nil(t, err)
	err = r.Inspect(func(data data.Clonable) fail.Error {
		v, ok := data.(*SomeClonable)
		if !ok {
			return fail.InconsistentError("Expect SomeClonable data")
		}
		// if is "any 2", is swallow clone
		require.EqualValues(t, v.GetValue(), "any")
		return nil
	})
	require.Nil(t, err)

}

func TestShielded_Inpect(t *testing.T) {

	var a *Shielded
	var derr error

	err := a.Inspect(func(clonable data.Clonable) fail.Error {
		return nil
	})
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstance")
	require.Contains(t, err.Error(), "calling method from a nil pointer")

	a = &Shielded{}
	err = a.Inspect(func(clonable data.Clonable) fail.Error {
		return nil
	})
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstanceContent")
	require.Contains(t, err.Error(), "invalid instance content")

	a, derr = NewShielded(&SomeClonable{value: "any"})
	require.EqualValues(t, derr, nil)
	var f func(clonable data.Clonable) fail.Error
	err = a.Inspect(f)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	require.Contains(t, err.Error(), "invalid parameter: inspector")

	a = &Shielded{}
	err = a.Inspect(func(clonable data.Clonable) fail.Error {
		return nil
	})
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstanceContent")
	require.Contains(t, err.Error(), "invalid instance content: d.witness")

	a, derr = NewShielded(&SomeClonable{value: "any"})
	require.EqualValues(t, derr, nil)
	err = a.Inspect(func(clonable data.Clonable) fail.Error {
		return nil
	})
	require.Nil(t, err)

}

func TestShielded_Alter(t *testing.T) {

	var a *Shielded
	var derr error

	err := a.Alter(func(clonable data.Clonable) fail.Error {
		return nil
	})
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstance")
	require.Contains(t, err.Error(), "calling method from a nil pointer")

	a = &Shielded{}
	err = a.Alter(func(clonable data.Clonable) fail.Error {
		return nil
	})
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstanceContent")
	require.Contains(t, err.Error(), "invalid instance content")

	a, derr = NewShielded(&SomeClonable{value: "any"})
	require.EqualValues(t, derr, nil)

	var f func(clonable data.Clonable) fail.Error
	err = a.Alter(f)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	require.Contains(t, err.Error(), "invalid parameter: alterer")

	a = &Shielded{}
	err = a.Alter(func(clonable data.Clonable) fail.Error {
		return nil
	})
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstanceContent")
	require.Contains(t, err.Error(), "invalid instance content: d.witness")

	a, derr = NewShielded(&SomeClonable{value: "any"})
	require.EqualValues(t, derr, nil)

	err = a.Alter(func(clonable data.Clonable) fail.Error {
		v, ok := clonable.(*SomeClonable)
		if !ok {
			return fail.InconsistentError("Expect SomeClonable data")
		}
		v.SetValue("any 2")
		return nil
	})
	require.Nil(t, err)
	err = a.Inspect(func(data data.Clonable) fail.Error {
		v, ok := data.(*SomeClonable)
		if !ok {
			return fail.InconsistentError("Expect SomeClonable data")
		}
		require.EqualValues(t, v.GetValue(), "any 2")
		return nil
	})
	require.Nil(t, err)

}

func TestShielded_Serialize(t *testing.T) {

	var a *Shielded
	var derr error

	d, err := a.Serialize()
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstance")
	require.Contains(t, err.Error(), "invalid instance: in")
	require.EqualValues(t, len(d), 0)

	a, derr = NewShielded(&SomeClonable{value: "any"})
	require.EqualValues(t, derr, nil)

	d, err = a.Serialize()
	require.Nil(t, err)
	require.EqualValues(t, string(d), "{\"Clonable\":null}")

}

func TestShielded_Deserialize(t *testing.T) {

	var a *Shielded
	var derr error

	err := a.Deserialize([]byte("{\"Clonable\":null}"))
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstance")
	require.Contains(t, err.Error(), "invalid instance: in")

	err = a.Deserialize([]byte(""))
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstance")
	require.Contains(t, err.Error(), "calling method from a nil pointer")

	a, derr = NewShielded(&SomeClonable{value: "any"})
	require.EqualValues(t, derr, nil)

	err = a.Deserialize([]byte("{\"Clonable\":null}"))
	require.Nil(t, err)

}

// ---------------------------------------------------------------------------------

func TestSerialize(t *testing.T) {
	a := datatests.NewStructWithoutPointers()
	a.Rumba = 9
	a.Content = "Bailame como si fuera la ultima vez"

	armored, err := NewShielded(a)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	// Note: As soon as 'a' is "shielded", it MUST not be accessed directly, only through the Shielded instance (using Inspect and Alter)

	content, err := armored.Serialize()
	assert.Nil(t, err)
	assert.NotNil(t, content)

	assert.True(t, strings.Contains(string(content), "Content"))
	assert.True(t, strings.Contains(string(content), "vez"))
}

func TestSerializeDeserialize(t *testing.T) {
	a := datatests.NewStructWithoutPointers()
	a.Rumba = 9
	a.Content = "Bailame como si fuera la ultima vez"
	assert.NotNil(t, a)

	b := datatests.NewStructWithoutPointers()
	gotForYou, err := NewShielded(b)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	assert.NotNil(t, gotForYou)

	armored, err := NewShielded(a)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	assert.NotNil(t, armored)
	// Note: As soon as 'a' is "shielded", it MUST not be accessed directly, only through the Shielded instance (using Inspect and Alter)

	content, err := armored.Serialize()
	assert.Nil(t, err)
	assert.NotNil(t, content)

	err = gotForYou.Deserialize(content)
	assert.Nil(t, err)

	err = gotForYou.Inspect(func(clonable data.Clonable) fail.Error {
		take := clonable.(*datatests.StructWithoutPointers).Content
		trumba := clonable.(*datatests.StructWithoutPointers).Rumba
		assert.Equal(t, "Bailame como si fuera la ultima vez", take)
		assert.Equal(t, 9, trumba)
		return nil
	})
	assert.Nil(t, err)
}
