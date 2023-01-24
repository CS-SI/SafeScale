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

package shielded

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	datatests "github.com/CS-SI/SafeScale/v22/lib/utils/data/tests"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type SomeClonable struct {
	clonable.Clonable
	value string
}

func (e *SomeClonable) IsNull() bool {
	return e.value == ""
}
func (e *SomeClonable) Clone() (clonable.Clonable, error) {
	return &SomeClonable{value: e.value}, nil
}
func (e *SomeClonable) Replace(data clonable.Clonable) error {
	e.value = data.(*SomeClonable).value
	return nil
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

	err = c.Inspect(func(p clonable.Clonable) fail.Error {
		data, innerErr := lang.Cast[*SomeClonable](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
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

	err = c.Alter(func(data clonable.Clonable) fail.Error {
		v, ok := data.(*SomeClonable)
		if !ok {
			return fail.InconsistentError("Expect SomeClonable data")
		}
		v.SetValue("any 2")
		return nil
	})
	require.Nil(t, err)
	err = c.Inspect(func(data clonable.Clonable) fail.Error {
		v, ok := data.(*SomeClonable)
		if !ok {
			return fail.InconsistentError("Expect SomeClonable data")
		}
		require.EqualValues(t, v.GetValue(), "any 2")
		return nil
	})
	require.Nil(t, err)
	err = r.Inspect(func(data clonable.Clonable) fail.Error {
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

	err := a.Inspect(func(p clonable.Clonable) fail.Error {
		return nil
	})
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstance")
	require.Contains(t, err.Error(), "calling method from a nil pointer")

	a = &Shielded{}
	err = a.Inspect(func(p clonable.Clonable) fail.Error {
		return nil
	})
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstanceContent")
	require.Contains(t, err.Error(), "invalid instance content")

	a, derr = NewShielded(&SomeClonable{value: "any"})
	require.EqualValues(t, derr, nil)
	var f func(p clonable.Clonable) fail.Error
	err = a.Inspect(f)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	require.Contains(t, err.Error(), "invalid parameter: inspector")

	a = &Shielded{}
	err = a.Inspect(func(p clonable.Clonable) fail.Error {
		return nil
	})
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstanceContent")
	require.Contains(t, err.Error(), "invalid instance content: d.witness")

	a, derr = NewShielded(&SomeClonable{value: "any"})
	require.EqualValues(t, derr, nil)
	err = a.Inspect(func(p clonable.Clonable) fail.Error {
		return nil
	})
	require.Nil(t, err)

}

func TestShielded_Alter(t *testing.T) {

	var a *Shielded
	var derr error

	err := a.Alter(func(p clonable.Clonable) fail.Error {
		return nil
	})
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstance")
	require.Contains(t, err.Error(), "calling method from a nil pointer")

	a = &Shielded{}
	err = a.Alter(func(p clonable.Clonable) fail.Error {
		return nil
	})
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstanceContent")
	require.Contains(t, err.Error(), "invalid instance content")

	a, derr = NewShielded(&SomeClonable{value: "any"})
	require.EqualValues(t, derr, nil)

	var f func(p clonable.Clonable) fail.Error
	err = a.Alter(f)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	require.Contains(t, err.Error(), "invalid parameter: alterer")

	a = &Shielded{}
	err = a.Alter(func(p clonable.Clonable) fail.Error {
		return nil
	})
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstanceContent")
	require.Contains(t, err.Error(), "invalid instance content: d.witness")

	a, derr = NewShielded(&SomeClonable{value: "any"})
	require.EqualValues(t, derr, nil)

	err = a.Alter(func(p clonable.Clonable) fail.Error {
		v, err := lang.Cast[*SomeClonable](p)
		if err != nil {
			return fail.Wrap(err)
		}

		v.SetValue("any 2")
		return nil
	})
	require.Nil(t, err)
	err = a.Inspect(func(data clonable.Clonable) fail.Error {
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

// taki taki, Ozuna
func TestTakiTaki(t *testing.T) {
	a := datatests.NewStructWithoutPointers()
	a.Rumba = 9
	a.Content = "Bailame como si fuera la ultima vez"

	armored, err := NewShielded(a)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	// Note: As soon as 'a' is "shielded", it MUST not be accessed directly, only through the Shielded instance (using Inspect and Alter)

	takitaki, err := concurrency.NewTask()
	if err != nil || takitaki == nil {
		t.Errorf("Error creating task")
		t.FailNow()
	}
	err = takitaki.SetID("foo")
	if err != nil {
		t.Errorf("Error setting id")
	}

	nagasaki, err := concurrency.NewTask()
	if err != nil || nagasaki == nil {
		t.Errorf("Error creating the other task")
		t.FailNow()
	}
	err = nagasaki.SetID("bar")
	if err != nil {
		t.Errorf("Error setting id")
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() { // simulate a goroutine that also can access this armored value and tries to change it
		inerr := armored.Alter(func(p clonable.Clonable) fail.Error {
			defer wg.Done()

			take := p.(*datatests.StructWithoutPointers)
			time.Sleep(60 * time.Millisecond)
			take.Rumba++
			return nil
		})
		if inerr != nil {
			t.Errorf("Ouch: %s", inerr)
		}
	}()
	err = armored.Alter(func(p clonable.Clonable) fail.Error {
		defer wg.Done()

		time.Sleep(80 * time.Millisecond)
		take := p.(*datatests.StructWithoutPointers)
		take.Rumba++
		return nil
	})
	if err != nil {
		t.Errorf("Ugh: %s", err)
	}

	wg.Wait()

	err = armored.Inspect(func(p clonable.Clonable) fail.Error {
		assert.Equal(t, 11, p.(*datatests.StructWithoutPointers).Rumba)
		return nil
	})
	if err != nil {
		t.Errorf("Ugh: %s", err)
	}

	assert.Equal(t, 9, a.Rumba)
}

// cri cri criminal, Ozuna
func TestCriminal(t *testing.T) {
	a := datatests.NewStructWithoutPointers()
	a.Rumba = 9
	a.Content = "tu me robaste el corazon como un criminaaal"

	armored, err := NewShielded(a)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	criminal, err := concurrency.NewTask()
	if err != nil {
		t.Errorf("Error creating task")
		t.FailNow()
	}
	if criminal == nil {
		t.Errorf("Error creating task")
		t.FailNow()
	}
	err = criminal.SetID("foo")
	if err != nil {
		t.Errorf("Error setting id")
	}

	estilo, err := concurrency.NewTask()
	if err != nil {
		t.Errorf("Error creating the other task")
	}
	if estilo == nil {
		t.Errorf("Error creating the other task")
		t.FailNow()
	}
	err = estilo.SetID("bar")
	if err != nil {
		t.Errorf("Error setting id")
	}

	wg := sync.WaitGroup{}
	wg.Add(3) // 2 readers 1 writer
	go func() {
		inerr := armored.Inspect(func(p clonable.Clonable) fail.Error {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond)
			take := p.(*datatests.StructWithoutPointers)
			_ = take.Rumba
			return nil
		})
		if inerr != nil {
			t.Errorf("Ouch: %s", inerr)
		}
	}()
	go func() {
		inerr := armored.Inspect(func(p clonable.Clonable) fail.Error {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond)
			take := p.(*datatests.StructWithoutPointers)
			_ = take.Rumba
			return nil
		})
		if inerr != nil {
			t.Errorf("Ouch: %s", inerr)
		}
	}()
	err = armored.Alter(func(p clonable.Clonable) fail.Error {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond)
		take := p.(*datatests.StructWithoutPointers)
		take.Rumba++
		time.Sleep(80 * time.Millisecond)
		return nil
	})
	if err != nil {
		t.Errorf("Ugh: %s", err)
	}

	wg.Wait()

	// fmt.Println(a.Rumba)
	err = armored.Inspect(func(p clonable.Clonable) fail.Error {
		take := p.(*datatests.StructWithoutPointers).Rumba
		_ = take // Here take may be 9 or 10, depending on who enters the lock 1st, the 2 readers or the writer
		return nil
	})
	if err != nil {
		t.Errorf("Ugh: %s", err)
	}

	assert.Equal(t, 9, a.Rumba)
}

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

	err = gotForYou.Inspect(func(p clonable.Clonable) fail.Error {
		take := p.(*datatests.StructWithoutPointers).Content
		trumba := p.(*datatests.StructWithoutPointers).Rumba
		assert.Equal(t, "Bailame como si fuera la ultima vez", take)
		assert.Equal(t, 9, trumba)
		return nil
	})
	assert.Nil(t, err)
}
