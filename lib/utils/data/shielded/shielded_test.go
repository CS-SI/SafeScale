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
	datatests "github.com/CS-SI/SafeScale/v22/lib/utils/data/tests"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type SomeClonable struct {
	clonable.Clonable
	value string
}

func (e *SomeClonable) IsNull() bool {
	return e == nil || e.value == ""
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

func Test_NewShielded(t *testing.T) {
	// Expect NO panic
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()

		var a *SomeClonable
		_, _ = NewShielded(a)
	}()

	a := &SomeClonable{value: "any"}
	c, err := NewShielded(a)
	require.Nil(t, err)

	err = c.Inspect(func(data *SomeClonable) fail.Error {
		if data.GetValue() != "any" {
			return fail.InconsistentError("expect SomeClonable:value \"any\"")
		}

		return nil
	})
	require.Nil(t, err)
}

func TestShielded_IsNull(t *testing.T) {
	var s *Shielded[*SomeClonable]
	require.EqualValues(t, s.IsNull(), true)

	var a *SomeClonable
	_, xerr := NewShielded(a)
	require.NotNil(t, xerr)

	a = &SomeClonable{}
	require.True(t, a.IsNull())
	_, xerr = NewShielded(a)
	require.Nil(t, xerr)
}

func TestShielded_Clone(t *testing.T) {
	// Expect panic
	func() {
		defer func() {
			r := recover()
			require.NotEqual(t, r, nil)
			fmt.Println(r)
		}()

		var s *Shielded[*SomeClonable]
		_, _ = s.Clone()
	}()

	a := &SomeClonable{value: "any"}
	c, xerr := NewShielded(a)
	require.Nil(t, xerr)

	_, err := c.Clone()
	require.Nil(t, err)

	r, err := clonable.CastedClone[*Shielded[*SomeClonable]](c)
	require.Nil(t, err)

	xerr = c.Alter(func(data *SomeClonable) fail.Error {
		data.SetValue("any 2")
		return nil
	})
	require.Nil(t, xerr)

	xerr = c.Inspect(func(data *SomeClonable) fail.Error {
		require.EqualValues(t, data.GetValue(), "any 2")
		return nil
	})
	require.Nil(t, xerr)

	xerr = r.Inspect(func(data *SomeClonable) fail.Error {
		// if is "any 2", is swallow clone
		require.EqualValues(t, data.GetValue(), "any")
		return nil
	})
	require.Nil(t, xerr)

}

func TestShielded_Inpect(t *testing.T) {

	var a *Shielded[*SomeClonable]
	xerr := a.Inspect(func(_ *SomeClonable) fail.Error {
		return nil
	})
	require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrInvalidInstance")
	require.Contains(t, xerr.Error(), "calling method from a nil pointer")

	a = &Shielded[*SomeClonable]{}
	xerr = a.Inspect(func(_ *SomeClonable) fail.Error {
		return nil
	})
	require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrInvalidInstance")

	a, err := NewShielded(&SomeClonable{value: "any"})
	require.EqualValues(t, err, nil)
	var f func(_ *SomeClonable) fail.Error
	xerr = a.Inspect(f)
	require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrInvalidParameter")
	require.Contains(t, xerr.Error(), "invalid parameter: inspector")

	a = &Shielded[*SomeClonable]{}
	xerr = a.Inspect(func(_ *SomeClonable) fail.Error {
		return nil
	})
	require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrInvalidInstance")

	var some *SomeClonable
	a, xerr = NewShielded[*SomeClonable](some)
	require.NotNil(t, xerr)
	require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrInvalidParameter")

	a, err = NewShielded(&SomeClonable{value: "any"})
	require.Nil(t, err)
	err = a.Inspect(func(_ *SomeClonable) fail.Error {
		return nil
	})
	require.Nil(t, err)

}

func TestShielded_Alter(t *testing.T) {

	var a *Shielded[*SomeClonable]
	xerr := a.Alter(func(_ *SomeClonable) fail.Error {
		return nil
	})
	require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrInvalidInstance")

	a = &Shielded[*SomeClonable]{}
	xerr = a.Alter(func(_ *SomeClonable) fail.Error {
		return nil
	})
	require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrInvalidInstance")

	a, xerr = NewShielded(&SomeClonable{value: "any"})
	require.Nil(t, xerr)

	var f func(_ *SomeClonable) fail.Error
	xerr = a.Alter(f)
	require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrInvalidParameter")

	var some *SomeClonable
	a, xerr = NewShielded[*SomeClonable](some)
	require.NotNil(t, xerr)
	require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrInvalidParameter")

	a, xerr = NewShielded(&SomeClonable{value: "any"})
	require.Nil(t, xerr)

	xerr = a.Alter(func(p *SomeClonable) fail.Error {
		p.SetValue("any 2")
		return nil
	})
	require.Nil(t, xerr)
	xerr = a.Inspect(func(data *SomeClonable) fail.Error {
		require.EqualValues(t, data.GetValue(), "any 2")
		return nil
	})
	require.Nil(t, xerr)

}

func TestShielded_Serialize(t *testing.T) {

	var a *Shielded[*SomeClonable]
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

	var a *Shielded[*SomeClonable]
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
		inerr := armored.Alter(func(p *datatests.StructWithoutPointers) fail.Error {
			defer wg.Done()
			assert.Equal(t, p, a)

			time.Sleep(60 * time.Millisecond)
			p.Rumba++
			return nil
		})
		if inerr != nil {
			t.Errorf("Ouch: %s", inerr)
		}
	}()
	err = armored.Alter(func(p *datatests.StructWithoutPointers) fail.Error {
		defer wg.Done()
		assert.Equal(t, p, a)

		time.Sleep(80 * time.Millisecond)
		p.Rumba++
		return nil
	})
	if err != nil {
		t.Errorf("Ugh: %s", err)
	}

	wg.Wait()

	err = armored.Inspect(func(p *datatests.StructWithoutPointers) fail.Error {
		assert.Equal(t, p, a)
		assert.Equal(t, 11, p.Rumba)

		return nil
	})
	if err != nil {
		t.Errorf("Ugh: %s", err)
	}

	// a.RumbaMUST have the same value than inside the inspect, it's the same pointer, it's the reason for existence of Shielded
	assert.Equal(t, 11, a.Rumba)
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
		inerr := armored.Inspect(func(take *datatests.StructWithoutPointers) fail.Error {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond)
			_ = take.Rumba
			return nil
		})
		if inerr != nil {
			t.Errorf("Ouch: %s", inerr)
		}
	}()
	go func() {
		inerr := armored.Inspect(func(take *datatests.StructWithoutPointers) fail.Error {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond)
			_ = take.Rumba
			return nil
		})
		if inerr != nil {
			t.Errorf("Ouch: %s", inerr)
		}
	}()
	err = armored.Alter(func(take *datatests.StructWithoutPointers) fail.Error {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond)
		take.Rumba++
		time.Sleep(80 * time.Millisecond)
		return nil
	})
	if err != nil {
		t.Errorf("Ugh: %s", err)
	}

	wg.Wait()

	// fmt.Println(a.Rumba)
	err = armored.Inspect(func(take *datatests.StructWithoutPointers) fail.Error {
		_ = take // Here take may be 9 or 10, depending on who enters the lock 1st, the 2 readers or the writer
		return nil
	})
	if err != nil {
		t.Errorf("Ugh: %s", err)
	}

	assert.Equal(t, 10, a.Rumba)
}

func TestSerialize(t *testing.T) {
	a := datatests.NewStructWithoutPointers()
	a.Rumba = 9
	a.Content = "Bailame como si fuera la ultima vez"

	armored, xerr := NewShielded(a)
	if xerr != nil {
		t.Error(xerr)
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
	spanish := "Bailame como si fuera la ultima vez"
	english := "Dance with me like it's the last time"

	a := datatests.NewStructWithoutPointers()
	require.NotNil(t, a)
	a.Rumba = 9
	a.Content = spanish

	b := datatests.NewStructWithoutPointers()
	require.NotNil(t, b)
	b.Rumba = 10
	b.Content = english
	gotForYou, xerr := NewShielded(b)
	require.Nil(t, xerr)

	armored, xerr := NewShielded(a)
	require.Nil(t, xerr)
	require.NotNil(t, armored)
	// Note: As soon as 'a' is "shielded", it MUST not be accessed directly, only through the Shielded instance (using Inspect and Alter)

	content, err := armored.Serialize()
	require.Nil(t, err)
	require.NotNil(t, content)

	err = gotForYou.Deserialize(content)
	require.Nil(t, err)

	xerr = gotForYou.Inspect(func(take *datatests.StructWithoutPointers) fail.Error {
		require.EqualValues(t, spanish, take.Content)
		require.EqualValues(t, 9, take.Rumba)
		return nil
	})
	require.Nil(t, xerr)
}
