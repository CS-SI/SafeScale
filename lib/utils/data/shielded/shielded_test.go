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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v21/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/stretchr/testify/assert"

	datatests "github.com/CS-SI/SafeScale/v21/lib/utils/data/tests"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

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
		inerr := armored.Alter(func(clonable data.Clonable) fail.Error {
			defer wg.Done()

			take := clonable.(*datatests.StructWithoutPointers)
			time.Sleep(60 * time.Millisecond)
			take.Rumba++
			return nil
		})
		if inerr != nil {
			t.Errorf("Ouch: %s", inerr)
		}
	}()
	err = armored.Alter(func(clonable data.Clonable) fail.Error {
		defer wg.Done()

		time.Sleep(80 * time.Millisecond)
		take := clonable.(*datatests.StructWithoutPointers)
		take.Rumba++
		return nil
	})
	if err != nil {
		t.Errorf("Ugh: %s", err)
	}

	wg.Wait()

	err = armored.Inspect(func(clonable data.Clonable) fail.Error {
		assert.Equal(t, 11, clonable.(*datatests.StructWithoutPointers).Rumba)
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
		inerr := armored.Inspect(func(clonable data.Clonable) fail.Error {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond)
			take := clonable.(*datatests.StructWithoutPointers)
			_ = take.Rumba
			return nil
		})
		if inerr != nil {
			t.Errorf("Ouch: %s", inerr)
		}
	}()
	go func() {
		inerr := armored.Inspect(func(clonable data.Clonable) fail.Error {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond)
			take := clonable.(*datatests.StructWithoutPointers)
			_ = take.Rumba
			return nil
		})
		if inerr != nil {
			t.Errorf("Ouch: %s", inerr)
		}
	}()
	err = armored.Alter(func(clonable data.Clonable) fail.Error {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond)
		take := clonable.(*datatests.StructWithoutPointers)
		take.Rumba++
		time.Sleep(80 * time.Millisecond)
		return nil
	})
	if err != nil {
		t.Errorf("Ugh: %s", err)
	}

	wg.Wait()

	// fmt.Println(a.Rumba)
	err = armored.Inspect(func(clonable data.Clonable) fail.Error {
		take := clonable.(*datatests.StructWithoutPointers).Rumba
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

	err = gotForYou.Inspect(func(clonable data.Clonable) fail.Error {
		take := clonable.(*datatests.StructWithoutPointers).Content
		trumba := clonable.(*datatests.StructWithoutPointers).Rumba
		assert.Equal(t, "Bailame como si fuera la ultima vez", take)
		assert.Equal(t, 9, trumba)
		return nil
	})
	assert.Nil(t, err)
}
