package concurrency

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	datatests "github.com/CS-SI/SafeScale/lib/utils/data/tests"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// taki taki, Ozuna
func TestTakiTaki(t *testing.T) {
	a := datatests.NewStructWithoutPointers()
	a.Rumba = 9
	a.Content = "Bailame como si fuera la ultima vez"

	armored := NewShielded(a)
	// Note: As soon as 'a' is "shielded", it MUST not be accessed directly, only through the Shielded instance (using Inspect and Alter)

	takitaki, err := NewTask()
	if err != nil {
		t.Errorf("Error creating task")
	}
	err = takitaki.SetID("foo")
	if err != nil {
		t.Errorf("Error setting id")
	}

	nagasaki, err := NewTask()
	if err != nil {
		t.Errorf("Error creating the other task")
	}
	err = nagasaki.SetID("bar")
	if err != nil {
		t.Errorf("Error setting id")
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() { // simulate a goroutine that also can access this armored value and tries to change it
		inerr := armored.Alter(nagasaki, func(clonable data.Clonable) fail.Error {
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
	err = armored.Alter(takitaki, func(clonable data.Clonable) fail.Error {
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

	err = armored.Inspect(takitaki, func(clonable data.Clonable) fail.Error {
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

	armored := NewShielded(a)

	criminal, err := NewTask()
	if err != nil {
		t.Errorf("Error creating task")
	}
	err = criminal.SetID("foo")
	if err != nil {
		t.Errorf("Error setting id")
	}

	estilo, err := NewTask()
	if err != nil {
		t.Errorf("Error creating the other task")
	}
	err = estilo.SetID("bar")
	if err != nil {
		t.Errorf("Error setting id")
	}

	wg := sync.WaitGroup{}
	wg.Add(3) // 2 readers 1 writer
	go func() {
		inerr := armored.Inspect(estilo, func(clonable data.Clonable) fail.Error {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond)
			take := clonable.(*datatests.StructWithoutPointers)
			assert.Equal(t, 10, take.Rumba)
			return nil
		})
		if inerr != nil {
			t.Errorf("Ouch: %s", inerr)
		}
	}()
	go func() {
		inerr := armored.Inspect(estilo, func(clonable data.Clonable) fail.Error {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond)
			take := clonable.(*datatests.StructWithoutPointers)
			assert.Equal(t, 10, take.Rumba)
			return nil
		})
		if inerr != nil {
			t.Errorf("Ouch: %s", inerr)
		}
	}()
	err = armored.Alter(criminal, func(clonable data.Clonable) fail.Error {
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
	err = armored.Inspect(criminal, func(clonable data.Clonable) fail.Error {
		assert.Equal(t, 10, clonable.(*datatests.StructWithoutPointers).Rumba)
		return nil
	})
	if err != nil {
		t.Errorf("Ugh: %s", err)
	}

	assert.Equal(t, 9, a.Rumba)
}
