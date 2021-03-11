/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

func TestLockContent(t *testing.T) {
	content := &reservation{key: "content"}
	cacheEntry := newEntry(content)

	assert.EqualValues(t, uint(0), cacheEntry.LockCount())

	cacheEntry.LockContent()
	assert.EqualValues(t, uint(1), cacheEntry.LockCount())

	cacheEntry.LockContent()
	assert.EqualValues(t, uint(2), cacheEntry.LockCount())

	cacheEntry.UnlockContent()
	assert.EqualValues(t, uint(1), cacheEntry.LockCount())

	cacheEntry.UnlockContent()
	assert.EqualValues(t, uint(0), cacheEntry.LockCount())
}

func TestParallelLockContent(t *testing.T) {
	content := &reservation{key: "content"}
	cacheEntry := newEntry(content)

	task1, _ := concurrency.NewUnbreakableTask()
	task2, _ := concurrency.NewUnbreakableTask()

	_, _ = task1.Start(func(task concurrency.Task, p concurrency.TaskParameters) (concurrency.TaskResult, fail.Error) {
		cacheEntry.LockContent()
		assert.Equal(t, uint(1), cacheEntry.LockCount())

		time.Sleep(time.Second)

		assert.Equal(t, uint(2), cacheEntry.LockCount())

		cacheEntry.UnlockContent()

		return nil, nil
	}, nil)

	_, _ = task2.Start(func(task concurrency.Task, p concurrency.TaskParameters) (concurrency.TaskResult, fail.Error) {
		time.Sleep(time.Millisecond * 250)
		assert.Equal(t, uint(1), cacheEntry.LockCount())

		cacheEntry.LockContent()
		assert.Equal(t, uint(2), cacheEntry.LockCount())

		time.Sleep(time.Second)

		cacheEntry.UnlockContent()
		assert.Equal(t, uint(0), cacheEntry.LockCount())

		return nil, nil
	}, nil)

	_, _ = task1.Wait()
	_, _ = task2.Wait()

	assert.EqualValues(t, uint(0), cacheEntry.LockCount())
}

func makeDeadlockHappy(mdh *Cache) error {
	// doing some stuff that ends up calling....
	anotherRead, err := (*mdh).GetEntry("What")
	if err != nil {
		return err
	}

	theReadCt := anotherRead.Content() // Deadlock
	fmt.Printf("The deadlocked content : %v\n", theReadCt)
	return nil
}

// waitTimeout waits for the waitgroup for the specified max timeout.
// Returns true if waiting timed out.
func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}

func TestDeadlock(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		content := &reservation{key: "content"}

		nukaCola, _ := NewCache("nuka")
		err := nukaCola.ReserveEntry("What")
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		// between reserve and commit, someone with a reference to our cache just checks its content
		_ = makeDeadlockHappy(&nukaCola)

		time.Sleep(1 * time.Second)
		_, _ = nukaCola.CommitEntry("What", content)

		theX, err := nukaCola.GetEntry("What")
		if err == nil {
			fmt.Println(theX)
		}
	}()

	failed := waitTimeout(&wg, 3*time.Second)
	if failed {
		t.Error("We have a deadlock in TestDeadlock")
		t.FailNow()
	}
}

func TestReserveCommitGet(t *testing.T) {
	content := &reservation{key: "content"}

	nukaCola, err := NewCache("nuka")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	err = nukaCola.ReserveEntry(content.GetID())
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	time.Sleep(100 * time.Millisecond)

	compilerHappy, fe := nukaCola.CommitEntry(content.GetID(), content)
	if fe != nil {
		t.Error(err)
		t.FailNow()
	}

	_ = compilerHappy

	time.Sleep(1 * time.Second)

	theX, err := nukaCola.GetEntry(content.GetID())
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	_ = theX
}

func TestSurprisingBehaviour(t *testing.T) {
	content := &reservation{key: "content"}

	nukaCola, err := NewCache("nuka")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	err = nukaCola.ReserveEntry("What")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	time.Sleep(100 * time.Millisecond)

	compilerHappy, fe := nukaCola.CommitEntry("What", content) // problem here ?, a mismatch and no complaining ?
	if fe != nil {
		t.Error(err)
		t.FailNow()
	}

	_ = compilerHappy

	time.Sleep(1 * time.Second)

	// that is highly unexpected from an user point of view, we reserved a entry with key "What" and successfully commited also with key "What"
	// after that, the GetEntry with the same key, FAILS
	theX, err := nukaCola.GetEntry("What")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	_ = theX
}

func TestDeadlockAddingEntry(t *testing.T) {
	content := &reservation{key: "content"}

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		nukaCola, err := NewCache("nuka")
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		_, err = nukaCola.AddEntry(content)
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}
	}()

	failed := waitTimeout(&wg, 3*time.Second)
	if failed {
		t.Error("We have a deadlock in TestDeadlockAddingEntry")
		t.FailNow()
	}
}

func TestSignalChangeEntry(t *testing.T) {
	content := &reservation{key: "content"}
	_ = content

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		nukaCola, err := NewCache("nuka")
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		err = nukaCola.ReserveEntry(content.GetName())
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		_, err = nukaCola.CommitEntry(content.GetName(), content)
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		nukaCola.SignalChange(content.GetName())
	}()

	failed := waitTimeout(&wg, 3*time.Second)
	if failed {
		t.Error("We have a deadlock in TestSignalChangeEntry")
		t.FailNow()
	}
}

func TestFreeWhenConflictingReservationAlreadyThere(t *testing.T) {
	rc, err := NewCache("nuka")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	previous := &reservation{key: "previous"}
	_ = previous
	content := &reservation{key: "cola"}
	_ = content

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()

		_ = rc.ReserveEntry("previous")
		// _ , _ = rc.CommitEntry("previous", previous)

		key := "cola"
		if xerr := rc.ReserveEntry(key); xerr != nil {
			t.Error(xerr)
			t.Fail()
			return
		}

		_, xerr := rc.CommitEntry("previous", content)
		if xerr != nil {
			nerr := rc.FreeEntry("previous")
			if nerr != nil {
				t.Error(nerr)
				t.Fail()
				return
			}
		} else {
			t.Error("The commit should have failed")
			t.Fail()
			return
		}
		return
	}()

	failed := waitTimeout(&wg, 3*time.Second)
	if failed {
		t.Error("We have a deadlock in TestSignalChangeEntry")
		t.FailNow()
	}

}
