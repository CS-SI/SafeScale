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

	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLockContent(t *testing.T) {
	content := newReservation("content")
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
	content := newReservation("content")
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

func makeDeadlockHappy(mdh Cache) error {
	// doing some stuff that ends up calling....
	anotherRead, err := mdh.Entry("What")
	if err != nil {
		return err
	}

	theReadCt := anotherRead.Content() // Deadlock
	fmt.Printf("The (not deadlocked on success) content : %v\n", theReadCt)
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
		content := newReservation("content")

		nukaCola, _ := NewCache("nuka")
		err := nukaCola.Reserve("What")
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		// between reserve and commit, someone with a reference to our cache just checks its content
		_ = makeDeadlockHappy(nukaCola)

		time.Sleep(1 * time.Second)
		_, _ = nukaCola.Commit("What", content)

		theX, err := nukaCola.Entry("What")
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
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		content := newReservation("content")

		nukaCola, err := NewCache("nuka")
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		err = nukaCola.Reserve(content.GetID())
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		time.Sleep(100 * time.Millisecond)

		compilerHappy, err := nukaCola.Commit(content.GetID(), content)
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		_ = compilerHappy

		time.Sleep(1 * time.Second)

		theX, err := nukaCola.Entry(content.GetID())
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		_ = theX
	}()

	failed := waitTimeout(&wg, 100*time.Second)
	if failed {
		t.Error("We have a deadlock in TestReserveCommitGet")
		t.FailNow()
	}
}

func TestMultipleReserveCommitGet(t *testing.T) {
	wg := sync.WaitGroup{}
	content := newReservation("content")
	nukaCola, err := NewCache("nuka")
	require.Nil(t, err)

	for i := 0; i < 10; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()
			xerr := nukaCola.Reserve(content.GetID())
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotAvailable, *fail.ErrDuplicate:
					// should be the error code for 9 of the 10 rounds
				default:
					t.Error(xerr)
					t.Fail()
					return
				}
			}

			time.Sleep(100 * time.Millisecond)

			_, xerr = nukaCola.Commit(content.GetID(), content)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotAvailable, *fail.ErrDuplicate, *fail.ErrNotFound:
					// should be the case for 9 of the 10 rounds
				default:
					t.Errorf("Unexpected error: %v", xerr)
					t.Fail()
					return
				}
			}

			time.Sleep(1 * time.Second)

			_, xerr = nukaCola.Entry(content.GetID())
			if xerr != nil {
				t.Errorf("Unexpected error: %v", xerr)
				t.Fail()
				return
			}
		}()
	}

	failed := waitTimeout(&wg, 100*time.Second)
	if failed {
		t.Error("We have a deadlock in TestMultipleReserveCommitGet")
		t.FailNow()
	}
}

func TestSurprisingBehaviour(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		content := newReservation("content")

		nukaCola, err := NewCache("nuka")
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		err = nukaCola.Reserve("What")
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		time.Sleep(100 * time.Millisecond)

		compilerHappy, xerr := nukaCola.Commit("What", content) // problem here ?, a mismatch and no complaining ?
		if xerr != nil {
			t.Errorf("unexpected error: %v", xerr)
			t.Fail()
			return
		}

		_ = compilerHappy

		time.Sleep(1 * time.Second)

		// This Entry should fail; "What" has been replacd by "content" during the commit (the key of cache entry follows content ID)
		theX, xerr := nukaCola.Entry("What")
		if xerr == nil {
			t.Error("there is no cache entry identified by 'What', how can we find it?")
			t.Fail()
			return
		}

		// This Entry should succeed
		theX, xerr = nukaCola.Entry("content")
		if xerr != nil {
			t.Errorf("unexpected error: %v", xerr)
			t.Fail()
			return
		}

		_ = theX
	}()

	failed := waitTimeout(&wg, 3*time.Second)
	if failed {
		t.Error("We have a deadlock in TestSurprisingBehaviour")
		t.FailNow()
	}
}

func TestDeadlockAddingEntry(t *testing.T) {
	content := newReservation("content")

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

		_, err = nukaCola.Add(content)
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
	content := newReservation("content")
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

		err = nukaCola.Reserve(content.GetName())
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		_, err = nukaCola.Commit(content.GetName(), content)
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

	previous := newReservation("previous")
	_ = previous
	content := newReservation("cola")
	_ = content

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()

		_ = rc.Reserve("previous")
		// _ , _ = rc.Commit("previous", previous)

		key := "cola"
		if xerr := rc.Reserve(key); xerr != nil {
			t.Error(xerr)
			t.Fail()
			return
		}

		_, xerr := rc.Commit("previous", content)
		if xerr != nil {
			nerr := rc.Free("previous")
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
	}()

	failed := waitTimeout(&wg, 3*time.Second)
	if failed {
		t.Error("We have a deadlock in TestSignalChangeEntry")
		t.FailNow()
	}
}
