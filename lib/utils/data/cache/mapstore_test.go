//go:build ignore
// +build ignore

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

package cache

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapStore_New(t *testing.T) {

	_, err := NewMapStore("")
	require.Error(t, err)

}

/*
func TestCache_IsNull(t *testing.T) {

	var c *cache = nil
	require.EqualValues(t, c.isNull(), true)

	c, err := NewCache("")
	require.NotEqual(t, err, nil)
	require.EqualValues(t, c.isNull(), true)

	c, err = NewCache("name")
	require.Nil(t, err)
	require.EqualValues(t, c.isNull(), false)

}
*/

// TestMapStore_ReserveUnknownRequestor validates the case where cache entry does not know its requestor (ie context does not contain Task instance)
func TestMapStore_ReserveUnknownRequestor(t *testing.T) {

	/*
		var c *cache = nil
		err := c.Reserve("", 1*time.Second)
		if err == nil {
			t.Error("Can't reserve on nil pointer cache")
			t.Fail()
		}
	*/
	c2, err := NewMapStore("store")
	if err != nil {
		t.Fail()
	}
	err = c2.Reserve(context.Background(), "", 1*time.Second)
	if err == nil {
		t.Error("Expect empty key error")
		t.Fail()
	}
	err = c2.Reserve(context.Background(), "key", 0*time.Second)
	if err == nil {
		t.Error("Expect timeout=0 error")
		t.Fail()
	}
	err = c2.Reserve(context.Background(), "key", 5*time.Second)
	require.NoError(t, err)

	// Note: in same goroutine, the second reserve will return *fail.ErrDuplicate
	err = c2.Reserve(context.Background(), "key", 1*time.Second)
	require.NotNil(t, err)
}

func TestMapStore_ReserveSameTask(t *testing.T) {

	task, xerr := concurrency.NewTask()
	require.Nil(t, xerr)

	/*
		var c *cache = nil
		err := c.Reserve("", 1*time.Second)
		if err == nil {
			t.Error("Can't reserve on nil pointer cache")
			t.Fail()
		}
	*/
	c2, err := NewMapStore("store")
	if err != nil {
		t.Fail()
	}
	err = c2.Reserve(task.Context(), "", 1*time.Second)
	if err == nil {
		t.Error("Expect empty key error")
		t.Fail()
	}
	err = c2.Reserve(task.Context(), "key", 0*time.Second)
	if err == nil {
		t.Error("Expect timeout=0 error")
		t.Fail()
	}
	err = c2.Reserve(task.Context(), "key", 5*time.Second)
	require.NoError(t, err)

	// VPL: in same goroutine, the second reserve will report reservation already done
	err = c2.Reserve(task.Context(), "key", 1*time.Second)
	require.NotNil(t, err)
}

func TestMapStore_Commit(t *testing.T) {

	task, xerr := concurrency.NewTask()
	require.Nil(t, xerr)

	content := newReservation(context.Background(), "store", "content" /*, time.Minute*/)

	/*
		var c *cache = nil
		_, err := c.Commit("", content)
		if err == nil {
			t.Error("Can't commit on nil pointer cache")
			t.Fail()
		}
	*/

	c2, err := NewMapStore("nuka")
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	err = c2.Reserve(task.Context(), content.GetID(), 100*time.Millisecond)
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	time.Sleep(100 * time.Millisecond)

	_, err = c2.Commit(task.Context(), "", content)
	if err == nil {
		t.Error("Expect empty key error")
		t.Fail()
	}

}

func TestMapStore_Free(t *testing.T) {

	task, xerr := concurrency.NewTask()
	require.Nil(t, xerr)

	var rc *mapStore
	err := rc.Free(task.Context(), "key")
	if err == nil {
		t.Error("Can't Free on nil pointer cache")
		t.Fail()
	}

	content := newReservation(task.Context(), "store", "content" /*, time.Minute*/)

	rc2, err := NewMapStore("cache")
	require.NoError(t, err)

	err = rc2.Reserve(task.Context(), "key", 100*time.Millisecond)
	require.NoError(t, err)

	_, err = rc2.Commit(task.Context(), "key", content)
	require.NoError(t, err)

	err = rc2.Free(task.Context(), "")
	if err == nil {
		t.Error("Can't Free empty key")
		t.Fail()
	}

}

func TestMapStore_Add(t *testing.T) {
	task, xerr := concurrency.NewTask()
	require.Nil(t, xerr)

	content := newReservation(task.Context(), "store", "content")
	var rc *mapStore
	_, err := rc.Add(task.Context(), content)
	if err == nil {
		t.Error("Can't Add on nil pointer cache")
		t.Fail()
	}
	rc2, err := NewMapStore("cache")
	require.NoError(t, err)
	_, err = rc2.Add(task.Context(), nil)
	if err == nil {
		t.Error("Can't Add nil content")
		t.Fail()
	}
	_, err = rc2.Add(task.Context(), content)
	require.NoError(t, err)

}

func TestMapStore_SignalChange(t *testing.T) {

	// Expect no panic
	defer func() {
		if q := recover(); q != nil {
			t.Error(q)
			t.Fail()
		}
	}()

	task, xerr := concurrency.NewTask()
	require.Nil(t, xerr)

	content := newReservation(task.Context(), "store", "content" /*, time.Minute*/)

	var rc *mapStore
	rc.SignalChange(content.GetName())

	rc2, err := NewMapStore("nuka")
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	err = rc2.Reserve(task.Context(), content.GetName(), 100*time.Millisecond)
	require.Nil(t, err)

	_, err = rc2.Commit(context.Background(), content.GetName(), content)
	require.NotNil(t, err)

	_, err = rc2.Commit(task.Context(), content.GetName(), content)
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	rc2.SignalChange("")
	rc2.SignalChange(content.GetName())

}

func TestMapStore_MarkAsFreed(t *testing.T) {

	// Expect no panic
	defer func() {
		if q := recover(); q != nil {
			t.Error(q)
			t.Fail()
		}
	}()

	content := newReservation(context.Background(), "store", "content")

	var rc *mapStore
	rc.MarkAsFreed(content.GetName())

	rc2, err := NewMapStore("nuka")
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	err = rc2.Reserve(context.Background(), content.GetName(), 100*time.Millisecond)
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	_, err = rc2.Commit(context.Background(), content.GetName(), content)
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	rc2.MarkAsFreed("")
	rc2.MarkAsFreed(content.GetName())

}

func TestMapStore_MarkAsDeleted(t *testing.T) {

	// Expect no panic
	defer func() {
		if q := recover(); q != nil {
			t.Error(q)
			t.Fail()
		}
	}()

	content := newReservation(context.Background(), "store", "content" /*, time.Minute*/)

	var rc *mapStore
	rc.MarkAsDeleted(content.GetName())

	rc2, err := NewMapStore("nuka")
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	err = rc2.Reserve(context.Background(), content.GetName(), 100*time.Millisecond)
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	_, err = rc2.Commit(context.Background(), content.GetName(), content)
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	rc2.MarkAsDeleted("")
	rc2.MarkAsDeleted(content.GetName())

}

func TestMapStore_LockContent(t *testing.T) {
	content := newReservation(context.Background(), "store", "content")
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

func TestMapStore_ParallelLockContent(t *testing.T) {
	content := newReservation(context.Background(), "store", "content")
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

func makeDeadlockHappy(mdh Store) fail.Error {
	// doing some stuff that ends up calling....
	anotherRead, xerr := mdh.Entry(context.Background(), "What")
	if xerr != nil {
		return xerr
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

func TestMapStore_Deadlock(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		content := newReservation(context.Background(), "store", "content")

		nukaCola, _ := NewMapStore("nuka")
		xerr := nukaCola.Reserve(context.Background(), "What", 2*time.Second)
		if xerr != nil {
			t.Error(xerr)
			t.Fail()
			return
		}

		// between reserve and commit, someone with a reference to our cache just checks its content
		xerr = makeDeadlockHappy(nukaCola)
		t.Log(xerr)

		time.Sleep(1 * time.Second)
		_, xerr = nukaCola.Commit(context.Background(), "What", content)
		if xerr != nil {
			t.Log(xerr)
		}

		theX, xerr := nukaCola.Entry(context.Background(), "What")
		if xerr == nil {
			fmt.Println(theX)
		} else {
			t.Log(xerr)
		}
	}()

	failed := waitTimeout(&wg, 30*time.Second)
	if failed {
		t.Error("We have a deadlock in TestDeadlock")
		t.FailNow()
	}
}

func TestMapStore_ReserveCommitGet(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		content := newReservation(context.Background(), "store", "content")

		nukaCola, err := NewMapStore("nuka")
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		err = nukaCola.Reserve(context.Background(), content.GetID(), 100*time.Millisecond)
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		time.Sleep(100 * time.Millisecond)

		compilerHappy, err := nukaCola.Commit(context.Background(), content.GetID(), content)
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		_ = compilerHappy

		time.Sleep(1 * time.Second)

		theX, err := nukaCola.Entry(context.Background(), content.GetID())
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

func TestMapStore_MultipleReserveCommitGet(t *testing.T) {
	wg := sync.WaitGroup{}
	content := newReservation(context.Background(), "store", "content")
	nukaCola, err := NewMapStore("nuka")
	require.Nil(t, err)

	for i := 0; i < 10; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()
			xerr := nukaCola.Reserve(context.Background(), content.GetID(), 200*time.Millisecond)
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

			_, xerr = nukaCola.Commit(context.Background(), content.GetID(), content)
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

			_, xerr = nukaCola.Entry(context.Background(), content.GetID())
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

func TestMapStore_SurprisingBehaviour(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		content := newReservation(context.Background(), "store", "content")

		nukaCola, err := NewMapStore("nuka")
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		err = nukaCola.Reserve(context.Background(), "What", 200*time.Millisecond)
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		time.Sleep(100 * time.Millisecond)

		compilerHappy, xerr := nukaCola.Commit(context.Background(), "What", content) // problem here ?, a mismatch and no complaining ?
		if xerr != nil {
			t.Errorf("unexpected error: %v", xerr)
			t.Fail()
			return
		}

		_ = compilerHappy

		time.Sleep(1 * time.Second)

		// This Entry should fail; "What" has been replacd by "content" during the commit (the key of cached entry follows content ID)
		theX, xerr := nukaCola.Entry(context.Background(), "What")
		if xerr == nil {
			t.Error("there is no cached entry identified by 'What', how can we find it?")
			t.Fail()
			return
		}
		require.Nil(t, theX)

		// This Entry should succeed
		theX, xerr = nukaCola.Entry(context.Background(), "content")
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

func TestMapStore_DeadlockAddingEntry(t *testing.T) {
	content := newReservation(context.Background(), "store", "content")

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		nukaCola, err := NewMapStore("nuka")
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		_, err = nukaCola.Add(context.Background(), content)
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

func TestMapStore_SignalChangeEntry(t *testing.T) {
	content := newReservation(context.Background(), "store", "content")
	_ = content

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		nukaCola, err := NewMapStore("nuka")
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		err = nukaCola.Reserve(context.Background(), content.GetName(), 100*time.Millisecond)
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		_, err = nukaCola.Commit(context.Background(), content.GetName(), content)
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

func TestMapStore_FreeWhenConflictingReservationAlreadyThere(t *testing.T) {
	rc, err := NewMapStore("nuka")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	previous := newReservation(context.Background(), "store", "previous")
	_ = previous
	content := newReservation(context.Background(), "store", "cola")
	_ = content

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()

		_ = rc.Reserve(context.Background(), "previous", 100*time.Millisecond)
		// _ , _ = rc.Commit("previous", previous)

		key := "cola"
		if xerr := rc.Reserve(context.Background(), key, 100*time.Millisecond); xerr != nil {
			t.Error(xerr)
			t.Fail()
			return
		}

		_, xerr := rc.Commit(context.Background(), "previous", content)
		if xerr != nil {
			nerr := rc.Free(context.Background(), "previous")
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

func TestMapStore_Entry(t *testing.T) {

	// Empty cache
	/*
		var nilCache *cache = nil
		_, err := nilCache.Entry("What")
		if err == nil {
			t.Error("Should throw a fail.InvalidInstanceError")
			t.FailNow()
		}
	*/

	// Filled cache, empty key
	nukaCola, err := NewMapStore("nuka")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	_, err = nukaCola.Entry(context.Background(), "")
	if err == nil {
		t.Error("Should throw a fail.InvalidParameterCannotBeEmptyStringError")
		t.FailNow()
	}

	// Filled cache, filled key
	nukaCola, err = NewMapStore("nuka")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	_, err = nukaCola.Entry(context.Background(), "key1")
	if err == nil {
		t.Error("Should throw a fail.NotFoundError")
		t.FailNow()
	}

	err = nukaCola.Reserve(context.Background(), "key1", 1*time.Second)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	// Cache never created on commited
	_, err = nukaCola.Entry(context.Background(), "key1")
	if err == nil {
		t.Error("Should throw a *expired cache* error")
		t.FailNow()
	}

	// Special broken reservation
	err = nukaCola.Reserve(context.Background(), "key1", 1*time.Second)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	_, err = nukaCola.Commit(context.Background(), "key1", nil)
	if err == nil {
		t.Error("Should throw a fail.InvalidParameterCannotBeNilError(content)")
		t.FailNow()
	}
	r := &reservation{
		key:     "content",
		timeout: 1000,
	}
	_, err = nukaCola.Commit(context.Background(), "key1", r)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	_, err = nukaCola.Entry(context.Background(), "key1")
	if err == nil {
		t.Error("Should throw a fail.NotFoundError (fail to found entry...broken one)")
		t.FailNow()
	}
}
