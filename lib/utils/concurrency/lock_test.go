/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package concurrency

import (
	"fmt"
	"github.com/gophercloud/gophercloud/acceptance/tools"
	"github.com/jwells131313/goethe"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
	"time"
)

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

func TestNewTaskedLock(t *testing.T) {
	talo := NewTaskedLock()

	tawri, _ := NewTask(nil)

	num := 100
	wg := sync.WaitGroup{}
	wg.Add(num)
	for j := 0; j < num; j++ {
		go func() {
			fmt.Println("Ask 4 Reading...")
			err := talo.RLock(tawri)
			assert.Nil(t, err)
			defer func() {
				err = talo.RUnlock(tawri)
				assert.Nil(t, err)
			}()
			fmt.Println("Reading...")
			time.Sleep(time.Duration(tools.RandomInt(30, 90)) * time.Millisecond)
			fmt.Println("Finished reading...")
			wg.Done()
		}()
	}

	monum := 1
	wg.Add(monum)
	for j := 0; j < monum; j++ {
		go func() {
			fmt.Println("Ask 4 Writing...")
			err := talo.Lock(tawri)
			assert.Nil(t, err)
			defer func() {
				err = talo.Unlock(tawri)
				assert.Nil(t, err)
			}()
			fmt.Println("Writing...")
			time.Sleep(time.Duration(tools.RandomInt(3, 30)) * time.Millisecond)
			fmt.Println("Finished Writing...")
			wg.Done()
		}()
	}

	runOutOfTime := waitTimeout(&wg, time.Duration(8*time.Second))
	if runOutOfTime {
		t.Errorf("Failure: timeout")
	}
}

func TestNewTaskedLockWait(t *testing.T) {
	talo := NewTaskedLock()

	tawri, _ := NewTask(nil)

	num := 100
	wg := sync.WaitGroup{}
	wg.Add(num)
	for j := 0; j < num; j++ {
		go func() {
			fmt.Println("Ask 4 Reading...")
			err := talo.RLock(tawri)
			assert.Nil(t, err)
			defer func() {
				err = talo.RUnlock(tawri)
				assert.Nil(t, err)
			}()
			fmt.Println("Reading...")
			time.Sleep(time.Duration(tools.RandomInt(30, 90)) * time.Millisecond)
			fmt.Println("Finished reading...")
			wg.Done()
		}()
	}

	time.Sleep(40 * time.Millisecond)

	monum := 1
	wg.Add(monum)
	for j := 0; j < monum; j++ {
		go func() {
			fmt.Println("Ask 4 Writing...")
			err := talo.Lock(tawri)
			assert.Nil(t, err)
			defer func() {
				err = talo.Unlock(tawri)
				assert.Nil(t, err)
			}()
			fmt.Println("Writing...")
			time.Sleep(time.Duration(tools.RandomInt(700, 1200)) * time.Millisecond)
			fmt.Println("Finished Writing...")
			wg.Done()
		}()
	}

	runOutOfTime := waitTimeout(&wg, time.Duration(8*time.Second))
	if runOutOfTime {
		t.Errorf("Failure: timeout")
	}
}

func TestNewTaskedLockMono(t *testing.T) {
	talo := NewTaskedLock()

	tawri, _ := NewTask(nil)

	num := 1
	wg := sync.WaitGroup{}
	wg.Add(num)
	for j := 0; j < num; j++ {
		go func() {
			fmt.Println("Ask 4 Reading...")
			err := talo.RLock(tawri)
			assert.Nil(t, err)
			defer func() {
				err = talo.RUnlock(tawri)
				assert.Nil(t, err)
			}()
			fmt.Println("Ask 4 Writing...")
			err = talo.Lock(tawri)
			assert.Nil(t, err)
			defer func() {
				err = talo.Unlock(tawri)
				assert.Nil(t, err)
			}()
			fmt.Println("Reading and writing...")
			time.Sleep(time.Duration(tools.RandomInt(300, 900)) * time.Millisecond)
			fmt.Println("Finished reading and writing...")
			wg.Done()
		}()
	}

	runOutOfTime := waitTimeout(&wg, time.Duration(8*time.Second))
	if runOutOfTime {
		t.Errorf("Failure: timeout")
	}
}

func TestNewTaskedLockStereo(t *testing.T) {
	talo := NewTaskedLock()

	tawri, _ := NewTask(nil)

	num := 1
	wg := sync.WaitGroup{}
	wg.Add(num)
	for j := 0; j < num; j++ {
		go func() {
			fmt.Println("Ask 4 Writing...")
			err := talo.Lock(tawri)
			assert.Nil(t, err)
			defer func() {
				err = talo.Unlock(tawri)
				assert.Nil(t, err)
			}()
			fmt.Println("Ask 4 Reading...")
			err = talo.RLock(tawri)
			assert.Nil(t, err)
			defer func() {
				err = talo.RUnlock(tawri)
				assert.Nil(t, err)
			}()
			fmt.Println("Reading and Writing...")
			time.Sleep(time.Duration(tools.RandomInt(300, 900)) * time.Millisecond)
			fmt.Println("Finished reading and writing...")
			wg.Done()
		}()
	}

	runOutOfTime := waitTimeout(&wg, time.Duration(8*time.Second))
	if runOutOfTime {
		t.Errorf("Failure: timeout")
	}
}

func TestOldLockType(t *testing.T) {
	talo := NewTaskedLock()

	tawri, _ := NewTask(nil)

	reader := func() {
		err := talo.RLock(tawri)
		assert.Nil(t, err)
		defer talo.RUnlock(tawri)
	}

	recall := func() {
		err := talo.Lock(tawri)
		assert.Nil(t, err)
		defer talo.Unlock(tawri)

		reader()
	}

	kall := func() {
		err := talo.Lock(tawri)
		assert.Nil(t, err)
		defer talo.Unlock(tawri)

		recall()
	}

	kall()
}

func TestOldLockTypeBis(t *testing.T) {
	talo := NewTaskedLock()

	tawri, _ := NewTask(nil)

	recall := func() string {
		err := talo.Lock(tawri)
		assert.Nil(t, err)
		defer talo.Unlock(tawri)
		return "World"
	}

	reader := func() string {
		err := talo.RLock(tawri)
		assert.Nil(t, err)
		defer talo.RUnlock(tawri)

		fmt.Println(recall())
		return "Hello"
	}

	kall := func() {
		err := talo.Lock(tawri)
		assert.Nil(t, err)
		defer talo.Unlock(tawri)

		fmt.Println(reader())
	}

	kall()
}

func TestNewLockType(t *testing.T) {
	var ethe = goethe.GG()
	var lock = ethe.NewGoetheLock()

	reader := func() {
		err := lock.ReadLock()
		assert.Nil(t, err)
		defer lock.ReadUnlock()
	}

	seb := func() {
		err := lock.WriteLock()
		assert.Nil(t, err)
		defer lock.WriteUnlock()

		reader()
	}

	anofu := func() {
		err := lock.WriteLock()
		assert.Nil(t, err)
		defer lock.WriteUnlock()

		seb()
	}

	_, err := ethe.Go(anofu)
	assert.Nil(t, err)
}

func TestNewTaskedLockMonoBis(t *testing.T) {
	var ethe = goethe.GG()
	var lock = ethe.NewGoetheLock()

	num := 1
	wg := sync.WaitGroup{}
	wg.Add(num)
	for j := 0; j < num; j++ {
		ethe.Go(func() {
			fmt.Println("Ask 4 Reading...")
			err := lock.ReadLock()
			assert.Nil(t, err)
			defer func() {
				err = lock.ReadUnlock()
				assert.Nil(t, err)
			}()
			fmt.Println("Ask 4 Writing...")
			err = lock.WriteLock()
			assert.Nil(t, err)
			defer func() {
				err = lock.WriteUnlock()
				assert.Nil(t, err)
			}()
			fmt.Println("Reading and writing...")
			time.Sleep(time.Duration(tools.RandomInt(30, 90)) * time.Millisecond)
			fmt.Println("Finished reading and writing...")
			wg.Done()
		})
	}

	runOutOfTime := waitTimeout(&wg, time.Duration(18*time.Second))
	if runOutOfTime {
		t.Errorf("Failure: timeout")
	}
}
