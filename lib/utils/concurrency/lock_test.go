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
	"github.com/stretchr/testify/require"
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
			require.Nil(t, err)
			defer func() {
				err = talo.RUnlock(tawri)
				require.Nil(t, err)
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
			require.Nil(t, err)
			defer func() {
				err = talo.Unlock(tawri)
				require.Nil(t, err)
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
			require.Nil(t, err)
			defer func() {
				err = talo.RUnlock(tawri)
				require.Nil(t, err)
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
			require.Nil(t, err)
			defer func() {
				err = talo.Unlock(tawri)
				require.Nil(t, err)
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
			require.Nil(t, err)
			defer func() {
				err = talo.RUnlock(tawri)
				require.Nil(t, err)
			}()
			fmt.Println("Ask 4 Writing...")
			err = talo.Lock(tawri)
			require.Nil(t, err)
			defer func() {
				err = talo.Unlock(tawri)
				require.Nil(t, err)
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
			require.Nil(t, err)
			defer func() {
				err = talo.Unlock(tawri)
				require.Nil(t, err)
			}()
			fmt.Println("Ask 4 Reading...")
			err = talo.RLock(tawri)
			require.Nil(t, err)
			defer func() {
				err = talo.RUnlock(tawri)
				require.Nil(t, err)
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

	recall := func() {
		talo.Lock(tawri)
		defer talo.Unlock(tawri)
	}

	kall := func() {
		talo.Lock(tawri)
		defer talo.Unlock(tawri)

		recall()
	}

	kall()
}

func TestNewLockType(t *testing.T) {
	var ethe = goethe.GG()
	var lock = ethe.NewGoetheLock()

	seb := func() {
		lock.WriteLock()
		defer lock.WriteUnlock()
	}

	anofu := func() {
		lock.WriteLock()
		defer lock.WriteUnlock()

		seb()
	}

	ethe.Go(anofu)
}
