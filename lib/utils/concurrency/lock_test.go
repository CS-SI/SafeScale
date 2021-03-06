// +build ignore

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

package concurrency

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/acceptance/tools"
	"github.com/stretchr/testify/assert"
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

	tawri, _ := NewUnbreakableTask()

	gocalls := uint32(0)
	rlockcalls := uint32(0)
	runlockcalls := uint32(0)
	lockcalls := uint32(0)
	unlockcalls := uint32(0)

	num := 100
	wg := sync.WaitGroup{}
	wg.Add(num)

	for j := 0; j < num; j++ {
		go func() {
			defer wg.Done()
			_ = atomic.AddUint32(&gocalls, 1)
			fmt.Println("Ask 4 Reading...")
			err := talo.RLock(tawri)
			assert.Nil(t, err)
			_ = atomic.AddUint32(&rlockcalls, 1)

			defer func() {
				err = talo.RUnlock(tawri)
				assert.Nil(t, err)
				_ = atomic.AddUint32(&runlockcalls, 1)
			}()

			fmt.Println("Reading...")
			time.Sleep(time.Duration(tools.RandomInt(30, 60)) * time.Millisecond)
			fmt.Println("Finished reading...")
		}()
	}

	monum := 1
	wg.Add(monum)
	for j := 0; j < monum; j++ {
		go func() {
			defer wg.Done()
			fmt.Println("Ask 4 Writing...")
			var err error
			for {
				err = talo.Lock(tawri)
				if err == nil {
					_ = atomic.AddUint32(&lockcalls, 1)
					break
				}
			}
			assert.Nil(t, err)
			defer func() {
				var unlockerr error
				for {
					unlockerr = talo.Unlock(tawri)
					if unlockerr == nil {
						_ = atomic.AddUint32(&unlockcalls, 1)
						break
					}
				}
			}()
			fmt.Println("Writing...")
			time.Sleep(time.Duration(tools.RandomInt(3, 30)) * time.Millisecond)
			fmt.Println("Finished Writing...")
		}()
	}

	runOutOfTime := waitTimeout(&wg, time.Duration(20*time.Second))
	if runOutOfTime {
		t.Errorf("Failure: timeout")
	}

	fmt.Printf("go calls: %d\n", gocalls)
	fmt.Printf("RLock calls: %d\n", rlockcalls)
	fmt.Printf("RUnlock calls: %d\n", runlockcalls)
	fmt.Printf("Lock calls: %d\n", lockcalls)
	fmt.Printf("Unlock calls: %d\n", unlockcalls)
	assert.EqualValues(t, uint32(num), rlockcalls)
	assert.EqualValues(t, uint32(num), runlockcalls)
	assert.EqualValues(t, uint32(monum), lockcalls)
	assert.EqualValues(t, uint32(monum), unlockcalls)
}

func TestNewTaskedLockWait(t *testing.T) {
	talo := NewTaskedLock()

	tawri, _ := NewUnbreakableTask()

	num := 100
	wg := sync.WaitGroup{}
	wg.Add(num)
	for j := 0; j < num; j++ {
		go func() {
			defer wg.Done()
			fmt.Println("Ask 4 Reading...")
			err := talo.RLock(tawri)
			assert.Nil(t, err)
			defer func() {
				err = talo.RUnlock(tawri)
				assert.Nil(t, err)
			}()
			fmt.Println("Reading...")
			time.Sleep(time.Duration(tools.RandomInt(3, 9)) * time.Millisecond)
			fmt.Println("Finished reading...")
		}()
	}

	time.Sleep(4 * time.Millisecond)

	monum := 1
	wg.Add(monum)
	for j := 0; j < monum; j++ {
		go func() {
			defer wg.Done()
			fmt.Println("Ask 4 Writing...")
			var err error
			for {
				err = talo.Lock(tawri)
				if err == nil {
					break
				}
			}
			defer func() {
				for {
					unlockErr := talo.Unlock(tawri)
					if unlockErr == nil {
						break
					}
				}
			}()
			fmt.Println("Writing...")
			time.Sleep(time.Duration(tools.RandomInt(70, 120)) * time.Millisecond)
			fmt.Println("Finished Writing...")
		}()
	}

	runOutOfTime := waitTimeout(&wg, time.Duration(200*time.Millisecond))
	if runOutOfTime {
		t.Errorf("Failure: timeout")
	}
}

func TestNewTaskedLockReadThenWrite(t *testing.T) {
	talo := NewTaskedLock()

	tawri, _ := NewUnbreakableTask()

	num := 1
	wg := sync.WaitGroup{}
	wg.Add(num)
	for j := 0; j < num; j++ {
		go func() {
			defer wg.Done()
			fmt.Println("Ask 4 Reading...")
			err := talo.RLock(tawri)
			assert.Nil(t, err)
			defer func() {
				err = talo.RUnlock(tawri)
				assert.Nil(t, err)
			}()
			fmt.Println("Ask 4 Writing...")
			err = talo.Lock(tawri)
			assert.NotNil(t, err)
			defer func() {
				for {
					unlockErr := talo.Unlock(tawri)
					if unlockErr == nil {
						break
					}
				}
			}()
			fmt.Println("Reading and writing...")
			time.Sleep(time.Duration(tools.RandomInt(30, 90)) * time.Millisecond)
			fmt.Println("Finished reading and writing...")
		}()
	}

	runOutOfTime := waitTimeout(&wg, time.Duration(500*time.Millisecond))
	if !runOutOfTime {
		t.Errorf("Failure: this should timeout !!")
	}
}

func TestNewTaskedLockStereoS(t *testing.T) {
	talo := NewTaskedLock()
	tawri, _ := NewUnbreakableTask()

	err := talo.Lock(tawri)
	assert.Nil(t, err)
	for {
		unlockErr := talo.Unlock(tawri)
		if unlockErr == nil {
			break
		}
	}
}

func TestNewTaskedLockWriteThenRead(t *testing.T) {
	talo := NewTaskedLock()

	tawri, _ := NewUnbreakableTask()

	num := 1
	wg := sync.WaitGroup{}
	wg.Add(num)
	for j := 0; j < num; j++ {
		fmt.Println("Throwing functions")
		go func() {
			defer wg.Done()
			fmt.Println("Ask 4 Writing...")
			err := talo.Lock(tawri)
			assert.Nil(t, err)
			defer func() {
				for {
					unlockErr := talo.Unlock(tawri)
					if unlockErr == nil {
						break
					}
				}
			}()
			fmt.Println("Ask 4 Reading...")
			err = talo.RLock(tawri)
			assert.Nil(t, err)
			defer func() {
				fmt.Println("RUnlocking")
				err = talo.RUnlock(tawri)
				assert.Nil(t, err)
			}()
			fmt.Println("Reading and Writing...")
			time.Sleep(time.Duration(tools.RandomInt(300, 900)) * time.Millisecond)
			fmt.Println("Finished reading and writing...")
		}()
	}

	runOutOfTime := waitTimeout(&wg, time.Duration(8*time.Second))
	if runOutOfTime {
		t.Errorf("Failure: timeout")
	}
}

func TestWriteThenWriteThenRead(t *testing.T) {
	talo := NewTaskedLock()

	tawri, _ := NewUnbreakableTask()

	reader := func() {
		err := talo.RLock(tawri)
		assert.Nil(t, err)
		defer func() {
			err = talo.RUnlock(tawri)
			assert.Nil(t, err)
		}()
	}

	recall := func() {
		err := talo.Lock(tawri)
		assert.Nil(t, err)
		defer func() {
			for {
				unlockErr := talo.Unlock(tawri)
				if unlockErr == nil {
					break
				}
			}
		}()

		reader()
	}

	kall := func() {
		err := talo.Lock(tawri)
		assert.Nil(t, err)
		defer func() {
			for {
				unlockErr := talo.Unlock(tawri)
				if unlockErr == nil {
					break
				}
			}
		}()

		recall()
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		kall()
	}()

	runOutOfTime := waitTimeout(&wg, time.Duration(50*time.Millisecond))
	if runOutOfTime {
		t.Errorf("Failure: timeout")
	}
}

func TestRawCounter(t *testing.T) {
	talo := NewTaskedLock()
	tawri, _ := NewTask()

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		err := talo.Lock(tawri)
		assert.Nil(t, err)
		fmt.Println("1")
		err = talo.Lock(tawri)
		assert.Nil(t, err)

		fmt.Println("2")
		for {
			unlockErr := talo.Unlock(tawri)
			if unlockErr == nil {
				break
			}
		}
		assert.Nil(t, err)

		for {
			unlockErr := talo.Unlock(tawri)
			if unlockErr == nil {
				break
			}
		}
	}()

	runOutOfTime := waitTimeout(&wg, time.Duration(2*time.Second))
	if runOutOfTime {
		t.Errorf("Failure: timeout")
	}
}
