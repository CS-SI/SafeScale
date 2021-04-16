// +build alltests,ignore

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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWriteThenReadThenWrite(t *testing.T) {
	talo := NewTaskedLock()

	tawri, _ := NewUnbreakableTask()

	recall := func() string {
		err := talo.Lock(tawri)
		assert.Nil(t, err)
		defer func() {
			for {
				unlockErr := talo.Unlock(tawri)
				if unlockErr == nil {
					break
				} else {
					fmt.Println("recall() Unlock error:", unlockErr)
				}
				time.Sleep(time.Millisecond)
			}
		}()
		return "World"
	}

	reader := func() string {
		err := talo.RLock(tawri)
		assert.Nil(t, err)
		defer func() {
			err = talo.RUnlock(tawri)
			assert.Nil(t, err)
		}()

		fmt.Println(recall())
		return "Hello"
	}

	kall := func() {
		err := talo.Lock(tawri)
		assert.Nil(t, err)
		defer func() {
			for {
				unlockErr := talo.Unlock(tawri)
				if unlockErr == nil {
					break
				} else {
					fmt.Println("kall() Unlock error:", unlockErr)
				}
			}
		}()

		fmt.Println(reader())
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		kall()
	}()

	runOutOfTime := waitTimeout(&wg, time.Duration(50*time.Millisecond))
	if !runOutOfTime {
		t.Errorf("Failure: this should timeout !")
	}
}
