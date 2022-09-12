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

package taskqueue

import (
	"math/rand"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

var TEST_ITERATIONS int = 800

func TestTaskQueue_CreateTaskQueue(t *testing.T) {

	tq := CreateTaskQueue(30)
	require.EqualValues(t, reflect.TypeOf(tq).String(), "*taskqueue.TaskQueue")

}

func TestTaskQueue_PushDrain(t *testing.T) {

	tq := CreateTaskQueue(uint(TEST_ITERATIONS))

	errors := struct {
		mu   sync.Mutex
		list []error
	}{
		list: make([]error, 0),
	}

	wg := sync.WaitGroup{}
	for i := 0; i < TEST_ITERATIONS; i++ {
		t.Logf("[Routine %d] Start", i)
		go func(i int) {
			wg.Add(1)
			defer wg.Done()
			_, err := tq.Push(func() (interface{}, fail.Error) {
				time.Sleep((1 + time.Duration(rand.Intn(50))) * time.Millisecond) // Do not keep order
				return i, nil
			}, 10*time.Second)
			if err != nil {
				errors.mu.Lock()
				errors.list = append(errors.list, err)
				errors.mu.Unlock()
			}
			t.Logf("[Routine %d] End", i)
		}(i + 0)
	}
	tq.Drain() // Drain is called when task queue is empty
	require.EqualValues(t, tq.Length(), 0)
	errors.mu.Lock()
	for err := range errors.list {
		t.Error(err)
	}
	errors.mu.Unlock()
	wg.Wait()
}
