/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package fail

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
)

func waitTimeoutWithoutDeadlock(wg *sync.WaitGroup, timeout time.Duration) bool {
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

func Test_whateverThatMightDeadlockTheRightWay(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()

		err := &errorCore{
			message:             "houston, we have a problem",
			cause:               fmt.Errorf("math: can't divide by zero"),
			consequences:        []error{fmt.Errorf("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		}
		err.lock.Lock()
		// That kills not only this test, it deadlocks, it kills the test suite itself, depending on how it runs, it might block other tests, stop them
		// adding a temporary ban running tests, etc.
		err.lock.Lock()
		fmt.Println("Luck reaching this line")
		fmt.Println("but now it doesn't matter, waitTimeoutWithoutDeadlock detects the deadlock and can fail -> show error in test suit instead of crashing")
	}()
	failed := waitTimeoutWithoutDeadlock(&wg, 1000*time.Millisecond) // the test should take 2,3 ms (without the 2nd lock.Lock()), so waiting 1000 ms is a very safe bet
	if failed {                                                      // It never ended, there is a deadlock with high probability
		t.Logf("It seems we have a deadlock in function: Test_whateverThatMightDeadlockTheRightWay, this was expected, no problem")
	} else {
		t.FailNow() // In this, test, a deadlock is expected, if we don't detect one -> problem
	}
}
