//go:build alltests
// +build alltests

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

package concurrency

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

func TestChildrenWaitingGameWithTimeoutsButAbortingInParallel(t *testing.T) {
	defer func() { // sometimes this test panics, breaking coverage collection..., so no more panics
		if r := recover(); r != nil {
			t.Errorf("Test panicked")
			t.FailNow()
		}
	}()

	failure := false
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()

		overlord, xerr := NewTaskGroup()
		require.NotNil(t, overlord)
		require.Nil(t, xerr)

		theID, xerr := overlord.GetID()
		require.Nil(t, xerr)
		require.NotEmpty(t, theID)

		fmt.Println("Begin")

		for ind := 0; ind < 100; ind++ {
			fmt.Println("Iterating...")
			rint := time.Duration(rand.Intn(20)+30) * 10 * time.Millisecond
			_, xerr := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
				delay := parameters.(time.Duration)
				fmt.Printf("Entering (waiting %v)\n", delay)
				defer fmt.Println("Exiting")

				dur := delay / 100
				for i := 0; i < 100; i++ {
					if t.Aborted() {
						break
					}
					time.Sleep(dur)
				}
				return "waiting game", nil
			}, rint)
			if xerr != nil {
				t.Errorf("Unexpected: %s", xerr)
			}
		}

		begin := time.Now()
		go func() {
			time.Sleep(310 * time.Millisecond)
			if xerr := overlord.Abort(); xerr != nil {
				t.Fail()
			}
			// did we abort ?
			aborted := overlord.Aborted()
			if !aborted {
				t.Logf("We just aborted without error above..., why Aborted() says it's not ?")
			}
		}()

		if _, xerr := overlord.WaitGroup(); xerr != nil {
			switch xerr.(type) { // nolint
			case *fail.ErrAborted:
				// Wanted situation, continue
			case *fail.ErrorList:
				el, _ := xerr.(*fail.ErrorList)
				for _, ae := range el.ToErrorSlice() {
					if _, ok := ae.(*fail.ErrAborted); !ok {
						t.Errorf(
							"everything should be aborts in this test: %v", ae,
						) // FIXME: CI Failed
						// This happened on previous CI failure : 3d90f4a9-1e13-446b-881e-002041f02f92: context canceled: context canceled
						failure = true
						return
					}
				}
			default:
				t.Errorf("waitgroup failed with an unexpected error: %v", xerr)
				failure = true
				return
			}
		} else {
			t.Errorf("WaitGroup didn't fail and it should")
			failure = true
			return
		}

		end := time.Since(begin)

		fmt.Println("Here we are")

		if end >= (time.Millisecond * 1200) {
			t.Logf("It should have finished near 1200 ms but it didn't, it was %v !!", end)
		}

		if end >= (time.Millisecond * 2000) {
			t.Errorf("It should have finished near 1200 ms but it didn't, it was %v !!", end)
		}
	}()

	runOutOfTime := waitTimeout(&wg, 60*time.Second)
	if runOutOfTime {
		if failure {
			t.FailNow()
		}
		t.Errorf("Failure: there is a deadlock in TestChildrenWaitingGameWithTimeoutsButAbortingInParallel !")
		t.FailNow()
	}
	if failure {
		t.FailNow()
	}

	time.Sleep(3 * time.Second)
}
