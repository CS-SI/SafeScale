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
	"math"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/davecgh/go-spew/spew"
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

func TestChildrenWaitingGameWithTimeoutsButAborting(t *testing.T) {
	for j := 0; j < 100; j++ {
		overlord, xerr := NewTaskGroup()
		require.NotNil(t, overlord)
		require.Nil(t, xerr)

		theID, xerr := overlord.GetID()
		require.Nil(t, xerr)
		require.NotEmpty(t, theID)

		for ind := 0; ind < 10; ind++ {
			_, xerr := overlord.Start(taskgen(30, 50, 10, 0, 0, 0, false), nil)
			if xerr != nil {
				t.Errorf("Unexpected error: %v", xerr)
				t.FailNow()
			}
		}

		time.Sleep(10 * time.Millisecond)
		begin := time.Now()
		xerr = overlord.Abort()
		require.Nil(t, xerr)

		// did we abort ?
		aborted := overlord.Aborted()
		if !aborted {
			t.Errorf("We just aborted without error above..., why Aborted() says it's not ?")
		}

		_, _, xerr = overlord.WaitFor(5 * time.Second)
		require.NotNil(t, xerr)
		end := time.Since(begin)

		if end >= (time.Millisecond * 400) { // this is 8x the maximum time...
			t.Logf("Abort() lasted %v\n", end)
			t.Logf("Wait() lasted %v\n", end)
			t.Errorf("It should have finished near 400 ms but it didn't!!")
			t.FailNow()
		}
	}
}

func TestChildrenWaitingGameEnoughTimeAfter(t *testing.T) {
	funk := func(index int, rounds int, lower int, upper int, latency int, margin int, gcpressure int) {
		failures := 0
		for iter := 0; iter < rounds; iter++ {
			overlord, xerr := NewTaskGroupWithParent(nil)
			require.NotNil(t, overlord)
			require.Nil(t, xerr)
			xerr = overlord.SetID("/parent")
			require.Nil(t, xerr)

			theID, xerr := overlord.GetID()
			require.Nil(t, xerr)
			require.NotEmpty(t, theID)

			begin := time.Now()
			for ind := 0; ind < gcpressure; ind++ {
				_, xerr := overlord.Start(taskgen(lower, upper, latency, 0, 0, 0, false), nil, InheritParentIDOption, AmendID(fmt.Sprintf("/child-%d", ind)))
				if xerr != nil {
					t.Errorf("Test %d: Unexpected: %s", index, xerr)
					t.FailNow()
					return
				}
			}
			childrenStartDuration := time.Since(begin)

			upbound := int(math.Ceil(float64(upper)/float64(latency)) * float64(latency))
			timeout := time.Duration(upbound+margin) * time.Millisecond
			// Waits that all children have started to access max safely
			begin = time.Now()
			res, xerr := overlord.Wait()
			waitForRealDuration := time.Since(begin)
			if waitForRealDuration > timeout {
				if childrenStartDuration > 5*time.Millisecond { // however, it grows with gcpressure
					t.Logf("Launching children took %v", childrenStartDuration)
				}
				t.Logf("WaitFor really waited %v/%v", waitForRealDuration, timeout)
				t.Logf("Test %d, It should be enough time but it wasn't at iteration #%d", index, iter)
				failures++
				if failures > (75 * rounds / 100) {
					t.Errorf("Test %d: too many failures", index)
					t.FailNow()
					return
				}
			} else {
				require.Nil(t, xerr)
				require.NotEmpty(t, res)
			}
		}
	}

	// Look at the pressure supported by GC
	funk(1, 10, 50, 250, 20, 40, 20)

	// time.Sleep(50 * time.Millisecond)
	// funk(2, 10, 50, 250, 20, 40, 20)
	// time.Sleep(50 * time.Millisecond)
	// funk(3, 10, 50, 250, 20, 40, 20)
	// time.Sleep(50 * time.Millisecond)
	// funk(4, 10, 50, 250, 20, 40, 20)
}

func TestChildrenWaitingGameWithTimeoutsButAbortingInParallelWF(t *testing.T) {
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
			_, xerr := overlord.Start(
				func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
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
				}, rint,
			)
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

		if _, _, xerr := overlord.WaitGroupFor(5 * time.Second); xerr != nil {
			switch xerr.(type) { // nolint
			case *fail.ErrAborted:
				// Wanted situation, continue
			case *fail.ErrorList:
				el, _ := xerr.(*fail.ErrorList)
				for _, ae := range el.ToErrorSlice() {
					if _, ok := ae.(*fail.ErrAborted); !ok {
						t.Errorf("everything should be aborts in this test")
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
			t.Errorf("It should have finished near 1200 ms but it didn't, it was %v !!", end)
		}
	}()

	runOutOfTime := waitTimeout(&wg, 60*time.Second)
	if runOutOfTime {
		if failure {
			t.FailNow()
		}
		t.Errorf("Failure: there is a deadlock in TestChildrenWaitingGameWithTimeoutsButAbortingInParallelWF !")
		t.FailNow()
	}
	if failure {
		t.FailNow()
	}

	time.Sleep(3 * time.Second)
}

func TestChildrenWaitingGameWithTimeoutsButAbortingWF(t *testing.T) {
	for j := 0; j < 100; j++ {
		overlord, xerr := NewTaskGroup()
		require.NotNil(t, overlord)
		require.Nil(t, xerr)

		theID, xerr := overlord.GetID()
		require.Nil(t, xerr)
		require.NotEmpty(t, theID)

		for ind := 0; ind < 10; ind++ {
			_, xerr := overlord.Start(taskgen(30, 50, 10, 0, 0, 0, false), nil)
			if xerr != nil {
				t.Errorf("Unexpected error: %v", xerr)
				t.FailNow()
			}
		}

		time.Sleep(10 * time.Millisecond)
		begin := time.Now()
		xerr = overlord.Abort()
		require.Nil(t, xerr)

		// did we abort ?
		aborted := overlord.Aborted()
		if !aborted {
			t.Errorf("We just aborted without error above..., why Aborted() says it's not ?")
		}

		_, _, xerr = overlord.WaitFor(5 * time.Second)
		require.NotNil(t, xerr)
		end := time.Since(begin)

		if end >= (time.Millisecond * 200) { // this is 4x the maximum time...
			t.Logf("Abort() lasted %v\n", end)
			t.Logf("Wait() lasted %v\n", end)
			t.Errorf("It should have finished near 200 ms but it didn't!!")
			t.FailNow()
		}
	}
}

// This tests the same thing as TestAbortThingsThatActuallyTakeTimeCleaningUpWhenWeAlreadyStartedWaiting, it just
// runs .Abort first, then Wait
// It fails, however it's unclear if it should work..: by design, what should happen if we abort 1st before running the wait ?
func TestAbortThingsThatActuallyTakeTimeCleaningUpAbortAndWaitForLater(t *testing.T) {
	enough := false
	iter := 0
	streak := 0
	chansize := 10
	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		for {
			iter++
			if iter > 1 {
				break
			}
			if enough {
				break
			}

			t.Log("Next") // Each time we iterate we see this line, sometimes this doesn't fail at 1st iteration
			overlord, xerr := NewTaskGroup()
			require.NotNil(t, overlord)
			require.Nil(t, xerr)
			xerr = overlord.SetID(fmt.Sprintf("parent-%d", iter))
			require.Nil(t, xerr)

			bailout := make(chan string, chansize) // a buffered channel
			for ind := 0; ind < chansize; ind++ {  // with the same number of tasks, good
				_, xerr = overlord.Start(
					func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
						weWereAborted := false
						for { // do some work, then look for aborted, again and again
							// some work
							time.Sleep(time.Duration(randomInt(20, 30)) * time.Millisecond)
							if t.Aborted() {
								// Cleaning up first before leaving... ;)
								time.Sleep(time.Duration(randomInt(100, 800)) * time.Millisecond)
								weWereAborted = true
								break
							}
						}
						// We are using the classic 'send on closed channel' trick to see if Wait actually waits until everyone is DONE.
						// If it does we will never see a panic, but if, Abort doesn't mean TellYourChildrenToAbort but
						// actually means AbortYourChildrenAndQuitNOWWithoutWaiting, then we have a problem
						acha := parameters.(chan string)
						acha <- "Bailing out"

						if weWereAborted {
							return "", fail.AbortedError(nil, "we were killed")
						}

						return "who cares", nil
					}, bailout,
					InheritParentIDOption, AmendID(fmt.Sprintf("/child-%d", ind)),
				)
				require.Nil(t, xerr)
			}

			// after this, some tasks will already be looking for ABORT signals
			time.Sleep(time.Duration(65) * time.Millisecond)

			xerr = overlord.Abort()
			require.Nil(t, xerr)

			// did we abort ?
			aborted := overlord.Aborted()
			if !aborted {
				t.Errorf("We just aborted without error above..., why Aborted() says it's not ?")
			}

			_, res, xerr := overlord.WaitFor(5 * time.Second)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrAborted:
					consequences := xerr.Consequences()
					if strings.Contains(spew.Sdump(consequences), "panic happened") {
						t.Logf("unexpected panic occurred!")
					}
				// or maybe we were fast enough and we are quitting only because of Abort, but no problem, we have more iterations...
				case *fail.ErrRuntimePanic:
					t.Errorf("That shouldn't happen")
					t.Fail()
					return
				case *fail.ErrorList:
					if strings.Contains(spew.Sdump(xerr), "panic happened") {
						t.Logf("unexpected panic occurred!")
					}
				default:
					t.Errorf("Unexpected error: %v", xerr)
				}
			} else {
				require.NotNil(t, res)
				if len(bailout) == chansize {
					streak++
					if streak > 5 {
						break
					}
					continue
				}
			}

			close(bailout) // If Wait actually waits, this is closed AFTER all Tasks filled the channel, so no panics
			// If not..., well...

			reminder := false
			if len(bailout) != chansize { // this means panic
				reminder = true
				t.Errorf("Not everyone finished on time !!, panic is coming !!, some tasks will hit a closed channel !!")
				// if we now do a t.FailNow() we already proved our point (if Wait actually waited, the channel
				// size should be chansize each time), but if we dont...
				// we will see runtime panics on our LOGS !!, but NOT in the code
				// with a t.FailNow() we also fail, but the test output is less frightening
				enough = true
			}

			time.Sleep(2000 * time.Millisecond)
			if reminder {
				t.Errorf("by now we should see panics in lines above, panics that only shows in logs and the rest of the code is unaware of")
			}
			// Well, we have a problem Waiting, now it's clear, and as a bonus we uncovered a problem communicating panics to function callers
		}
	}()

	failed := waitTimeout(&wg, 120*time.Second)
	if failed { // It ended with a deadlock
		t.Errorf("We have a deadlock in TestAbortThingsThatActuallyTakeTimeCleaningUpAbortAndWaitForLater")
		t.Fail()
	}
}
