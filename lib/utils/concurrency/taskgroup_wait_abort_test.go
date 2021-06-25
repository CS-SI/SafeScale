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
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/davecgh/go-spew/spew"
	"github.com/gophercloud/gophercloud/acceptance/tools"
	"github.com/stretchr/testify/require"
)

// Well, let's run a few tasks that, after listening to ABORT signal, quit, but they quit
// after a while, let's say they do a cleanup before exiting ;)
// this is also one of those tests that when tested in a demo, it works..., so we run it 50 times to make sure we see the problem.
// it's better to run this test without race -> too many logs and warnings, hunting data races here doesn't change the outcome,
// it only clouds the real issues
// We want to Wait for our children, and when Abort actually comes, then wait until the children have finished
// and then quit
// This is not what happens (even if that's the easy case where children actually listen and don't block themselves fighting for resources)...
// Let's take a look...
func TestAbortThingsThatActuallyTakeTimeCleaningUpWhenWeAlreadyStartedWaiting(t *testing.T) {
	enough := false
	iter := 0
	for {
		iter++
		if iter > 50 {
			break
		}
		if enough {
			break
		}

		t.Log("Next") // Each time we iterate we see this line, sometimes this doesn't fail at 1st iteration
		single, xerr := NewTaskGroup()
		require.NotNil(t, single)
		require.Nil(t, xerr)

		bailout := make(chan string, 80) // a buffered channel
		for ind := 0; ind < 80; ind++ {  // with the same number of tasks, good
			_, xerr = single.StartInSubtask(
				func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
					for { // do some work, then look for aborted, again and again
						// some work
						time.Sleep(time.Duration(tools.RandomInt(20, 30)) * time.Millisecond)
						status, xerr := t.GetStatus()
						if xerr != nil {
							return "Big failure...", xerr
						}
						// looking again and again...
						if status == ABORTED || status == TIMEOUT {
							// Cleaning up first before leaving... ;)
							time.Sleep(time.Duration(tools.RandomInt(100, 800)) * time.Millisecond)
							break
						}
					}
					// We are using the classic 'send on closed channel' trick to see if Wait actually waits until everyone is DONE.
					// If it does we will never see a panic, but if, Abort doesn't mean TellYourChildrenToAbort but
					// actually means AbortYourChildrenAndQuitNOWWithoutWaiting, then we have a problem
					acha := parameters.(chan string)
					acha <- "Bailing out"
					return "who cares", nil
				}, bailout,
			)
			require.Nil(t, xerr)
		}

		// after this, some tasks will already be looking for ABORT signals
		time.Sleep(time.Duration(65) * time.Millisecond)

		go func() {
			// this will actually start after wait
			time.Sleep(time.Duration(100) * time.Millisecond)

			// let's have fun
			xerr := single.Abort()
			require.Nil(t, xerr)
		}()

		_, xerr = single.Wait() // 100 ms after this, .Abort() should hit
		if xerr != nil {
			t.Errorf("Failed to Wait: %s", xerr.Error()) // Of course, we did !!, we induced a panic !! didn't we ?
			if _, ok := xerr.(*fail.ErrRuntimePanic); !ok {
				t.Errorf("Wait, What ??, only Abort ? where is the panic ??")
			}
			if !strings.Contains(spew.Sdump(xerr), "panic happened") {
				t.Errorf("What ?? the panic was just swallowed in the logs ??, the code making the call doesn't know ???, or we just stopped waiting even before the panic happened ??...")
			}
			// or maybe we were fast enough and we are quitting only because of Abort, but no problem, we have more iterations...
		}
		close(bailout) // If Wait actually waits, this is closed AFTER all Tasks filled the channel, so no panics
		// If not..., well...

		reminder := false
		if len(bailout) != 80 { // this means panic
			reminder = true
			t.Errorf("Not everyone finished on time !!, panic is coming !!, some tasks will hit a closed channel !!")
			// if we now do a t.FailNow() we already proved our point (if Wait actually waited, the channel
			// size should be 80 each time), but if we dont...
			// we will see runtime panics on our LOGS !!, but NOT in the code
			// with a t.FailNow() we also fail, but the test output is less frightening
			enough = true
		}

		time.Sleep(2 * time.Second)
		if reminder {
			t.Errorf("by now we should see panics in lines above, panics that only shows in logs and the rest of the code is unaware of")
		}
		// Well, we have a problem Waiting, now it's clear, and as a bonus we uncovered a problem communicating panics to function callers
	}
}

// This tests the same thing as TestAbortThingsThatActuallyTakeTimeCleaningUpWhenWeAlreadyStartedWaiting, it just
// runs .Abort first, then Wait
// It fails, however it's unclear if it should work..: by design, what should happen if we abort 1st before running the wait ?
func TestAbortThingsThatActuallyTakeTimeCleaningUpAbortAndWaitLater(t *testing.T) {
	enough := false
	iter := 0
	for {
		iter++
		if iter > 50 {
			break
		}
		if enough {
			break
		}

		t.Log("Next") // Each time we iterate we see this line, sometimes this doesn't fail at 1st iteration
		single, xerr := NewTaskGroup()
		require.NotNil(t, single)
		require.Nil(t, xerr)

		bailout := make(chan string, 80) // a buffered channel
		for ind := 0; ind < 80; ind++ {  // with the same number of tasks, good
			_, xerr = single.StartInSubtask(
				func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
					for { // do some work, then look for aborted, again and again
						// some work
						time.Sleep(time.Duration(tools.RandomInt(20, 30)) * time.Millisecond)
						status, xerr := t.GetStatus()
						if xerr != nil {
							return "Big failure...", xerr
						}
						// looking again and again...
						if status == ABORTED || status == TIMEOUT {
							// Cleaning up first before leaving... ;)
							time.Sleep(time.Duration(tools.RandomInt(100, 800)) * time.Millisecond)
							break
						}
					}
					// We are using the classic 'send on closed channel' trick to see if Wait actually waits until everyone is DONE.
					// If it does we will never see a panic, but if, Abort doesn't mean TellYourChildrenToAbort but
					// actually means AbortYourChildrenAndQuitNOWWithoutWaiting, then we have a problem
					acha := parameters.(chan string)
					acha <- "Bailing out"
					return "who cares", nil
				}, bailout,
			)
			require.Nil(t, xerr)
		}

		// after this, some tasks will already be looking for ABORT signals
		time.Sleep(time.Duration(65) * time.Millisecond)

		xerr = single.Abort()
		require.Nil(t, xerr)

		_, xerr = single.Wait()
		if xerr != nil {
			t.Errorf("Failed to Wait: %s", xerr.Error()) // Of course, we did !!, we induced a panic !! didn't we ?
			if _, ok := xerr.(*fail.ErrRuntimePanic); !ok {
				t.Errorf("Wait, What ??, only Abort ? where is the panic ??")
			}
			if !strings.Contains(spew.Sdump(xerr), "panic happened") {
				t.Errorf("What ?? the panic was just swallowed in the logs ??, the code making the call doesn't know ???, or we just stopped waiting even before the panic happened ??...")
			}
			// or maybe we were fast enough and we are quitting only because of Abort, but no problem, we have more iterations...
		}
		close(bailout) // If Wait actually waits, this is closed AFTER all Tasks filled the channel, so no panics
		// If not..., well...

		reminder := false
		if len(bailout) != 80 { // this means panic
			reminder = true
			t.Errorf("Not everyone finished on time !!, panic is coming !!, some tasks will hit a closed channel !!")
			// if we now do a t.FailNow() we already proved our point (if Wait actually waited, the channel
			// size should be 80 each time), but if we dont...
			// we will see runtime panics on our LOGS !!, but NOT in the code
			// with a t.FailNow() we also fail, but the test output is less frightening
			enough = true
		}

		time.Sleep(2 * time.Second)
		if reminder {
			t.Errorf("by now we should see panics in lines above, panics that only shows in logs and the rest of the code is unaware of")
		}
		// Well, we have a problem Waiting, now it's clear, and as a bonus we uncovered a problem communicating panics to function callers
	}
}

// This could be an open question
// This test runs some tasks that succeed by design, so what should happen
// What's troubling about this test, it's that non-determinisic...
// non-deterministic ?? what ??, yes, run it enough times and you will have different outcomes, seriosly
// sometimes the wait fails, sometimes doesn't, sometimes we have an empty result map, sometimes a populated map...
func TestAbortAlreadyFinishedSuccessfullyThingsThenWait(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	single, xerr := NewTaskGroupWithParent(nil)
	require.NotNil(t, single)
	require.Nil(t, xerr)

	for ind := 0; ind < 10; ind++ {
		_, err := single.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(tools.RandomInt(10, 20)) * time.Millisecond)
			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
			t.FailNow()
		}
	}

	time.Sleep(time.Duration(100) * time.Millisecond)
	// single should have finished a loooongtime ago...

	// but we abort anyway
	xerr = single.Abort()
	if xerr != nil {
		t.Errorf("Failed to abort")
		t.FailNow()
	}

	// the question here, is why we fail ?
	// and more, from a client point of view, why this failed ?
	// all we have is an aborted error
	res, xerr := single.Wait()
	if xerr != nil {
		t.Errorf("Failed to Wait: %v", xerr)
	}

	t.Errorf("Recovered this: %v", res)

	_ = w.Close()
	_, _ = ioutil.ReadAll(r)
	os.Stdout = rescueStdout
}
