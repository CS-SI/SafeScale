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
	"context"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestStartAfterDone(t *testing.T) {
	for i := 0; i < 10; i++ {
		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			root, err := RootTask()
			require.Nil(t, err)
			require.NotNil(t, root)

			overlord, err := NewTaskGroupWithParent(root)
			require.Nil(t, err)
			require.NotNil(t, overlord)

			_, err = overlord.Start(taskgenWithCustomFunc(20, 80, 5, 3, 0, 0, false, nil), nil)
			require.Nil(t, err)

			time.Sleep(10 * time.Millisecond)
			_, err = overlord.Start(taskgenWithCustomFunc(20, 80, 5, 3, 0, 0, false, nil), nil)
			require.Nil(t, err)

			_, err = overlord.Wait()
			require.Nil(t, err)

			ok, _ := overlord.IsSuccessful()
			require.True(t, ok)

			// already DONE taskgroup, now it should fail
			_, err = overlord.Start(taskgenWithCustomFunc(20, 80, 5, 3, 0, 0, false, nil), nil)
			require.NotNil(t, err)
		}()

		runOutOfTime := waitTimeout(&wg, 60*time.Second)
		if runOutOfTime {
			t.Errorf("Failure: there is a deadlock in TestChildrenWaitingGameWithTimeoutsButAbortingInParallel !")
			t.FailNow()
		}
	}
}

func TestIntrospection(t *testing.T) {
	for i := 0; i < 4; i++ {
		overlord, err := NewTaskGroupWithParent(nil)
		require.NotNil(t, overlord)
		require.Nil(t, err)

		theID, err := overlord.GetID()
		require.Nil(t, err)
		require.NotEmpty(t, theID)

		for ind := 0; ind < 50; ind++ {
			_, err := overlord.Start(taskgen(50, 250, 25, 0, 0, 0, false), nil)
			if err != nil {
				t.Errorf("Unexpected: %s", err)
				t.FailNow()
			}
		}

		time.Sleep(20 * time.Millisecond)

		num, err := overlord.Started()
		require.Nil(t, err)
		if num != 50 {
			t.Errorf("Problem reporting # of started tasks")
		}

		id, err := overlord.GetID()
		require.Nil(t, err)
		require.NotEmpty(t, id)

		sign := overlord.Signature()
		require.NotEmpty(t, sign)

		ok, err := overlord.IsSuccessful()
		require.NotNil(t, err)

		res, err := overlord.Wait()
		require.Nil(t, err)
		require.NotEmpty(t, res)

		ok, err = overlord.IsSuccessful()
		require.Nil(t, err)
		require.True(t, ok)
	}
}

func TestIntrospectionWithErrors(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()

		overlord, err := NewTaskGroupWithParent(nil)
		require.NotNil(t, overlord)
		require.Nil(t, err)

		theID, err := overlord.GetID()
		require.Nil(t, err)
		require.NotEmpty(t, theID)

		for ind := 0; ind < 50; ind++ {
			_, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
				time.Sleep(time.Duration(randomInt(50, 250)) * time.Millisecond)
				return "waiting game", nil
			}, nil)
			if err != nil {
				t.Errorf("Unexpected: %s", err)
				t.Fail()
				return
			}
		}

		_, err = overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(randomInt(50, 250)) * time.Millisecond)
			return "waiting game", fail.NewError("something happened")
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
			t.Fail()
			return
		}

		time.Sleep(49 * time.Millisecond)

		num, err := overlord.Started()
		require.Nil(t, err)
		if num != 51 {
			t.Errorf("Problem reporting # of started tasks: %d (!= 51)", num)
		}

		id, err := overlord.GetID()
		require.Nil(t, err)
		require.NotEmpty(t, id)

		sign := overlord.Signature()
		require.NotEmpty(t, sign)

		ok, err := overlord.IsSuccessful()
		require.NotNil(t, err)

		res, err := overlord.Wait()
		require.NotNil(t, err)
		require.NotEmpty(t, res)

		ok, err = overlord.IsSuccessful()
		require.Nil(t, err)
		require.False(t, ok)
	}()

	failed := waitTimeout(&wg, 3*time.Second)
	if failed {
		t.Error("We have a deadlock in TestIntrospectionWithErrors")
		t.FailNow()
	}
}

func TestChildrenWaitingGameOnlyAWhile(t *testing.T) {
	overlord, err := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 50; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(randomInt(50, 250)) * time.Millisecond)
			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
			t.FailNow()
		}
	}

	fastEnough, res, err := overlord.WaitFor(90 * time.Millisecond)
	if fastEnough {
		t.FailNow()
	}
	require.NotNil(t, err)
	require.Empty(t, res)
}

func TestCallingReadyTaskGroup(t *testing.T) {
	overlord, err := NewTaskGroupWithParent(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	res, err := overlord.Wait()
	require.Empty(t, res)
	require.NotNil(t, err)

	done, res, err := overlord.WaitFor(10 * time.Millisecond)
	require.False(t, done)
	require.Empty(t, res)
	require.NotNil(t, err)

	done, res, err = overlord.TryWait()
	require.False(t, done)
	require.Empty(t, res)
	require.NotNil(t, err)

	err = overlord.Abort()
	require.Nil(t, err)

	result := overlord.Aborted() // We just aborted without error, why not ?
	require.True(t, result)
}

func TestChildrenWaitingGameEnoughTime(t *testing.T) {
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
			fastEnough, res, xerr := overlord.WaitFor(timeout)
			waitForRealDuration := time.Since(begin)
			if !fastEnough {
				if childrenStartDuration > 5*time.Millisecond { // however, it grows with gcpressure
					t.Logf("Launching children took %v", childrenStartDuration)
				}
				t.Logf("WaitFor really waited %v/%v", waitForRealDuration, timeout)
				t.Logf("Test %d, It should be enough time but it wasn't at iteration #%d", index, iter)
				failures++
				if failures > (rounds / 2) {
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
	funk(1, 20, 200, 250, 50, 50, 10)
	funk(2, 20, 200, 250, 50, 50, 10)
	funk(3, 20, 200, 250, 50, 50, 10)
	funk(4, 20, 200, 250, 50, 50, 10)
}

func TestTimingOnlyOne(t *testing.T) {
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
			waitRealDuration := time.Since(begin)
			if waitRealDuration > timeout {
				if childrenStartDuration > 5*time.Millisecond { // however, it grows with gcpressure
					t.Logf("Launching children took %v", childrenStartDuration)
				}
				t.Logf("Wait really waited %v/%v", waitRealDuration, timeout)
				t.Logf("Test %d, It should be enough time but it wasn't at iteration #%d", index, iter)
				failures++
			} else {
				if xerr != nil { // FIXME: It happens
					t.Errorf("Wait should not have failed with: %v", xerr)
				}
				if res == nil {
					t.Errorf("Result should NOT be nil")
				}
				require.Nil(t, xerr)
				require.NotEmpty(t, res)
			}
		}
	}

	// the latency heavily impacts the results, it's not the gc, it's the increasing sleep overhead
	funk(10, 1, 230, 250, 5, 10, 1)
	time.Sleep(50 * time.Millisecond)
	funk(11, 1, 230, 250, 10, 10, 1)
	time.Sleep(50 * time.Millisecond)
	funk(12, 1, 230, 250, 20, 10, 1)
	time.Sleep(50 * time.Millisecond)
	funk(13, 1, 230, 250, 40, 10, 1)
	time.Sleep(50 * time.Millisecond)
	funk(20, 1, 230, 250, 5, 20, 1)
	time.Sleep(50 * time.Millisecond)
	funk(21, 1, 230, 250, 10, 20, 1)
	time.Sleep(50 * time.Millisecond)
	funk(22, 1, 230, 250, 20, 20, 1)
	time.Sleep(50 * time.Millisecond)
	funk(23, 1, 230, 250, 40, 20, 1)
	time.Sleep(50 * time.Millisecond)
	funk(30, 1, 230, 250, 5, 30, 1)
	time.Sleep(50 * time.Millisecond)
	funk(31, 1, 230, 250, 10, 30, 1)
	time.Sleep(50 * time.Millisecond)
	funk(32, 1, 230, 250, 20, 30, 1)
	time.Sleep(50 * time.Millisecond)
	funk(33, 1, 230, 250, 40, 30, 1)
	time.Sleep(50 * time.Millisecond)
	funk(40, 1, 230, 250, 5, 40, 1)
	time.Sleep(50 * time.Millisecond)
	funk(41, 1, 230, 250, 10, 40, 1)
	time.Sleep(50 * time.Millisecond)
	funk(42, 1, 230, 250, 20, 40, 1)
	time.Sleep(50 * time.Millisecond)
	funk(43, 1, 230, 250, 40, 40, 1)
	time.Sleep(50 * time.Millisecond)
	funk(50, 1, 230, 250, 5, 50, 1)
	time.Sleep(50 * time.Millisecond)
	funk(51, 1, 230, 250, 10, 50, 1)
	time.Sleep(50 * time.Millisecond)
	funk(52, 1, 230, 250, 20, 50, 1)
	time.Sleep(50 * time.Millisecond)
	funk(53, 1, 230, 250, 40, 50, 1)
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
				if failures > (rounds / 2) {
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

func TestStates(t *testing.T) {
	overlord, xerr := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, xerr)

	theID, xerr := overlord.GetID()
	require.Nil(t, xerr)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 4; ind++ {
		_, xerr := overlord.StartWithTimeout(taskgen(200, 250, 50, 0, 0, 0, false), nil, 60*time.Millisecond)
		if xerr != nil {
			t.Errorf("Unexpected: %s", xerr)
		}
	}

	aborted := overlord.Aborted()
	require.False(t, aborted)

	res, xerr := overlord.WaitGroup()
	require.NotNil(t, xerr)
	require.NotEmpty(t, res)

	// We have waited, and no problem, so are we DONE ?
	st, xerr := overlord.Status()
	require.Nil(t, xerr)
	if st != DONE {
		t.Errorf("We should be DONE but we are: %s", st)
	}

	// VPL: (status == DONE) + (xerr is ErrorList) = TaskGroup finished normally with TaskAction(s) in TIMEOUT error(s)
	aborted = overlord.Aborted()
	if aborted {
		t.Errorf("We should be DONE here, so aborted should be true (according to taskgroup.go:776)")
	}
	require.False(t, aborted)

	st, xerr = overlord.Status()
	require.Nil(t, xerr)
	require.NotNil(t, st)

	gst, xerr := overlord.GroupStatus()
	require.Nil(t, xerr)
	require.NotNil(t, gst)

	// VPL: tg.Status() returns the status of the TaskGroup (ie the parent Task launching the children)
	//      tg.GroupStatus() returns the current status of each child of the TaskGroup
	//      maybe we should rename it to GetChildrenStatus()?
	require.NotEqual(t, st, gst) // this is unclear, why both a Status and a GroupStatus ?
}

func TestTimeoutState(t *testing.T) {
	overlord, xerr := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, xerr)
	xerr = overlord.SetID("/parent")
	require.Nil(t, xerr)

	theID, xerr := overlord.GetID()
	require.Nil(t, xerr)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 1; ind++ {
		_, xerr := overlord.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(randomInt(50, 250)) * time.Millisecond)
			return "waiting game", nil
		}, nil, 20*time.Millisecond,
			InheritParentIDOption, AmendID(fmt.Sprintf("/child-%d", ind)))
		if xerr != nil {
			t.Errorf("Unexpected: %s", xerr)
		}
	}

	time.Sleep(400 * time.Millisecond)

	// VPL: Actually, you point at something to think about: some of the statuses are purely internal, like TIMEOUT, ABORTED.
	//      Status() should only return READY, RUNNING or DONE. TIMEOUT and ABORTED are transient status that should
	//      move towards DONE.
	st, xerr := overlord.Status()
	require.Nil(t, xerr)
	require.NotNil(t, st)
	if st != RUNNING {
		t.Errorf("This should be a RUNNING and it's not: %s", st) // VPL: overlord in itself never timed out... expected value is RUNNING
	} // To make TaskGroup times out, you have to use a Deadline on its parent context

	res, xerr := overlord.Wait()
	require.NotNil(t, xerr) // VPL: all children ended on Timeout, but all terminates normally... So xerr is ErrorList
	require.NotEmpty(t, res)

	st, xerr = overlord.Status()
	require.Nil(t, xerr)
	require.NotNil(t, st)
	if st != DONE {
		t.Errorf("This should be a DONE and it's not: %s", st)
	}
}

func TestGrTimeoutState(t *testing.T) {
	overlord, xerr := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, xerr)
	xerr = overlord.SetID("/parent")
	require.Nil(t, xerr)

	theID, xerr := overlord.GetID()
	require.Nil(t, xerr)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 4; ind++ {
		_, xerr = overlord.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(randomInt(50, 250)) * time.Millisecond)
			return "waiting game", nil
		}, nil, 20*time.Millisecond)
		if xerr != nil {
			t.Errorf("Unexpected: %s", xerr)
		}
	}

	time.Sleep(400 * time.Millisecond)

	st, xerr := overlord.GroupStatus()
	require.Nil(t, xerr)
	require.NotNil(t, st)

	numChildren, xerr := overlord.Started()
	require.Nil(t, xerr)

	spew.Dump(st)
	t.Logf("How do I know what's the taskgroup status ?, and how to work with it ? it's undocumented")
	if len(st[TIMEOUT]) != int(numChildren) {
		t.Errorf("Everything should be a timeout")
	}

	res, xerr := overlord.Wait()
	require.NotNil(t, xerr)
	require.NotEmpty(t, res)

	st, xerr = overlord.GroupStatus()
	require.Nil(t, xerr)
	require.NotNil(t, st)

	spew.Dump(st)
	t.Logf("How do I know what's the taskgroup status ?, and how to work with it ? it's undocumented")
	if len(st[DONE]) != int(numChildren) {
		t.Errorf("Everything should be a timeout")
	}
	if len(st[TIMEOUT]) != 0 {
		t.Errorf("There should be a timeout somewhere")
	}
}

func TestChildrenWaitingGame(t *testing.T) {
	overlord, err := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 50; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(randomInt(50, 250)) * time.Millisecond)
			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
	}

	res, err := overlord.Wait()
	require.Nil(t, err)
	require.NotEmpty(t, res)
}

func TestChildrenHaveDistinctIDs(t *testing.T) {
	overlord, err := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	const numTasks = 10
	dictOfIDs := make(map[string]int)

	for ind := 0; ind < numTasks; ind++ {
		subtaskID, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(randomInt(50, 250)) * time.Millisecond)
			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		} else {
			theID, _ := subtaskID.ID()
			dictOfIDs[theID] = ind
		}
	}

	res, err := overlord.WaitGroup()
	require.Nil(t, err)
	require.NotEmpty(t, res)

	if len(res) != numTasks {
		t.Errorf("The waitgroup doesn't have %d tasks: %d", numTasks, len(res))
		t.FailNow()
	}

	if len(dictOfIDs) != numTasks {
		t.Errorf("The dict of IDs doesn't have %d tasks: %d", numTasks, len(dictOfIDs))
		t.FailNow()
	}

	if len(res) != len(dictOfIDs) {
		t.Errorf("The waitgroup and the dict of IDs don't have the same size: %d vs %d", len(res), len(dictOfIDs))
		t.FailNow()
	}
}

func TestChildrenWaitingGameWithPanic(t *testing.T) {
	overlord, err := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 50; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			rint := randomInt(50, 250)
			time.Sleep(time.Duration(rint) * time.Millisecond)
			if rint > 100 {
				panic("Panic protection is needed")
			}

			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
	}

	res, err := overlord.WaitGroup()
	require.NotNil(t, err)
	require.NotEmpty(t, res)

	cause := fail.RootCause(err)
	if cause == nil {
		t.FailNow()
	}

	ct := cause.Error()
	if !strings.Contains(ct, "Panic protection") {
		t.Errorf("Expected to catch a Panic here...")
	}

	if !strings.Contains(ct, "panic happened") {
		t.Errorf("Expected to catch a Panic here...")
	}
}

func TestChildrenWaitingGameWithRandomError(t *testing.T) {
	overlord, err := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 50; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			rint := randomInt(50, 250)
			time.Sleep(time.Duration(rint) * time.Millisecond)
			if rint > 55 {
				return "", fail.NewError("suck it")
			}

			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
	}

	res, err := overlord.WaitGroup()
	require.NotNil(t, err)
	require.NotEmpty(t, res)
}

func TestChildrenTryWaitingGameWithRandomError(t *testing.T) {
	overlord, err := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 50; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			rint := randomInt(50, 250)
			time.Sleep(time.Duration(rint) * time.Millisecond)
			if rint > 100 {
				return "", fail.NewError("suck it")
			}

			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
	}

	begin := time.Now()
	waited, res, err := overlord.TryWaitGroup()
	end := time.Since(begin)

	if end >= (time.Millisecond * 200) {
		t.Errorf("It should have finished near 200 ms but it didn't !!")
	}

	require.False(t, waited)
	require.Nil(t, err)
	require.Nil(t, res)
}

func TestChildrenWaitingGameWithWait4EverTasks(t *testing.T) {
	defer func() { // sometimes this test panics, breaking coverage collection..., so no more panics
		if r := recover(); r != nil {
			t.Errorf("Test panicked")
			t.FailNow()
		}
	}()

	overlord, err := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	var tasks []Task

	for ind := 0; ind < 50; ind++ {
		rt, err := overlord.Start(func(ta Task, parameters TaskParameters) (TaskResult, fail.Error) {
			defer func() { // sometimes this test panics, breaking coverage collection..., so no more panics
				if r := recover(); r != nil {
					t.Errorf("Test panicked")
					t.FailNow()
				}
			}()
			rint := randomInt(5, 25)
			if rint > 8 {
				rint += 1000
			}
			fmt.Printf("sleeping %dms...\n", rint)
			time.Sleep(time.Duration(rint) * time.Millisecond)

			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
			t.Fail()
		}
		tasks = append(tasks, rt)
	}

	if len(tasks) == 0 {
		t.Fatal("Unexpected error")
	}

	var res TaskResult

	c := make(chan struct{})
	go func() {
		res, err = overlord.WaitGroup()
		if err != nil {
			t.Errorf("It shouldn't happen")
			t.Fail()
		}
		c <- struct{}{} // done
		close(c)
	}()

	select {
	case <-time.After(time.Duration(300) * time.Millisecond):
		stats, statsErr := overlord.GroupStatus()
		if statsErr != nil {
			t.Fatal(statsErr)
		}

		if len(stats[RUNNING]) == 0 {
			t.Errorf("We should have dangling goroutines here...")
		} else {
			// fmt.Printf("We have %d dead goroutines", len(stats[RUNNING]))
			require.True(t, len(stats[RUNNING]) > 0)
		}

	case <-c:
		fmt.Printf("Good %s", res)
		t.Errorf("It should have failed")
	}

	require.True(t, true)

	time.Sleep(3 * time.Second) // let goroutines finish
}

func TestNewMethod(t *testing.T) {
	overlord, err := NewTaskGroupWithParent(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)
	other, err := overlord.New()
	require.NotNil(t, other)
	require.Nil(t, err)

	overlord, err = NewTaskGroupWithContext(context.Background())
	require.NotNil(t, overlord)
	require.Nil(t, err)

	ctx := overlord.Context()
	require.NotNil(t, ctx)
}

func TestNewMethodOptions(t *testing.T) {
	task, err := NewTask()
	require.NotNil(t, task)
	require.Nil(t, err)
	overlord, err := NewTaskGroupWithParent(task, InheritParentIDOption)
	require.NotNil(t, overlord)
	require.Nil(t, err)
	other, err := overlord.New()
	require.NotNil(t, other)
	require.Nil(t, err)

	overlord, err = NewTaskGroupWithContext(context.Background())
	require.NotNil(t, overlord)
	require.Nil(t, err)

	ctx := overlord.Context()
	require.NotNil(t, ctx)
}

func TestNewMethodPTGOptions(t *testing.T) {
	task, err := NewTaskGroup()
	require.NotNil(t, task)
	require.Nil(t, err)
	overlord, err := NewTaskGroupWithParent(task, InheritParentIDOption)
	require.NotNil(t, overlord)
	require.Nil(t, err)
	other, err := overlord.New()
	require.NotNil(t, other)
	require.Nil(t, err)

	overlord, err = NewTaskGroupWithContext(context.Background())
	require.NotNil(t, overlord)
	require.Nil(t, err)

	ctx := overlord.Context()
	require.NotNil(t, ctx)
}

func TestNewMethodPTGAmendOptions(t *testing.T) {
	task, err := NewTaskGroup()
	require.NotNil(t, task)
	require.Nil(t, err)
	overlord, err := NewTaskGroupWithParent(task, AmendID("expectations"))
	require.NotNil(t, overlord)
	require.Nil(t, err)
	other, err := overlord.New()
	require.NotNil(t, other)
	require.Nil(t, err)

	overlord, err = NewTaskGroupWithContext(context.Background())
	require.NotNil(t, overlord)
	require.Nil(t, err)

	ctx := overlord.Context()
	require.NotNil(t, ctx)
}

func TestNewMethodOptionsAborted(t *testing.T) {
	task, err := NewTask()
	require.NotNil(t, task)
	require.Nil(t, err)

	_, err = task.Start(
		func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			rint := randomInt(30, 50)
			time.Sleep(time.Duration(rint) * 10 * time.Millisecond)

			return "waiting game", nil
		}, nil)

	err = task.Abort()
	require.Nil(t, err)

	_, _ = task.Wait()

	overlord, err := NewTaskGroupWithParent(task, InheritParentIDOption)
	require.Nil(t, overlord)
	require.NotNil(t, err)
}

func TestOneErrorOneOk(t *testing.T) {
	overlord, err := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	_, err = overlord.Start(
		func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			rint := randomInt(30, 50)
			time.Sleep(time.Duration(rint) * 10 * time.Millisecond)

			return "waiting game", nil
		}, nil)
	_, err = overlord.Start(
		func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			rint := randomInt(30, 50)
			time.Sleep(time.Duration(rint) * 10 * time.Millisecond)

			return nil, fail.NewError("Ouch")
		}, nil)
	_, err = overlord.WaitGroup()
	if err != nil {
		repr := err.Error()
		if !strings.Contains(repr, "Ouch") {
			t.FailNow()
		}
	}

	// Wait a 2nd time
	_, err = overlord.WaitGroup()
	if err != nil {
		repr := err.Error()
		if !strings.Contains(repr, "Ouch") {
			t.FailNow()
		}
	}

	// Wait a 3rd time
	_, _, err = overlord.WaitGroupFor(0 * time.Second)
	if err != nil {
		repr := err.Error()
		if !strings.Contains(repr, "Ouch") {
			t.FailNow()
		}
	}

	// Wait a 4th time
	_, _, err = overlord.WaitGroupFor(1 * time.Second)
	if err != nil {
		repr := err.Error()
		if !strings.Contains(repr, "Ouch") {
			t.FailNow()
		}
	}
}

func TestChildrenWaitingGameWithTimeouts(t *testing.T) {
	overlord, err := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 100; ind++ {
		fmt.Println("Iterating...")
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			rint := time.Duration(randomInt(300, 500)) * time.Millisecond
			fmt.Printf("Entering (sleeping %v)\n", rint)
			time.Sleep(rint)
			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
	}

	begin := time.Now()
	waited, _, err := overlord.WaitFor(100 * time.Millisecond)
	if err != nil {
		if _, ok := err.(*fail.ErrTimeout); !ok {
			t.Errorf("Unexpected group wait, wrong error type: %s", err)
		}
	}
	end := time.Since(begin)
	t.Logf("WaitFor lasted %v", end)
	if !(((time.Millisecond * 300) >= end) && (end >= (time.Millisecond * 100))) {
		t.Errorf("It should have finished between 100ms and 300ms but it didn't")
	}

	if waited {
		t.Errorf("It shouldn't happen")
	}
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
		end := time.Since(begin)

		// did we abort ?
		aborted := overlord.Aborted()
		if !aborted {
			t.Errorf("We just aborted without error above..., why Aborted() says it's not ?")
		}

		_, _, xerr = overlord.WaitFor(5 * time.Second)
		require.NotNil(t, xerr)
		end = time.Since(begin)

		if end >= (time.Millisecond * 200) { // this is 4x the maximum time...
			t.Logf("Abort() lasted %v\n", end)
			t.Logf("Wait() lasted %v\n", end)
			t.Errorf("It should have finished near 200 ms but it didn't!!")
			t.FailNow()
		}
	}
}

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
			switch xerr.(type) {
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

func BenchmarkTryWaitGroup(b *testing.B) {
	overlord, xerr := NewTaskGroup()
	require.Nil(b, xerr)
	require.NotNil(b, overlord)

	for ind := 0; ind < 1000; ind++ {
		_, xerr = overlord.Start(func(t Task, _ TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(10 * time.Second)
			return nil, nil
		}, nil)
		require.Nil(b, xerr)
	}

	for i := 0; i < b.N; i++ {
		_, _, xerr = overlord.TryWaitGroup()
	}
}
