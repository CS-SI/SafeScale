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
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

func TestIntrospection(t *testing.T) {
	overlord, err := NewTaskGroupWithParent(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 800; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			wat := time.Duration(RandomInt(50, 250)) * time.Millisecond
			tempo := wat / 100
			for i := 0; i < 100; i++ {
				if t.Aborted() {
					return "aborting", fail.AbortedError(nil, "killed by parent")
				}
				time.Sleep(tempo)
			}
			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
			t.FailNow()
		}
	}

	time.Sleep(20 * time.Millisecond)

	num, err := overlord.GetStarted()
	require.Nil(t, err)
	if num != 800 {
		t.Errorf("Problem reporting # of started tasks")
	}

	id, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, id)

	sign := overlord.GetSignature()
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

func TestIntrospectionWithErrors(t *testing.T) {
	overlord, err := NewTaskGroupWithParent(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 800; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(RandomInt(50, 250)) * time.Millisecond)
			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
			t.FailNow()
		}
	}

	_, err = overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(RandomInt(50, 250)) * time.Millisecond)
		return "waiting game", fail.NewError("something happened")
	}, nil)
	if err != nil {
		t.Errorf("Unexpected: %s", err)
		t.FailNow()
	}

	time.Sleep(49 * time.Millisecond)

	num, err := overlord.GetStarted()
	require.Nil(t, err)
	if num != 801 {
		t.Errorf("Problem reporting # of started tasks: %d (!= 800)", num)
	}

	id, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, id)

	sign := overlord.GetSignature()
	require.NotEmpty(t, sign)

	ok, err := overlord.IsSuccessful()
	require.NotNil(t, err)

	res, err := overlord.Wait()
	require.NotNil(t, err)
	require.NotEmpty(t, res)

	ok, err = overlord.IsSuccessful()
	require.Nil(t, err)
	require.False(t, ok)
}

func TestChildrenWaitingGameOnlyAWhile(t *testing.T) {
	overlord, err := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 800; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(RandomInt(50, 250)) * time.Millisecond)
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

	done, res, err := single.WaitFor(10 * time.Millisecond)
	require.True(t, done) // there's nothing to do with a READY group, so shouldn't this be true ?
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
	failures := 0
	for iter := 0; iter < 100; iter++ {
		overlord, xerr := NewTaskGroupWithParent(nil)
		require.NotNil(t, overlord)
		require.Nil(t, xerr)
		xerr = overlord.SetID("/parent")
		require.Nil(t, xerr)

		theID, xerr := overlord.GetID()
		require.Nil(t, xerr)
		require.NotEmpty(t, theID)

		begin := time.Now()
		for ind := 0; ind < 800; ind++ {
			_, xerr := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
				tempo := RandomInt(50, 250)
				time.Sleep(time.Duration(tempo) * time.Millisecond)
				return "waiting game", nil
			}, nil, InheritParentIDOption, AmendID(fmt.Sprintf("/child-%d", ind)))
			if xerr != nil {
				t.Errorf("Unexpected: %s", xerr)
				t.FailNow()
			}
		}
		childrenStartDuration := time.Since(begin)
		t.Logf("Launching children took %v", childrenStartDuration)
		timeout := 450 * time.Millisecond
		t.Logf("Waiting for %v", timeout)
		// Waits that all children have started to access max safely
		begin = time.Now()
		fastEnough, res, xerr := overlord.WaitFor(timeout)
		waitForRealDuration := time.Since(begin)
		t.Logf("WaitFor really waited %v", waitForRealDuration)
		if !fastEnough {
			t.Errorf("It should be enough time but it wasn't at iteration #%d", iter)
			failures++
			if failures > 4 {
				t.FailNow()
			}
		} else {
			require.Nil(t, xerr)
			require.NotEmpty(t, res)
		}
	}
}

func TestChildrenWaitingGame(t *testing.T) {
	overlord, err := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 800; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(RandomInt(50, 250)) * time.Millisecond)
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
			time.Sleep(time.Duration(RandomInt(50, 250)) * time.Millisecond)
			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		} else {
			theID, _ := subtaskID.GetID()
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

	for ind := 0; ind < 800; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			rint := RandomInt(50, 250)
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

	for ind := 0; ind < 800; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			rint := RandomInt(50, 250)
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

	for ind := 0; ind < 800; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			rint := RandomInt(50, 250)
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
	overlord, err := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	var tasks []Task

	for ind := 0; ind < 2800; ind++ {
		rt, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			rint := RandomInt(5, 25)
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
		stats, statsErr := overlord.GetGroupStatus()
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
			rint := RandomInt(30, 50)
			time.Sleep(time.Duration(rint) * 10 * time.Millisecond)

			return "waiting game", nil
		}, nil)
	_, err = overlord.Start(
		func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			rint := RandomInt(30, 50)
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
			rint := time.Duration(RandomInt(300, 500)) * time.Millisecond
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
			_, xerr := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
				dur := time.Duration(RandomInt(30, 50)) * 10 * time.Millisecond
				tempo := dur / 100
				for i := 0; i < 100; i++ {
					if t.Aborted() {
						return nil, fail.AbortedError(nil)
					}
					time.Sleep(tempo)
				}
				return "waiting game", nil
			}, nil)
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
		t.Logf("Abort() lasted %v\n", end)

		// did we abort ?
		aborted := overlord.Aborted()
		if !aborted {
			t.Errorf("We just aborted without error above..., why Aborted() says it's not ?")
		}

		_, xerr = overlord.Wait()
		require.NotNil(t, xerr)
		end = time.Since(begin)
		t.Logf("Wait() lasted %v\n", end)
		if end >= (time.Millisecond * 100) { // this is twice the maximum time...
			t.Errorf("It should have finished near 100 ms but it didn't!!")
			t.FailNow()
		}
	}
}

func TestChildrenWaitingGameWithTimeoutsButAbortingInParallel(t *testing.T) {
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
				t.Errorf("We just aborted without error above..., why Aborted() says it's not ?")
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
			t.Errorf("waitgroup didn't fail and it should")
			failure = true
			return
		}

		end := time.Since(begin)

		fmt.Println("Here we are")

		if end >= (time.Millisecond * 1000) {
			t.Errorf("It should have finished near 1000 ms but it didn't, it was %v !!", end)
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
