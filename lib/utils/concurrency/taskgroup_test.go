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
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/gophercloud/gophercloud/acceptance/tools"
	"github.com/stretchr/testify/require"
)

func TestChildrenWaitingGame(t *testing.T) {
	overlord, err := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 800; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(tools.RandomInt(50, 250)) * time.Millisecond)
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
			time.Sleep(time.Duration(tools.RandomInt(50, 250)) * time.Millisecond)
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
			rint := tools.RandomInt(50, 250)
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
			rint := tools.RandomInt(50, 250)
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
			rint := tools.RandomInt(50, 250)
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
			rint := tools.RandomInt(5, 25)
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

func TestOneErrorOneOk(t *testing.T) {
	overlord, err := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	_, err = overlord.StartInSubtask(
		func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			rint := tools.RandomInt(30, 50)
			time.Sleep(time.Duration(rint) * 10 * time.Millisecond)

			return "waiting game", nil
		}, nil)
	_, err = overlord.StartInSubtask(
		func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			rint := tools.RandomInt(30, 50)
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
}

func TestChildrenWaitingGameWithTimeouts(t *testing.T) {
	overlord, err := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 10; ind++ {
		fmt.Println("Iterating...")
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			rint := tools.RandomInt(30, 50)
			time.Sleep(time.Duration(rint) * 10 * time.Millisecond)

			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
	}

	begin := time.Now()
	waited, _, err := overlord.WaitFor(time.Duration(10) * 10 * time.Millisecond)
	if err != nil {
		if _, ok := err.(*fail.ErrTimeout); !ok {
			t.Errorf("Unexpected group wait, wrong error type: %s", err)
		}
	}
	end := time.Since(begin)

	if !(((time.Millisecond * 300) >= end) && (end >= (time.Millisecond * 100))) {
		t.Errorf("It should have finished between 100 ms and 300ms but it didn't, it was %s !!", end)
	}

	if waited {
		t.Errorf("It shouldn't happen")
	}
}

func TestChildrenWaitingGameWithTimeoutsButAborting(t *testing.T) {
	overlord, err := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	fmt.Println("Begin")

	for ind := 0; ind < 10; ind++ {
		fmt.Println("Iterating...")
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			rint := tools.RandomInt(30, 50)
			fmt.Printf("Entering (waiting %d)\n", rint)
			time.Sleep(time.Duration(rint) * 10 * time.Millisecond)
			fmt.Println("Exiting")

			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
	}

	begin := time.Now()
	time.Sleep(10 * time.Millisecond)
	err = overlord.Abort()
	require.Nil(t, err)

	end := time.Since(begin)

	fmt.Println("Here we are")

	if end >= (time.Microsecond * 22100) {
		t.Errorf("It should have finished near 20 ms but it didn't, it was %s !!", end)
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

		for ind := 0; ind < 10; ind++ {
			fmt.Println("Iterating...")
			rint := time.Duration(rand.Intn(20)+30) * 10 * time.Millisecond
			_, xerr := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
				delay := parameters.(time.Duration)
				fmt.Printf("Entering (waiting %v)\n", delay)
				defer fmt.Println("Exiting")

				dur := delay/100
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
			time.Sleep(350 * time.Millisecond)
			if xerr := overlord.Abort(); xerr != nil {
				t.Fail()
			}
		}()

		if _, xerr := overlord.WaitGroup(); xerr != nil {
			switch xerr.(type) {
			case *fail.ErrAborted:
				// Wanted situation, continue
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

		if end >= (time.Millisecond * 500) {
			t.Errorf("It should have finished near 350 ms but it didn't, it was %v !!", end)
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
