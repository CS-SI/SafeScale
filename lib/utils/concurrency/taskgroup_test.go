/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"strings"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/gophercloud/gophercloud/acceptance/tools"
	"github.com/stretchr/testify/require"
)

// FIXME The whole file taskgroup_test.go MUST pass UT flawlessly before using it confidently in foreman.go and controller.go

func TestChildrenWaitingGame(t *testing.T) {
	overlord, err := NewTaskGroup(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 800; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (result TaskResult, e error) {
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

func TestChildrenWaitingGameWithPanic(t *testing.T) {
	overlord, err := NewTaskGroup(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 800; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (result TaskResult, e error) {
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

	ct := err.Error()
	if !strings.Contains(ct, "Panic protection") {
		t.Errorf("Expected to catch a Panic here...")
	}

	if !strings.Contains(ct, "panic happened") {
		t.Errorf("Expected to catch a Panic here...")
	}
}

func TestChildrenWaitingGameWithRandomError(t *testing.T) {
	overlord, err := NewTaskGroup(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 800; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (result TaskResult, e error) {
			rint := tools.RandomInt(50, 250)
			time.Sleep(time.Duration(rint) * time.Millisecond)
			if rint > 55 {
				return "", fmt.Errorf("suck it")
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
	overlord, err := NewTaskGroup(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 800; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (result TaskResult, e error) {
			rint := tools.RandomInt(50, 250)
			time.Sleep(time.Duration(rint) * time.Millisecond)
			if rint > 100 {
				return "", fmt.Errorf("suck it")
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
	overlord, err := NewTaskGroup(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	var tasks []Task

	for ind := 0; ind < 2800; ind++ {
		rt, err := overlord.Start(func(t Task, parameters TaskParameters) (result TaskResult, e error) {
			rint := tools.RandomInt(5, 25)
			time.Sleep(time.Duration(rint) * time.Millisecond)
			if rint > 10 {
				time.Sleep(time.Duration(800) * time.Millisecond)
			}

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
		stats, statsErr := overlord.Stats()
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

func TestChildrenWaitingGameWithTimeouts(t *testing.T) {
	overlord, err := NewTaskGroup(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	for ind := 0; ind < 10; ind++ {
		fmt.Println("Iterating...")
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (result TaskResult, e error) {
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
		if _, ok := err.(scerr.ErrTimeout); !ok {
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
	overlord, err := NewTaskGroup(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	fmt.Println("Begin")

	for ind := 0; ind < 10; ind++ {
		fmt.Println("Iterating...")
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (result TaskResult, e error) {
			rint := tools.RandomInt(30, 50)
			fmt.Println("Entering")
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

	if end >= (time.Millisecond * 20) {
		t.Errorf("It should have finished near 20 ms but it didn't, it was %s !!", end)
	}
}

func TestChildrenWaitingGameWithTimeoutsButAbortingInParallel(t *testing.T) {
	overlord, err := NewTaskGroup(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	fmt.Println("Begin")

	for ind := 0; ind < 10; ind++ {
		fmt.Println("Iterating...")
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (result TaskResult, e error) {
			rint := tools.RandomInt(30, 50)
			fmt.Println("Entering")
			time.Sleep(time.Duration(rint) * 10 * time.Millisecond)
			fmt.Println("Exiting")

			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
	}

	begin := time.Now()
	go func() {
		time.Sleep(310 * time.Millisecond)
		err = overlord.Abort()
		if err != nil {
			t.Fail()
		}
	}()

	_, err = overlord.WaitGroup()
	if err != nil {
		t.Fail()
	}

	end := time.Since(begin)

	fmt.Println("Here we are")

	if end >= (time.Millisecond * 350) {
		t.Errorf("It should have finished near 350 ms but it didn't, it was %s !!", end)
	}
}
