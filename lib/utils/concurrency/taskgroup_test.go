/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/gophercloud/gophercloud/acceptance/tools"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
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

	res, err := overlord.Wait()
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

	res, err := overlord.Wait()
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
	waited, res, err := overlord.TryWait()
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
		}
		tasks = append(tasks, rt)
	}

	if len(tasks) == 0 {
		t.Fatal("Unexpected error")
	}

	var res TaskResult

	c := make(chan struct{})
	go func() {
		res, err = overlord.Wait()
		if err != nil {
			t.Errorf("It shouldn't happen")
		}
		c <- struct{}{} // done
		close(c)
	}()

	select {
	case <-time.After(time.Duration(300) * time.Millisecond):
		stats := overlord.Stats()

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
		t.Errorf("Unexpected: %s", err)
	}
	end := time.Since(begin)

	if end >= (time.Millisecond * 10 * 12) {
		t.Errorf("It should have finished near 100 ms but it didn't !!")
	}

	if waited {
		t.Errorf("It shouldn't happen")
	}
}
