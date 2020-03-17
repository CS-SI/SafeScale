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
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/acceptance/tools"
	"github.com/stretchr/testify/require"
)

// NOTICE The whole file task_test.go MUST pass UT flawlessly before using it confidently in foreman.go and controller.go

func TestNewTask(t *testing.T) {
	got, err := NewTask()
	require.NotNil(t, got)
	require.Nil(t, err)

	theID, err := got.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	theTask, err := got.Start(nil, nil)
	require.Nil(t, err)
	require.NotNil(t, theTask)

	if theTask != nil {
		if stat, ok := theTask.GetStatus(); ok == nil {
			if stat != DONE {
				t.Errorf("Task should be DONE")
			}
		}
	}

	what, err := got.Start(nil, nil)
	require.NotNil(t, err)
	require.Nil(t, what)

	// err = got.Reset()
	// require.Nil(t, err)
	// require.NotNil(t, got)
}

func TestWaitingGame(t *testing.T) {
	got, err := NewTask()
	require.NotNil(t, got)
	require.Nil(t, err)

	theID, err := got.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	var tarray []Task

	for ind := 0; ind < 800; ind++ {
		got, err := NewTask()
		require.Nil(t, err)
		require.NotNil(t, got)

		theTask, err := got.Start(func(t Task, parameters TaskParameters) (result TaskResult, e error) {
			time.Sleep(time.Duration(tools.RandomInt(50, 250)) * time.Millisecond)
			return "waiting game", nil
		}, nil)
		if err == nil {
			tarray = append(tarray, theTask)
		} else {
			t.Errorf("Shouldn't happen")
		}
	}

	waited := 0
	for _, itta := range tarray {
		res, err := itta.Wait()
		require.Nil(t, err)
		require.NotNil(t, res)
		waited++
	}

	if waited != 800 {
		t.Errorf("Not enough waiting...: %d", waited)
	}
}

func TestSingleTaskTryWait(t *testing.T) {
	single, err := NewTask()
	require.NotNil(t, single)
	require.Nil(t, err)

	single, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(3) * time.Second)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	begin := time.Now()
	waited, res, err := single.TryWait()
	end := time.Since(begin)

	require.False(t, waited)
	require.Nil(t, res)
	require.Nil(t, err)

	if end >= (time.Millisecond * 200) {
		t.Errorf("It should have finished fast but it didn't !!")
	}
}

func TestSingleTaskTryWaitCoreTask(t *testing.T) {
	single, err := NewTask()
	require.NotNil(t, single)
	require.Nil(t, err)

	_, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(30) * time.Millisecond)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	begin := time.Now()
	waited, res, err := single.TryWait()
	end := time.Since(begin)

	require.False(t, waited)
	require.Nil(t, res)
	require.Nil(t, err)

	if end >= (time.Millisecond * 15) {
		t.Errorf("It should have finished fast but it didn't !!")
	}
	single.Close()

	// VPL: Task.Reset() removed, don't understand the goal of this test to update it...
	// _, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
	// 	time.Sleep(time.Duration(30) * time.Millisecond)
	// 	return "Ahhhh", nil
	// }, nil)
	// require.NotNil(t, err)

	err = nil
	for {
		time.Sleep(time.Duration(80) * time.Millisecond)
		ctx, cancel, err := single.GetContext()
		require.Nil(t, err)

		if singleReplacement, err := NewTaskWithContext(ctx, cancel); err == nil {
			single = singleReplacement
			break
		}
	}
	require.Nil(t, err)

	_, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(30) * time.Millisecond)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	// err = single.Reset()
	// require.NotNil(t, single)
	// require.Nil(t, err)

	single, err = NewTask()
	require.NotNil(t, single)
	require.Nil(t, err)
	_, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(30) * time.Millisecond)
		return "Ahhhh", nil
	}, nil)
	require.NotNil(t, err)
	single.Close()
}

func TestSingleTaskTryWaitUsingSubtasks(t *testing.T) {
	single, err := NewTask()
	require.NotNil(t, single)
	require.Nil(t, err)

	_, err = single.StartInSubtask(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(3) * time.Second)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	begin := time.Now()
	res, err := single.Wait()
	end := time.Since(begin)

	_ = end

	require.Nil(t, res)
	require.NotNil(t, err)
	single.Close()
}

func TestSingleTaskTryWaitOK(t *testing.T) {
	single, err := NewTask()
	require.NotNil(t, single)
	require.Nil(t, err)

	single, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(30) * time.Millisecond)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	time.Sleep(time.Duration(50) * time.Millisecond)
	// by now single should succeed

	begin := time.Now()
	waited, res, err := single.TryWait()
	end := time.Since(begin)

	require.True(t, waited)
	require.NotNil(t, res)
	require.Nil(t, err)

	if end >= (time.Millisecond * 100) {
		t.Errorf("It should have finished fast but it didn't !!")
	}

	single.Close()
}

func TestSingleTaskTryWaitKO(t *testing.T) {
	single, err := NewTask()
	require.NotNil(t, single)
	require.Nil(t, err)

	single, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(30) * time.Millisecond)
		return "Ahhhh", fmt.Errorf("chaos")
	}, nil)
	require.Nil(t, err)

	time.Sleep(time.Duration(50) * time.Millisecond)
	// by now single should succeed

	begin := time.Now()
	waited, res, err := single.TryWait()
	end := time.Since(begin)

	require.True(t, waited)
	require.NotNil(t, res)
	require.NotNil(t, err)

	if end >= (time.Millisecond * 150) {
		t.Errorf("It should have finished fast but it didn't !!")
	}
	single.Close()
}

func TestSingleTaskWait(t *testing.T) {
	single, err := NewTask()
	require.NotNil(t, single)
	require.Nil(t, err)

	single, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(30) * time.Millisecond)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	begin := time.Now()
	res, err := single.Wait()
	end := time.Since(begin)

	require.NotNil(t, res)
	require.Nil(t, err)

	if end >= (time.Millisecond*50) || end < (time.Millisecond*20) {
		t.Errorf("It should have finished near 30 ms but it didn't !!")
	}
	single.Close()
}

func TestChildrenWaitingGameWithContextTimeouts(t *testing.T) {
	funk := func(timeout uint, sleep uint, trigger uint, witherror bool) {
		ctx, cafu := context.WithTimeout(context.TODO(), time.Duration(timeout*10)*time.Millisecond)
		defer cafu()

		single, err := NewTaskWithContext(ctx, nil)
		require.NotNil(t, single)
		require.Nil(t, err)

		begin := time.Now()

		single, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
			time.Sleep(time.Duration(sleep*10) * time.Millisecond)
			return "Ahhhh", nil
		}, nil)
		require.Nil(t, err)

		go func() {
			time.Sleep(time.Duration(trigger*10) * time.Millisecond)
			cafu()
		}()

		_, err = single.Wait()
		end := time.Since(begin)
		if err != nil {
			if !strings.Contains(err.Error(), "cancel") {
				t.Errorf("Why so serious ? it's just a failure cancelling a goroutine: %s", err.Error())
			}
		}

		if witherror {
			st, err := single.GetStatus()
			require.Nil(t, err)
			if st != ABORTED {
				t.Errorf("Failure in test: %d, %d, %d, %t", timeout, sleep, trigger, witherror)
			}
			require.True(t, st == ABORTED)
		} else {
			st, err := single.GetStatus()
			require.Nil(t, err)
			if st == ABORTED {
				t.Errorf("Failure in test: %d, %d, %d, %t", timeout, sleep, trigger, witherror)
			}
			require.True(t, st != ABORTED)
		}

		if !((err != nil) == witherror) {
			t.Errorf("Failure in test: %d, %d, %d, %t", timeout, sleep, trigger, witherror)
		}
		require.True(t, (err != nil) == witherror)

		if end > time.Millisecond*time.Duration(10*(trigger+2)) {
			t.Errorf("We waited too much !")
		}
	}
	funk(3, 5, 1, true)
	funk(3, 5, 8, true)
	funk(6, 3, 1, true)
	funk(4, 2, 1, true)
	funk(4, 2, 3, false)
	funk(14, 2, 4, false)
	funk(14, 5, 1, true)
}

func TestChildrenWaitingGameWithContextDeadlines(t *testing.T) {
	funk := func(timeout uint, sleep uint, trigger uint, witherror bool) {
		ctx, cafu := context.WithDeadline(context.TODO(), time.Now().Add(time.Duration(timeout*10)*time.Millisecond))
		single, err := NewTaskWithContext(ctx, nil)
		require.NotNil(t, single)
		require.Nil(t, err)

		begin := time.Now()

		single, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
			time.Sleep(time.Duration(sleep*10) * time.Millisecond)
			return "Ahhhh", nil
		}, nil)
		require.Nil(t, err)

		go func() {
			time.Sleep(time.Duration(trigger*10) * time.Millisecond)
			cafu()
		}()

		_, err = single.Wait()
		end := time.Since(begin)
		if err != nil {
			if !strings.Contains(err.Error(), "cancel") {
				t.Errorf("Why so serious ? it's just a failure cancelling a goroutine: %s", err.Error())
			}
		}

		if !((err != nil) == witherror) {
			t.Errorf("Failure in test: %d, %d, %d, %t", timeout, sleep, trigger, witherror)
		}
		require.True(t, (err != nil) == witherror)

		if end > time.Millisecond*time.Duration(10*(trigger+2)) {
			t.Errorf("We waited too much !")
		}
	}
	funk(3, 5, 1, true)
	funk(3, 5, 9, true)
	funk(5, 3, 1, true)

	funk(5, 1, 3, false)

	funk(7, 3, 1, true)
	funk(4, 1, 3, false)
	funk(14, 2, 4, false)
	funk(14, 4, 2, true)
}

func TestChildrenWaitingGameWithContextCancelfuncs(t *testing.T) {
	funk := func(sleep uint, trigger uint, witherror bool) {
		ctx, cafu := context.WithCancel(context.TODO())
		single, err := NewTaskWithContext(ctx, nil)
		require.NotNil(t, single)
		require.Nil(t, err)

		begin := time.Now()

		single, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
			time.Sleep(time.Duration(sleep*10) * time.Millisecond)
			return "Ahhhh", nil
		}, nil)
		require.Nil(t, err)

		go func() {
			time.Sleep(time.Duration(trigger*10) * time.Millisecond)
			cafu()
		}()

		_, err = single.Wait()
		end := time.Since(begin)
		if err != nil {
			if !strings.Contains(err.Error(), "cancel") {
				t.Errorf("Why so serious ? it's just a failure cancelling a goroutine: %s", err.Error())
			}
		}

		require.True(t, (err != nil) == witherror)

		if end > time.Millisecond*time.Duration(10*(trigger+2)) {
			t.Errorf("We waited too much !")
		}
	}
	funk(5, 1, true)
	funk(5, 8, false)
}

func TestStChildrenWaitingGameWithTimeouts(t *testing.T) {
	overlord, err := NewTask()
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	var tasks []Task
	for ind := 0; ind < 10; ind++ {
		incentive, err := overlord.StartInSubtask(func(t Task, parameters TaskParameters) (result TaskResult, e error) {
			rint := tools.RandomInt(3, 5)
			time.Sleep(time.Duration(rint) * time.Millisecond)

			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		} else {
			tasks = append(tasks, incentive)
		}
	}

	begin := time.Now()
	for _, war := range tasks {
		_, err = war.Wait()
		war.Close()
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
	}
	end := time.Since(begin)

	if end >= (time.Millisecond * 15) {
		t.Errorf("It should have finished near 15 ms but it didn't !!")
	}
}
