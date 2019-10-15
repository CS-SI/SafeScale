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
	"context"
	"github.com/gophercloud/gophercloud/acceptance/tools"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

// FIXME The whole file task_test.go MUST pass UT flawlessly before using it confidently in foreman.go and controller.go

func TestNewTask(t *testing.T) {
	got, err := NewTask(nil)
	require.NotNil(t, got)
	require.Nil(t, err)

	theId, err := got.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theId)

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

	what, err = got.Reset()
	require.Nil(t, err)
	require.NotNil(t, what)
}

func TestWaitingGame(t *testing.T) {
	got, err := NewTask(nil)
	require.NotNil(t, got)
	require.Nil(t, err)

	theId, err := got.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theId)

	tarray := []Task{}

	for ind := 0; ind < 800; ind++ {
		got, err := NewTask(nil)
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
	single, err := NewTask(nil)
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
	single, err := NewTask(nil)
	require.NotNil(t, single)
	require.Nil(t, err)

	_, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
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

	_, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(3) * time.Second)
		return "Ahhhh", nil
	}, nil)
	require.NotNil(t, err)

	time.Sleep(time.Duration(5) * time.Second)

	single, err = single.Reset()
	require.Nil(t, err)

	_, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(3) * time.Second)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	_, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(3) * time.Second)
		return "Ahhhh", nil
	}, nil)
	require.NotNil(t, err)
}

func TestSingleTaskTryWaitUsingSubtasks(t *testing.T) {
	single, err := NewTask(nil)
	require.NotNil(t, single)
	require.Nil(t, err)

	_, err = single.StartInSubTask(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
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
}

func TestSingleTaskTryWaitOK(t *testing.T) {
	single, err := NewTask(nil)
	require.NotNil(t, single)
	require.Nil(t, err)

	single, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(3) * time.Second)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	time.Sleep(time.Duration(5) * time.Second)
	// by now single should succeed

	begin := time.Now()
	waited, res, err := single.TryWait()
	end := time.Since(begin)

	require.True(t, waited)
	require.NotNil(t, res)
	require.Nil(t, err)

	if end >= (time.Millisecond * 200) {
		t.Errorf("It should have finished fast but it didn't !!")
	}
}

func TestSingleTaskWait(t *testing.T) {
	single, err := NewTask(nil)
	require.NotNil(t, single)
	require.Nil(t, err)

	single, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(3) * time.Second)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	begin := time.Now()
	res, err := single.Wait()
	end := time.Since(begin)

	require.NotNil(t, res)
	require.Nil(t, err)

	if end >= (time.Second*4) || end < (time.Second) {
		t.Errorf("It should have finished near 3s but it didn't !!")
	}
}

func TestChildrenWaitingGameWithContextTimeouts(t *testing.T) {
	funk := func(timeout uint, sleep uint, trigger uint, witherror bool) {
		ctx, cafu := context.WithTimeout(context.TODO(), time.Duration(timeout*10)*time.Millisecond)
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
			st, _ := single.GetStatus()
			require.True(t, st == ABORTED)
		} else {
			st, _ := single.GetStatus()
			require.True(t, st != ABORTED)
		}
		require.True(t, (err != nil) == witherror)

		if end > time.Millisecond*time.Duration(10*(trigger+1)) {
			t.Errorf("We waited too much !")
		}
	}
	funk(3, 5, 1, true)
	funk(3, 5, 8, true)
	funk(6, 3, 1, true)
	funk(4, 2, 1, true)
	funk(4, 2, 3, false)
	funk(14, 2, 4, false)
	funk(14, 4, 2, true)
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

		require.True(t, (err != nil) == witherror)

		if end > time.Millisecond*time.Duration(10*(trigger+1)) {
			t.Errorf("We waited too much !")
		}
	}
	funk(3, 5, 1, true)
	funk(3, 5, 8, true)
	funk(5, 2, 1, true)

	funk(5, 2, 3, false)

	funk(4, 2, 1, true)
	funk(4, 2, 3, false)
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

		if end > time.Millisecond*time.Duration(10*(trigger+1)) {
			t.Errorf("We waited too much !")
		}
	}
	funk(5, 1, true)
	funk(5, 8, false)
}

func TestStChildrenWaitingGameWithTimeouts(t *testing.T) {
	overlord, err := NewTask(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theId, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theId)

	var tasks []Task
	for ind := 0; ind < 10; ind++ {
		incentive, err := overlord.StartInSubTask(func(t Task, parameters TaskParameters) (result TaskResult, e error) {
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
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
	}
	end := time.Since(begin)

	if end >= (time.Millisecond * 11) {
		t.Errorf("It should have finished in 10s but it didn't !!")
	}
}
