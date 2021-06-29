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
	"io/ioutil"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// NOTICE The whole file task_test.go MUST pass UT flawlessly before using it confidently in foreman.go and controller.go

func TestCreateVoidTask(t *testing.T) {
	ta, err := VoidTask()
	require.NotNil(t, ta)
	require.Nil(t, err)
}

func TestWaitReadyTask(t *testing.T) {
	ta, err := VoidTask()
	require.NotNil(t, ta)
	require.Nil(t, err)

	su, err := ta.IsSuccessful()
	require.False(t, su)
	require.NotNil(t, err)

	_, tr, err := ta.WaitFor(10 * time.Second)
	require.Nil(t, tr)
	require.NotNil(t, err)

	_, tr, err = ta.TryWait()
	require.Nil(t, tr)
	require.NotNil(t, err)

	tr, err = ta.Wait()
	require.Nil(t, tr)
	require.NotNil(t, err)
}

func TestNewTask(t *testing.T) {
	got, err := NewUnbreakableTask()
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
}

func TestWaitingGame(t *testing.T) {
	got, err := NewUnbreakableTask()
	require.NotNil(t, got)
	require.Nil(t, err)

	theID, err := got.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	var tarray []Task

	for ind := 0; ind < 800; ind++ {
		got, err := NewUnbreakableTask()
		require.Nil(t, err)
		require.NotNil(t, got)

		theTask, err := got.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(RandomInt(50, 250)) * time.Millisecond)
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

	aerr, xerr := got.GetLastError()
	require.Nil(t, xerr)
	require.Nil(t, aerr)

	if waited != 800 {
		t.Errorf("Not enough waiting...: %d", waited)
	}
}

func TestOneWaitingForGame(t *testing.T) {
	got, err := NewUnbreakableTask()
	require.NotNil(t, got)
	require.Nil(t, err)

	theID, err := got.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	_, err = got.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(RandomInt(50, 250)) * time.Millisecond)
		return "waiting game", nil
	}, nil)
	if err != nil {
		t.Errorf("Shouldn't happen")
	}

	good, res, err := got.WaitFor(4 * time.Second)
	require.Nil(t, err)
	require.NotNil(t, res)
	require.True(t, good)
}

// TestTaskCantBeReused ensures that a started Task cannot be reused
func TestTaskCantBeReused(t *testing.T) {
	got, err := NewUnbreakableTask()
	require.NotNil(t, got)
	require.Nil(t, err)

	theID, err := got.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	_, err = got.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(RandomInt(50, 250)) * time.Millisecond)
		return "waiting game", nil
	}, nil)
	if err != nil {
		t.Errorf("Shouldn't happen")
	}

	res, err := got.Wait()
	require.Nil(t, err)
	require.NotNil(t, res)

	tr, xerr := got.GetResult()
	require.Nil(t, xerr)
	require.NotNil(t, tr)

	_, err = got.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(RandomInt(50, 250)) * time.Millisecond)
		return "waiting game", nil
	}, nil, 10*time.Millisecond)
	if err != nil {
		// If by design a task cannot be reused, its error should be more specific, not ready could also happen in other situations
		t.Errorf("shouldn't happen: %v", err)
	}

	res, err = got.Wait()
	require.Nil(t, err)
	require.NotNil(t, res)

	tr, xerr = got.GetResult()
	require.Nil(t, xerr)
	require.NotNil(t, tr)
}

func TestResultCheck(t *testing.T) {
	got, err := NewUnbreakableTask()
	require.NotNil(t, got)
	require.Nil(t, err)

	theID, err := got.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	_, err = got.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(RandomInt(50, 250)) * time.Millisecond)
		return "waiting game", nil
	}, nil, 10*time.Millisecond)
	if err != nil {
		t.Errorf("Shouldn't happen")
	}

	res, err := got.Wait()
	require.NotNil(t, err)
	require.NotNil(t, res)

	tr, xerr := got.GetResult()
	require.Nil(t, xerr)
	// Why would be this a problem ?, GetResult() was coded when the only states were RUNNING and DONE, long long time ago
	// this is no longer true, GetResult needs review
	require.NotNil(t, tr)
}

func TestResultCheckOfAbortedTask(t *testing.T) {
	got, xerr := NewTask()
	require.NotNil(t, got)
	require.Nil(t, xerr)

	theID, xerr := got.GetID()
	require.Nil(t, xerr)
	require.NotEmpty(t, theID)

	_, xerr = got.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		tempo := time.Duration(RandomInt(50, 250)) * time.Millisecond
		for i := 0; i < 100; i++ {
			if t.Aborted() {
				return "killed", fail.AbortedError(nil, "killed by parent")
			}
			time.Sleep(tempo)
		}
		return "waiting game", nil
	}, nil, 400*time.Millisecond)
	if xerr != nil {
		t.Errorf("Shouldn't happen")
	}

	xerr = got.Abort()
	require.Nil(t, xerr)

	st, xerr := got.GetStatus()
	require.Nil(t, xerr)
	if st != ABORTED {
		t.FailNow()
	}

	// Using GetResult() is invalid, Task has not been waited
	tr, xerr := got.GetResult()
	require.NotNil(t, xerr)
	require.Nil(t, tr)

	res, xerr := got.Wait()
	require.NotNil(t, xerr)
	require.NotNil(t, res)
	// Now that we waited the Task, GetResult() returns useful information

	tr, xerr = got.GetResult()
	require.Nil(t, xerr)
	require.NotNil(t, tr)

	st, xerr = got.GetStatus()
	if st != DONE {
		t.FailNow()
	}
}

func TestWaitingForGame(t *testing.T) {
	got, err := NewUnbreakableTask()
	require.NotNil(t, got)
	require.Nil(t, err)

	theID, err := got.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	var tarray []Task

	for ind := 0; ind < 800; ind++ {
		got, err := NewUnbreakableTask()
		require.Nil(t, err)
		require.NotNil(t, got)

		theTask, err := got.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(RandomInt(50, 250)) * time.Millisecond)
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
		good, res, err := itta.WaitFor(4 * time.Second)
		require.Nil(t, err)
		require.NotNil(t, res)
		require.True(t, good)
		waited++
	}

	if waited != 800 {
		t.Errorf("Not enough waiting...: %d", waited)
	}
}

func TestSingleTaskTryWait(t *testing.T) {
	single, err := NewUnbreakableTask()
	require.NotNil(t, single)
	require.Nil(t, err)

	single, err = single.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
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
	single, err := NewUnbreakableTask()
	require.NotNil(t, single)
	require.Nil(t, err)

	_, err = single.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
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

	_, err = single.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(30) * time.Millisecond)
		return "Ahhhh", nil
	}, nil)
	require.NotNil(t, err)

	err = nil
	for {
		time.Sleep(time.Duration(80) * time.Millisecond)
		ctx := single.GetContext()
		require.NotNil(t, ctx)

		if singleReplacement, err := NewTaskWithContext(ctx); err == nil {
			single = singleReplacement
			break
		}
	}
	require.Nil(t, err)

	_, err = single.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(30) * time.Millisecond)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	_, err = single.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(30) * time.Millisecond)
		return "Ahhhh", nil
	}, nil)
	require.NotNil(t, err)
}

func TestSingleTaskTryWaitOK(t *testing.T) {
	single, err := NewUnbreakableTask()
	require.NotNil(t, single)
	require.Nil(t, err)

	single, err = single.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
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
}

func TestSingleTaskRun(t *testing.T) {
	single, err := NewUnbreakableTask()
	require.NotNil(t, single)
	require.Nil(t, err)

	res, err := single.Run(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(30) * time.Millisecond)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	require.NotNil(t, res)
	require.Nil(t, err)
}

func TestSingleTaskRunThatFails(t *testing.T) {
	single, err := NewUnbreakableTask()
	require.NotNil(t, single)
	require.Nil(t, err)

	res, err := single.Run(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(30) * time.Millisecond)
		return "Ahhhh", fail.NewError("issues")
	}, nil)
	require.NotNil(t, err)
	require.NotNil(t, res)
}

func TestSingleTaskTryWaitKO(t *testing.T) {
	single, err := NewUnbreakableTask()
	require.NotNil(t, single)
	require.Nil(t, err)

	single, err = single.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(30) * time.Millisecond)
		return "Ahhhh", fail.NewError("chaos")
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
}

func TestSingleTaskWait(t *testing.T) {
	single, err := NewUnbreakableTask()
	require.NotNil(t, single)
	require.Nil(t, err)

	single, err = single.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
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
}

func TestChildrenWaitingGameWithContextTimeouts(t *testing.T) {
	funk := func(ind int, timeout time.Duration, sleep time.Duration, trigger time.Duration, errorExpected bool) {
		ctx, cafu := context.WithTimeout(context.TODO(), timeout)
		defer cafu()

		single, err := NewTaskWithContext(ctx)
		require.NotNil(t, single)
		require.Nil(t, err)

		begin := time.Now()

		single, err = single.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			tempo := sleep / 100
			for i := 0; i < 100; i++ {
				if t.Aborted() {
					return "aborted", fail.AbortedError(nil)
				}
				time.Sleep(tempo)
			}
			return "Ahhhh", nil
		}, nil)
		require.Nil(t, err)

		go func() {
			time.Sleep(trigger)
			cafu()
		}()

		_, err = single.Wait()
		end := time.Since(begin)
		if err != nil {
			switch err.(type) {
			case *fail.ErrAborted:
			case *fail.ErrTimeout:
			default:
				t.Errorf("Unexpected error occurred: %s (%s)", err.Error(), reflect.TypeOf(err).String())
			}
		}

		if !((err != nil) == errorExpected) {
			t.Errorf("Failure in test %d (in error expected): %v, %v, %v, %t", ind, timeout, sleep, trigger, errorExpected)
		}

		// the minimum of the 3 wins, so
		min := math.Min(math.Min(float64(timeout), float64(sleep)), float64(trigger))

		if end > time.Duration(min*14/10)*time.Millisecond {
			t.Logf("Failure in test %d: %v, %v, %v, %t: We waited too much! %v > %v", ind, timeout, sleep, trigger, errorExpected, end, trigger*14/10*time.Millisecond)
		}
	}

	// No errors here, look at TestChildrenWaitingGameWithContextCancelfuncs for more information
	// there is a performance degradation problem in Task/TaskGroup that impact the timings
	// example:
	// 140, 20, 50, false -> after the 20ms sleep it comes a cancel at 50ms, like twice the time later, yet we didn't finish the job
	// that's our fault (a go function with a select listening to Done nails the ms), so the cancel hits, error is true and the test fails
	// 140, 20, 120, false -> but if we put the cancel far enough, it works, returning a false
	//
	// is this critical ?, maybe not today but...
	// big problems have small beginnings...

	funk(1, 30*time.Millisecond, 50*time.Millisecond, 10*time.Millisecond, true)    // canceled
	funk(2, 10*time.Millisecond, 50*time.Millisecond, 30*time.Millisecond, true)    // timeout
	funk(3, 30*time.Millisecond, 50*time.Millisecond, 80*time.Millisecond, true)    // timeout
	funk(4, 80*time.Millisecond, 50*time.Millisecond, 10*time.Millisecond, true)    // canceled
	funk(5, 40*time.Millisecond, 20*time.Millisecond, 10*time.Millisecond, true)    // canceled
	funk(6, 40*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, false)   // cancel is triggered AFTER we are done (in 20ms), less that the timeout -> so no error
	funk(7, 140*time.Millisecond, 20*time.Millisecond, 40*time.Millisecond, false)  // same thing here
	funk(8, 140*time.Millisecond, 20*time.Millisecond, 100*time.Millisecond, false) // same thing here
	funk(9, 140*time.Millisecond, 20*time.Millisecond, 120*time.Millisecond, false) // same thing here
	funk(10, 140*time.Millisecond, 20*time.Millisecond, 50*time.Millisecond, false) // same thing here
	funk(11, 140*time.Millisecond, 50*time.Millisecond, 10*time.Millisecond, true)  // canceled
}

func TestChildrenWaitingGameWithContextDeadlines(t *testing.T) {
	funk := func(ind int, timeout uint, sleep uint, trigger uint, errorExpected bool) {
		ctx, cafu := context.WithDeadline(context.TODO(), time.Now().Add(time.Duration(timeout*10)*time.Millisecond))
		require.NotNil(t, ctx)
		require.NotNil(t, cafu)

		single, xerr := NewTaskWithContext(ctx)
		require.NotNil(t, single)
		require.Nil(t, xerr)

		singleID := fmt.Sprintf("/single-%d", ind)
		xerr = single.SetID(singleID)
		require.Nil(t, xerr)

		begin := time.Now()

		_, xerr = single.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			dur := time.Duration(sleep*10) * time.Millisecond
			tempo := dur / 100
			var (
				i       int
				aborted bool
			)
			for ; i < 100; i++ {
				aborted = t.Aborted()
				if aborted {
					break
				}
				time.Sleep(tempo)
			}

			fmt.Printf("%s: sleeped %v\n", singleID, time.Duration(i)*tempo+time.Duration(sleep)*10*time.Millisecond)
			if aborted {
				return "Ahhhh (aborted)", fail.AbortedError(nil)
			}

			return "Ahhhh", nil
		}, nil)
		require.Nil(t, xerr)

		go func() {
			time.Sleep(time.Duration(trigger*10) * time.Millisecond)
			cafu()
		}()

		_, xerr = single.Wait()
		end := time.Since(begin)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrAborted:
			case *fail.ErrTimeout:
				// expected error types
			default:
				t.Errorf("Unexpected error occurred in test #%d: %s (%s)", ind, xerr.Error(), reflect.TypeOf(xerr).String())
			}
		}

		if !((xerr != nil) == errorExpected) {
			t.Errorf("Failure in test %d: %d, %d, %d, %t", ind, timeout, sleep, trigger, errorExpected)
		}
		require.True(t, (xerr != nil) == errorExpected)

		// the minimum of the 3 wins, so
		min := math.Min(math.Min(float64(timeout), float64(sleep)), float64(trigger))

		if end > time.Millisecond*time.Duration(10*(min)*14/10) {
			t.Logf("Failure in test %d: %v, %v, %v, %t: We waited too much! %v > %v", ind, timeout, sleep, trigger, errorExpected, end, time.Duration(min)*10*14/10*time.Millisecond)
		}
	}
	funk(1, 30, 50, 10, true)
	funk(2, 30, 50, 90, true)
	funk(3, 50, 30, 10, true)
	funk(4, 50, 10, 30, false)
	funk(5, 70, 30, 10, true)
	funk(6, 40, 10, 30, false)
	funk(7, 140, 20, 40, false)
	funk(8, 140, 40, 20, true)
}

func TestChildrenWaitingGameWithContextCancelfuncs(t *testing.T) {
	funk := func(ind int, sleep uint, trigger uint, errorExpected bool) {
		ctx, cafu := context.WithCancel(context.TODO())
		single, xerr := NewTaskWithContext(ctx)
		require.NotNil(t, single)
		require.Nil(t, xerr)

		xerr = single.SetID(fmt.Sprintf("single-%d", ind))
		require.Nil(t, xerr)

		begin := time.Now()
		var singleEnd time.Duration
		single, xerr = single.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			singleBegin := time.Now()
			dur := time.Duration(sleep*10) * time.Millisecond
			tempo := dur / 100
			for i := 0; i < 100; i++ {
				if t.Aborted() {
					return "Ahhhh (aborted)", fail.AbortedError(nil)
				}
				time.Sleep(tempo)
			}
			singleEnd = time.Since(singleBegin)
			return "Ahhhh", nil
		}, nil)
		require.Nil(t, xerr)

		go func() {
			time.Sleep(time.Duration(trigger*10) * time.Millisecond)
			cafu()
		}()

		res, xerr := single.Wait()
		_ = res
		fmt.Printf("singleDuration=%v\n", singleEnd)
		end := time.Since(begin)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrAborted:
			default:
				t.Errorf("Unexpected error occurred in %s (%s)", xerr.Error(), reflect.TypeOf(xerr).String())
			}
		}

		if !((xerr != nil) == errorExpected) {
			t.Errorf("Failure in test %d: %v, %v, %t: wrong error!", ind, sleep, trigger, errorExpected)
		}

		if trigger < sleep {
			if end > time.Millisecond*time.Duration(10*(trigger*12)/10) {
				t.Logf("Warning in test %d: %v, %v, %t: We waited too much! %v > %v", ind, sleep, trigger, errorExpected, end, time.Duration(trigger*12/10)*10*time.Millisecond)
			}
		} else {
			if end > time.Millisecond*time.Duration(10*(sleep*12)/10) {
				t.Logf("Warning in test %d: %v, %v, %t: We waited too much! %v > %v", ind, sleep, trigger, errorExpected, end, time.Duration(sleep*12/10)*10*time.Millisecond)
			}
		}
	}

	// tests are right, errorExpected it what it should be
	// previous versions got the work done fast enough, now we don't, why ?
	funk(1, 5, 1, true)
	funk(2, 5, 8, false)   // this is a performance degradation, it worked before, look at the 2 next tests, this test should work like the next ones, it does not because the timings of Wait are degraded
	funk(3, 5, 80, false)  // this test and the previous should be equivalent
	funk(4, 50, 80, false) // *10 the timings (vs 5, 8) and the result changes ??
	funk(5, 50, 10, true)
	funk(6, 50, 80, false)
	funk(7, 50, 300, false)
	funk(8, 50, 3000, false)
	funk(9, 50, 6000, false)
	funk(10, 50, 48, true) // also look at this tests, from test 12 to 17 there should be no errors, but we are not fast / precise enough -> errors
	funk(11, 50, 49, true)
	funk(12, 50, 51, false) // Abort arrived before end of Task!
	funk(13, 50, 52, false)
	funk(14, 50, 53, false)
	funk(15, 50, 54, false)
	funk(16, 50, 55, false)
	funk(17, 50, 56, false) // if we go far enough, no errors
	funk(18, 50, 57, false) // if we go far enough, no errors
	funk(19, 50, 58, false) // if we go far enough, no errors
	funk(20, 50, 59, false) // if we go far enough, no errors
}

func TestDoesAbortReallyAbortOrIsJustFakeNews(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	single, xerr := NewTask()
	require.NotNil(t, single)
	require.Nil(t, xerr)

	single, xerr = single.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		for {
			time.Sleep(time.Duration(10) * time.Millisecond)
			status, xerr := t.GetStatus()
			if xerr != nil {
				return "Big failure...", nil
			}
			if status == ABORTED || status == TIMEOUT {
				break
			}

			fmt.Println("Forever young...")
		}
		return "I want to be forever young", nil
	}, nil, time.Duration(200)*time.Millisecond)
	require.Nil(t, xerr)

	time.Sleep(time.Duration(300) * time.Millisecond)
	// by now single should have finished with timeouts, so...

	stat, err := single.GetStatus()
	if err != nil {
		t.Errorf("Problem retrieving status ?")
	}

	if stat != TIMEOUT {
		t.Errorf("Where is the timeout ??, that's the textbook definition")
	}

	xerr = single.Abort()
	if xerr != nil {
		t.Errorf("How could it fail if the task was already finished longtime ago ?")
	}

	_, xerr = single.Wait()
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrTimeout); !ok {
			t.Errorf("Where are the timeout errors ??: %s", spew.Sdump(xerr))
		}
	}
	require.NotNil(t, xerr)

	// Nothing wrong should happen after this point...
	time.Sleep(time.Duration(100) * time.Millisecond)

	_ = w.Close()
	_, _ = ioutil.ReadAll(r)
	os.Stdout = rescueStdout
}

func TestLikeBeforeWithoutAbort(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	single, xerr := NewTask()
	require.NotNil(t, single)
	require.Nil(t, xerr)

	single, xerr = single.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		for {
			time.Sleep(time.Duration(10) * time.Millisecond)
			status, xerr := t.GetStatus()
			if xerr != nil {
				return "Big failure...", nil
			}
			if status == ABORTED || status == TIMEOUT {
				break
			}

			fmt.Println("Forever young...")
		}
		return "I want to be forever young", nil
	}, nil, time.Duration(200)*time.Millisecond)
	require.Nil(t, xerr)

	time.Sleep(time.Duration(300) * time.Millisecond)
	// by now single should have finished with timeouts, so...

	stat, err := single.GetStatus()
	if err != nil {
		t.Errorf("Problem retrieving status ?")
	}

	if stat != TIMEOUT {
		t.Errorf("Where is the timeout ??, that's the textbook definition")
	}

	_, xerr = single.Wait()
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrTimeout); !ok {
			t.Errorf("Where are the timeout errors ??: %s", spew.Sdump(xerr))
		}
	}
	require.NotNil(t, xerr)

	// Nothing wrong should happen after this point...
	time.Sleep(time.Duration(100) * time.Millisecond)

	_ = w.Close()
	_, _ = ioutil.ReadAll(r)
	os.Stdout = rescueStdout
}

func TestLikeBeforeWithoutAbortButContext(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	bg := context.Background()
	bgt, cancelBgt := context.WithTimeout(bg, time.Duration(30)*time.Millisecond)
	defer cancelBgt()

	single, xerr := NewTaskWithContext(bgt)
	require.NotNil(t, single)
	require.Nil(t, xerr)

	single, xerr = single.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		for {
			time.Sleep(time.Duration(10) * time.Millisecond)
			status, xerr := t.GetStatus()
			if xerr != nil {
				return "Big failure...", nil
			}
			if status == ABORTED || status == TIMEOUT {
				break
			}

			fmt.Println("Forever young...")
		}
		return "I want to be forever young", nil
	}, nil, time.Duration(200)*time.Millisecond)
	if xerr != nil {
		t.Errorf("This shouldn't happen")
	}
	require.Nil(t, xerr)

	time.Sleep(time.Duration(300) * time.Millisecond)
	// by now single should have finished with timeouts, so...

	stat, err := single.GetStatus()
	if err != nil {
		t.Errorf("Problem retrieving status ?")
	}

	if stat != TIMEOUT {
		t.Errorf("Where is the timeout ??, that's the textbook definition")
	}

	_, xerr = single.Wait()
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrTimeout); !ok { // This exception come from ctx, but it's the wrong type -> ErrAborted, and it should be an ErrTimeout
			t.Errorf("Where are the timeout errors ??: %s", spew.Sdump(xerr))
		}
	}
	if xerr == nil {
		t.Errorf("It should have finished with errors !")
		require.NotNil(t, xerr)
	}

	// Nothing wrong should happen after this point...
	time.Sleep(time.Duration(100) * time.Millisecond)

	_ = w.Close()
	_, _ = ioutil.ReadAll(r)
	os.Stdout = rescueStdout
}

func TestLikeBeforeWithoutLettingFinish(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	single, xerr := NewTask()
	require.NotNil(t, single)
	require.Nil(t, xerr)

	single, xerr = single.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		var aborted bool
		for {
			time.Sleep(time.Duration(10) * time.Millisecond)
			aborted = t.Aborted()
			if aborted {
				break
			}

			fmt.Println("Forever young...")
		}
		if aborted {
			fmt.Println("There can be only one...")
			return "There can be only one", fail.AbortedError(nil)
		}

		return "I want to be forever young", nil
	}, nil, time.Duration(200)*time.Millisecond)
	require.Nil(t, xerr)

	_, xerr = single.Wait()
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			// expected
		default:
			t.Errorf("Unexpected error %v (%s)", xerr, reflect.TypeOf(xerr).String())
		}
	}
	require.NotNil(t, xerr)

	// Nothing wrong should happen after this point...
	time.Sleep(time.Duration(100) * time.Millisecond)

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	// Here, last 2 lines of the output should be:
	// Forever young...
	// Aborted

	outString := string(out)
	nah := strings.Split(outString, "\n")

	if !strings.Contains(nah[len(nah)-3], "Forever young") {
		t.Fail()
	}

	if !strings.Contains(nah[len(nah)-2], "only one") {
		t.Fail()
	}
}

func TestCheckTimeoutStatus(t *testing.T) {
	single, xerr := NewTask()
	require.NotNil(t, single)
	require.Nil(t, xerr)

	_, xerr = single.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		for {
			time.Sleep(time.Duration(10) * time.Millisecond)
			if t.Aborted() {
				break
			}
			fmt.Println("Forever young...")
		}
		return "I want to be forever young", nil
	}, nil, time.Duration(40)*time.Millisecond)
	require.Nil(t, xerr)

	time.Sleep(time.Duration(100) * time.Millisecond)

	_, xerr = single.Wait()
	require.NotNil(t, xerr)

	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			// This is expected
		default:
			t.Errorf("Unexpected error '%s'", reflect.TypeOf(xerr).String())
		}
	}
}

func TestStartWithTimeoutWithTimeToFinish(t *testing.T) {
	single, xerr := NewTask()
	require.NotNil(t, single)
	require.Nil(t, xerr)

	single, xerr = single.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		for {
			time.Sleep(time.Duration(10) * time.Millisecond)
			if t.Aborted() {
				return nil, fail.AbortedError(nil)
			}
			fmt.Println("Forever young...")
		}
		return "I want to be forever young", nil
	}, nil, time.Duration(400)*time.Millisecond)
	require.Nil(t, xerr)

	time.Sleep(time.Duration(100) * time.Millisecond)
	xerr = single.Abort()
	if xerr != nil {
		t.Errorf("There was a failure aborting: %v", xerr)
	}

	// Nothing wrong should happen after this point...
	time.Sleep(time.Duration(100) * time.Millisecond)

	_, xerr = single.Wait()
	require.NotNil(t, xerr)
	switch xerr.(type) {
	case *fail.ErrAborted:
		// expected
	default:
		t.Errorf("unexpected error '%s'", reflect.TypeOf(xerr).String())
	}
}

func TestStartWithTimeoutThatTimeouts(t *testing.T) {
	single, xerr := NewTask()
	require.NotNil(t, single)
	require.Nil(t, xerr)

	single, xerr = single.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		for {
			time.Sleep(time.Duration(10) * time.Millisecond)
			status, _ := t.GetStatus()
			if status == ABORTED || status == TIMEOUT {
				break
			}
			fmt.Println("Forever young...")
		}
		return "I want to be forever young", nil
	}, nil, time.Duration(100)*time.Millisecond)
	require.Nil(t, xerr)

	// sleep more than duration defined in the timeout...
	time.Sleep(time.Duration(150) * time.Millisecond)

	// Abort, but too late, task already finished with timeout (hopefully)
	xerr = single.Abort()
	if xerr != nil {
		t.Errorf("There was a failure aborting: %v", xerr)
	}

	_, xerr = single.Wait()
	if xerr == nil {
		t.Errorf("Wait should have failed but didn't")
	} else {
		if _, ok := xerr.(*fail.ErrTimeout); !ok {
			t.Errorf("This should have failed by design with a Timeout error")
		}
	}
}

func TestTwoRoots(t *testing.T) {
	a, err := RootTask()
	require.NotNil(t, a)
	require.Nil(t, err)

	b, err := RootTask()
	require.NotNil(t, b)
	require.Nil(t, err)

	theyAre := reflect.DeepEqual(a, b)
	require.True(t, theyAre)

	_ = b.SetID("1")
	_ = a.SetID("2")
	theyAre = reflect.DeepEqual(a, b)
	require.True(t, theyAre)
}

// VPL: now that Task is working on this matter, maybe we should prepare a benchmark to compare Task method and this method?
func TestAbortButThisTimeUsingTrueAbortChannel(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	single, xerr := NewTask()
	require.NotNil(t, single)
	require.Nil(t, xerr)

	trueAbort := make(chan struct{})
	single, xerr = single.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		forever := true
		for forever {
			select {
			case <-trueAbort:
				fmt.Println("I'm Gotham's reckoning. Here to end the borrowed time you all have been living on. ")
				forever = false
				break
			default:
				time.Sleep(time.Duration(10) * time.Millisecond)
				fmt.Println("Forever young...")
			}
		}
		return "I want to be forever young", nil
	}, nil, time.Duration(40)*time.Millisecond)
	require.Nil(t, xerr)

	time.Sleep(time.Duration(200) * time.Millisecond)

	xerr = single.Abort()
	trueAbort <- struct{}{}

	time.Sleep(time.Duration(50) * time.Millisecond)
	fmt.Println("Aborted")

	_, xerr = single.Wait()
	require.NotNil(t, xerr)

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	// Here, last 3 lines of the output should be:
	// Forever young...
	// I'm Gotham's reckoning. Here to end the borrowed time you all have been living on.
	// Aborted

	outString := string(out)

	nah := strings.Split(outString, "\n")

	if !strings.Contains(nah[len(nah)-4], "Forever young") {
		t.Fail()
	}

	if !strings.Contains(nah[len(nah)-3], "I'm Gotham's reckoning") {
		t.Fail()
	}

	if !strings.Contains(nah[len(nah)-2], "Aborted") {
		t.Fail()
	}

	if t.Failed() {
		fmt.Println(outString)
	}
}

func TestAbortThatActuallyTakeTimeCleaningUpAndFailWhenWeAlreadyStartedWaiting(t *testing.T) {
	enough := false
	iter := 0
	panicReported := false

	for !enough {
		iter++
		if iter > 12 {
			break
		}

		t.Log("--- Next ---") // Each time we iterate we see this line, sometimes this doesn't fail at 1st iteration
		single, xerr := NewTask()
		require.NotNil(t, single)
		require.Nil(t, xerr)

		bailout := make(chan string, 80) // a buffered channel

		_, xerr = single.Start(
			func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
				for { // do some work, then look for aborted, again and again
					// some work
					time.Sleep(time.Duration(RandomInt(20, 30)) * time.Millisecond)
					if t.Aborted() {
						// Cleaning up first before leaving... ;)
						time.Sleep(time.Duration(RandomInt(100, 800)) * time.Millisecond)
						break
					}
				}

				// We are using the classic 'send on closed channel' trick to see if Wait actually waits until everyone is DONE.
				// If it does we will never see a panic, but if Abort doesn't mean TellYourChildrenToAbort but
				// actually means AbortYourChildrenAndQuitNOWWithoutWaiting, then we have a problem
				acha := parameters.(chan string)
				acha <- "Bailing out"

				// flip a coin, true and we panic, false we don't
				if RandomInt(0, 2) == 1 {
					return "mistakes happen", fail.NewError("It was head")
				}

				return "who cares", nil
			}, bailout,
		)
		require.Nil(t, xerr)

		// after this, some tasks will already be looking for ABORT signals
		time.Sleep(time.Duration(65) * time.Millisecond)

		go func() {
			// this will actually start after wait
			time.Sleep(time.Duration(100) * time.Millisecond)

			// let's have fun
			xerr := single.Abort()
			require.Nil(t, xerr)
		}()

		/*res*/
		_, xerr = single.Wait() // 100 ms after this, .Abort() should hit
		if xerr != nil {
			t.Logf("Wait reports a failure: %s", reflect.TypeOf(xerr).String()) // Of course, we did !!, we induced a panic !! didn't we ?
			switch cerr := xerr.(type) {
			case *fail.ErrAborted:
				consequences := cerr.Consequences()
				if len(consequences) > 0 {
					t.Log("Task reports consequences of the Abort:")
					for _, v := range consequences {
						logged := false
						switch cerr := v.(type) {
						case *fail.ErrAborted:
							consequences := cerr.Consequences()
							if len(consequences) > 0 {
								t.Logf("aborted with consequence: %v (%s)", v, reflect.TypeOf(v).String())
								logged = true
							}
						default:
						}
						if !logged {
							t.Logf("%v (%s)", v, reflect.TypeOf(v).String())
						}
					}
				} else {
					t.Log("Task reports no consequences of the Abort")
				}

				if !strings.Contains(spew.Sdump(consequences), "panic happened") {
					t.Logf("no panic reported by Task")
				} else {
					t.Logf("Task reports panic in consequences!!!")
					panicReported = true
				}
			// or maybe we were fast enough and we are quitting only because of Abort, but no problem, we have more iterations...
			case *fail.ErrRuntimePanic:
				t.Logf("Task generates a panic!!!")
				panicReported = true
			case *fail.ErrUnqualified:
				// can occur, nothing more to say
			default:
				t.Errorf("Unexpected error: %v", xerr)
			}
		}
		close(bailout) // If Wait actually waits, this is closed AFTER all Tasks filled the channel, so no panics
		// If not..., well...

		if panicReported {
			enough = true
		}
		time.Sleep(2 * time.Second)
	}
	if !panicReported {
		t.Logf("No panic reported, good")
	} else {
		t.Errorf("panics have been reported, bad!!!")
	}
}

func BenchmarkTryWait(b *testing.B) {
	single, xerr := NewTask()
	require.Nil(b, xerr)
	require.NotNil(b, single)

	_, xerr = single.Start(func(t Task, _ TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(1 * time.Second)
		return nil, nil
	}, nil)
	require.Nil(b, xerr)

	for i := 0; i < b.N; i++ {
		_, _, xerr = single.TryWait()
	}
}
