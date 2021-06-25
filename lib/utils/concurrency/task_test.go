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

	"github.com/gophercloud/gophercloud/acceptance/tools"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// NOTICE The whole file task_test.go MUST pass UT flawlessly before using it confidently in foreman.go and controller.go

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
	funk := func(timeout time.Duration, sleep time.Duration, trigger time.Duration, errorExpected bool) {
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
					break
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
			if !strings.Contains(err.Error(), "abort") {
				t.Errorf("Why so serious? it's just a failure cancelling a goroutine: %s", err.Error())
			}
		}

		if errorExpected {
			require.NotNil(t, err)
			switch err.(type) {
			case *fail.ErrAborted:
			default:
				t.Errorf("Failure in test: %v, %v, %v, %t", timeout, sleep, trigger, errorExpected)
			}
		} else {
			require.Nil(t, err)
		}

		if !((err != nil) == errorExpected) {
			t.Errorf("Failure in test: %v, %v, %v, %t", timeout, sleep, trigger, errorExpected)
		}
		require.True(t, (err != nil) == errorExpected)

		// the minimum of the 3 wins, so
		min := math.Min(math.Min(float64(timeout), float64(sleep)), float64(trigger))

		if end > time.Duration(min+10)*time.Millisecond {
			t.Errorf("Failure in test: %v, %v, %v, %t: We waited too much! %v > %v", timeout, sleep, trigger, errorExpected, end, trigger+20*time.Millisecond)
		}
	}

	// No errors here, look at TestChildrenWaitingGameWithContextCancelfuncs for more information
	// there is a performance degradation problem in Task/TaskGroup that impact the timings
	funk(30*time.Millisecond, 50*time.Millisecond, 10*time.Millisecond, true)   // timeout
	funk(30*time.Millisecond, 50*time.Millisecond, 80*time.Millisecond, true)   // timeout
	funk(80*time.Millisecond, 50*time.Millisecond, 10*time.Millisecond, true)   // canceled
	funk(40*time.Millisecond, 20*time.Millisecond, 10*time.Millisecond, true)   // canceled
	funk(40*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, false)  // cancel is tiggered AFTER we are done (in 20ms), less that the timeout -> so no error
	funk(140*time.Millisecond, 20*time.Millisecond, 40*time.Millisecond, false) // same thing here
	funk(140*time.Millisecond, 50*time.Millisecond, 10*time.Millisecond, true)  // canceled
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
			var i int
			for ; i < 100; i++ {
				if t.Aborted() {
					break
				}
				time.Sleep(tempo)
			}

			time.Sleep(time.Duration(sleep*10) * time.Millisecond)
			fmt.Printf("%s: sleeped %v\n", singleID, time.Duration(i)*tempo+time.Duration(sleep)*10*time.Millisecond)
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
			if !strings.Contains(xerr.Error(), "abort") {
				t.Errorf("Why so serious ? it's just a failure cancelling a goroutine: %s", xerr.Error())
			}
		}

		if !((xerr != nil) == errorExpected) {
			t.Errorf("Failure in test %s: %d, %d, %d, %t", singleID, timeout, sleep, trigger, errorExpected)
		}
		require.True(t, (xerr != nil) == errorExpected)

		// the minimum of the 3 wins, so
		min := math.Min(math.Min(float64(timeout), float64(sleep)), float64(trigger))

		if end > time.Millisecond*time.Duration(10*(min+1)) {
			t.Errorf("Failure in test %s: %v, %v, %v, %t: We waited too much! %v > %v", singleID, timeout, sleep, trigger, errorExpected, end, time.Duration(min+1)*10*time.Millisecond)
		}
	}
	funk(1, 3, 5, 1, true)
	funk(2, 3, 5, 9, true)
	funk(3, 5, 3, 1, true)
	funk(4, 5, 1, 3, false)
	funk(5, 7, 3, 1, true)
	funk(6, 4, 1, 3, false)
	funk(7, 14, 2, 4, false)
	funk(8, 14, 4, 2, true)
}

func TestChildrenWaitingGameWithContextCancelfuncs(t *testing.T) {
	funk := func(sleep uint, trigger uint, errorExpected bool) {
		ctx, cafu := context.WithCancel(context.TODO())
		single, xerr := NewTaskWithContext(ctx)
		require.NotNil(t, single)
		require.Nil(t, xerr)

		begin := time.Now()

		single, xerr = single.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			dur := time.Duration(sleep*10) * time.Millisecond
			tempo := dur / 100
			for i := 0; i < 100; i++ {
				if t.Aborted() {
					break
				}
				time.Sleep(tempo)
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
			if !strings.Contains(xerr.Error(), "abort") {
				t.Errorf("Why so serious ? it's just a failure cancelling a goroutine: %s", xerr.Error())
			}
		}

		require.True(t, (xerr != nil) == errorExpected)

		if trigger < sleep {
			if end > time.Millisecond*time.Duration(10*(trigger+2)) {
				t.Errorf("Failure in test: %v, %v, %t: We waited too much! %v > %v", sleep, trigger, errorExpected, end, time.Duration(trigger+2)*time.Millisecond)
			}
		} else {
			if end > time.Millisecond*time.Duration(10*(sleep+2)) {
				t.Errorf("Failure in test: %v, %v, %t: We waited too much! %v > %v", sleep, trigger, errorExpected, end, time.Duration(trigger+2)*time.Millisecond)
			}
		}
	}

	// tests are right, errorExpected it what it should be
	// previous versions got the work done in 50, 52 ms, problem is, now it takes twice the time, 110 ms, why ?
	funk(5, 1, true)
	funk(5, 8, false) // this is a performance degradation, it worked before, look at the 2 next tests, this text should work like the next ones, it does not because the timings of Wait are degraded
	funk(5, 30, false)
	funk(5, 300, false)
	funk(5, 600, false)
	funk(5, 6000, false)
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
	// by now single should succeed
	xerr = single.Abort()

	fmt.Println("Aborted")

	// Nothing wrong should happen after this point...
	time.Sleep(time.Duration(100) * time.Millisecond)

	require.Nil(t, xerr)

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	// Here, last 2 lines of the output should be:
	// Forever young...
	// Aborted

	_, _ = single.Wait()

	outString := string(out)
	nah := strings.Split(outString, "\n")

	if !strings.Contains(nah[len(nah)-3], "Forever young") {
		t.Fail()
	}

	if !strings.Contains(nah[len(nah)-2], "Aborted") {
		t.Fail()
	}
}

func TestDontCallMeUp(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	single, xerr := NewTask()
	require.NotNil(t, single)
	require.Nil(t, xerr)

	_, xerr = single.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		for {
			time.Sleep(time.Duration(10) * time.Millisecond)
			status, _ := t.GetStatus()
			if status == ABORTED || status == TIMEOUT {
				break
			}
			fmt.Println("Forever young...")
		}
		return "I want to be forever young", nil
	}, nil, time.Duration(40)*time.Millisecond)
	require.Nil(t, xerr)

	time.Sleep(time.Duration(100) * time.Millisecond)
	fmt.Println("Automagically aborted ??")

	// Nothing wrong should happen after this point...
	time.Sleep(time.Duration(100) * time.Millisecond)

	require.Nil(t, xerr)

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	// Here, last 2 lines of the output should be:
	// Forever young...
	// Automagically aborted ??

	outString := string(out)
	nah := strings.Split(outString, "\n")

	if !strings.Contains(nah[len(nah)-3], "Forever young") {
		t.Fail()
	}
	if !strings.Contains(nah[len(nah)-2], "Automagically") {
		t.Fail()
	}
}

func TestOneShot(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

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
	}, nil, time.Duration(400)*time.Millisecond)
	require.Nil(t, xerr)

	time.Sleep(time.Duration(100) * time.Millisecond)
	xerr = single.Abort()
	require.Nil(t, xerr)
	fmt.Println("Forcefully aborted ??")

	// Nothing wrong should happen after this point...
	time.Sleep(time.Duration(100) * time.Millisecond)

	require.Nil(t, xerr)

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	// Here, last 2 lines of the output should be:
	// Forever young...
	// Forcefully aborted ??

	outString := string(out)
	nah := strings.Split(outString, "\n")

	if !strings.Contains(nah[len(nah)-3], "Forever young") {
		t.Fail()
	}
	if !strings.Contains(nah[len(nah)-2], "Forcefully") {
		t.Fail()
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

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	if xerr != nil {
		fmt.Println(xerr.Error())
	}

	require.Nil(t, xerr)

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
