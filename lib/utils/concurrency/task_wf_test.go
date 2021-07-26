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

func TestWaitingGameWF(t *testing.T) {
	got, err := NewUnbreakableTask()
	require.NotNil(t, got)
	require.Nil(t, err)

	theID, err := got.ID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	var tarray []Task

	for ind := 0; ind < 200; ind++ {
		got, err := NewUnbreakableTask()
		require.Nil(t, err)
		require.NotNil(t, got)

		theTask, err := got.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(randomInt(50, 250)) * time.Millisecond)
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
		_, res, err := itta.WaitFor(5 * time.Second)
		require.Nil(t, err)
		require.NotNil(t, res)
		waited++
	}

	aerr, xerr := got.LastError()
	require.Nil(t, xerr)
	require.Nil(t, aerr)

	if waited != 200 {
		t.Errorf("Not enough waiting...: %d", waited)
	}
}

func TestChangeIdAfterAbortWF(t *testing.T) {
	for i := 0; i < 30; i++ {
		got, err := NewTask()
		require.NotNil(t, got)
		require.Nil(t, err)

		theID, err := got.ID()
		require.Nil(t, err)
		require.NotEmpty(t, theID)

		_, err = got.Start(taskgen(50, 250, 2, 2, 0, 0, false), nil)
		if err != nil {
			t.Errorf("Shouldn't happen: %v", err)
		}

		err = got.SetID("") // empty is invalid
		require.NotNil(t, err)

		err = got.SetID("0") // also is zero
		require.NotNil(t, err)

		err = got.Abort()
		require.Nil(t, err)

		require.True(t, got.Aborted())

		err = got.SetID("whatever") // this fails by design
		require.NotNil(t, err)

		_, _, err = got.WaitFor(5 * time.Second)
		require.NotNil(t, err)

		now := time.Now()
		good, _, err := got.WaitFor(4 * time.Second)
		require.NotNil(t, err)
		require.True(t, good)
		then := time.Since(now)
		if then > 3900*time.Millisecond { // this happened (30 iteration is because of that)
			t.Errorf("This should never be a timeout, task was aborted before starting the wait...")
		}
		if _, ok := err.(*fail.ErrTimeout); ok { // this happened (30 iteration is because of that)
			t.Errorf("This should never be a timeout (%v), task was aborted before starting the wait...", err)
		}
	}
}

func TestResultCheckWF(t *testing.T) {
	got, err := NewUnbreakableTask()
	require.NotNil(t, got)
	require.Nil(t, err)

	theID, err := got.ID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	_, err = got.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(randomInt(50, 250)) * time.Millisecond)
		return "waiting game", nil
	}, nil, 10*time.Millisecond)
	if err != nil {
		t.Errorf("Shouldn't happen")
	}

	_, res, err := got.WaitFor(5 * time.Second) // look at next text, why different behavior ?
	require.NotNil(t, err)
	require.NotNil(t, res)

	tr, xerr := got.Result()
	require.Nil(t, xerr)
	require.NotNil(t, tr)
}

func TestResultCheckWithoutWF(t *testing.T) {
	got, err := NewUnbreakableTask()
	require.NotNil(t, got)
	require.Nil(t, err)

	theID, err := got.ID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	_, err = got.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(randomInt(50, 250)) * time.Millisecond)
		return "waiting game", nil
	}, nil, 10*time.Millisecond)
	if err != nil {
		t.Errorf("Shouldn't happen")
	}

	res, err := got.Wait()
	require.NotNil(t, err)
	require.NotNil(t, res)

	tr, xerr := got.Result()
	require.Nil(t, xerr)
	require.NotNil(t, tr)
}

func TestSingleTaskWF(t *testing.T) {
	single, err := NewUnbreakableTask()
	require.NotNil(t, single)
	require.Nil(t, err)

	single, err = single.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(30) * time.Millisecond)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	begin := time.Now()
	_, res, err := single.WaitFor(5 * time.Second)
	end := time.Since(begin)

	require.NotNil(t, res)
	require.Nil(t, err)

	if end >= (time.Millisecond*50) || end < (time.Millisecond*20) {
		t.Errorf("It should have finished near 30 ms but it didn't !!")
	}
}

func TestChildrenWaitingGameWithContextTimeoutsWF(t *testing.T) {
	funk := func(ind int, timeout int, sleep int, trigger int, errorExpected bool) {
		ctx, cafu := context.WithTimeout(context.TODO(), time.Duration(timeout)*time.Millisecond)
		defer cafu()

		single, err := NewTaskWithContext(ctx)
		require.NotNil(t, single)
		require.Nil(t, err)

		begin := time.Now()

		_, xerr := single.Start(taskgen(int(sleep), int(sleep), 4, 0, 0, 0, false), nil)
		require.Nil(t, xerr)

		go func() {
			time.Sleep(time.Duration(trigger) * time.Millisecond)
			cafu()
		}()

		_, _, err = single.WaitFor(5 * time.Second)
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

		tolerance := func(in float64, percent uint) float32 {
			return float32(in * (100.0 + float64(percent)) / 100.0)
		}

		// the minimum of the 3 wins, so
		min := math.Min(math.Min(float64(timeout), float64(sleep)), float64(trigger))
		tolerated := time.Duration(tolerance(min, 20)) * time.Millisecond

		if end > tolerated {
			t.Logf("Failure in test %d: %v, %v, %v, %t: We waited too much! %v > %v", ind, timeout, sleep, trigger, errorExpected, end, tolerated)
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

	funk(1, 30, 50, 10, true)           // canceled
	funk(2, 10, 50, 30, true)           // timeout
	funk(3, 30, 50, 80, true)           // timeout
	funk(4, 80, 50, 10, true)           // canceled
	funk(5, 40, 20, 10, true)           // canceled
	funk(6, 40, 20, 30, false)          // cancel is triggered AFTER we are done (in 20ms), less longer than the timeout -> so no error
	funk(7, 140, 20, 240 /*40*/, false) // same thing here
	funk(8, 140, 20, 100, false)        // same thing here
	funk(9, 140, 20, 120, false)        // same thing here
	funk(10, 140, 20, 50, false)        // same thing here
	funk(11, 140, 50, 10, true)         // canceled
}

func TestChildrenWaitingGameWithContextDeadlinesWF(t *testing.T) {
	funk := func(ind int, timeout uint, sleep uint, trigger uint, errorExpected bool) {
		ctx, cafu := context.WithDeadline(context.TODO(), time.Now().Add(time.Duration(timeout)*time.Millisecond))
		require.NotNil(t, ctx)
		require.NotNil(t, cafu)

		single, xerr := NewTaskWithContext(ctx)
		require.NotNil(t, single)
		require.Nil(t, xerr)

		singleID := fmt.Sprintf("/single-%d", ind)
		xerr = single.SetID(singleID)
		require.Nil(t, xerr)

		begin := time.Now()

		_, xerr = single.Start(taskgen(int(sleep), int(sleep), 4, 0, 0, 0, false), nil)
		require.Nil(t, xerr)

		go func() {
			time.Sleep(time.Duration(trigger) * time.Millisecond)
			cafu()
		}()

		_, _, xerr = single.WaitFor(5 * time.Second)
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
			t.Errorf("Failure in test %d: %d, %d, %d, %t, wrong error", ind, timeout, sleep, trigger, errorExpected)
		}

		ok := (xerr != nil) == errorExpected
		if !ok {
			t.Fail()
		}

		tolerance := func(in float64, percent uint) float32 {
			return float32(in * (100.0 + float64(percent)) / 100.0)
		}

		// the minimum of the 3 wins, so
		min := math.Min(math.Min(float64(timeout), float64(sleep)), float64(trigger))
		tolerated := time.Duration(tolerance(min, 20)) * time.Millisecond

		if end > tolerated {
			t.Logf("Failure in test %d: %v, %v, %v, %t: We waited too much! %v > %v", ind, timeout, sleep, trigger, errorExpected, end, tolerated)
		}
	}
	funk(1, 30, 50, 10, true)   // cancel (aborted)
	funk(2, 30, 50, 90, true)   // timeout
	funk(3, 50, 30, 10, true)   // cancel (aborted)
	funk(4, 50, 10, 30, false)  // terminate normally
	funk(5, 70, 30, 10, true)   // cancel (aborted)
	funk(6, 40, 10, 30, false)  // terminate normally
	funk(7, 140, 20, 40, false) // terminate normally
	funk(8, 140, 40, 20, true)  // cancel (aborted)
}

func TestChildrenWaitingGameWithContextCancelfuncsWF(t *testing.T) {
	funk := func(ind int, sleep uint, lat uint, trigger uint, errorExpected bool) {
		fmt.Printf("--- funk #%d ---\n", ind)

		ctx, cafu := context.WithCancel(context.TODO())
		single, xerr := NewTaskWithContext(ctx)
		require.NotNil(t, single)
		require.Nil(t, xerr)

		xerr = single.SetID(fmt.Sprintf("single-%d", ind))
		require.Nil(t, xerr)

		begin := time.Now()
		single, xerr = single.Start(taskgen(int(sleep), int(sleep), int(lat), 0, 0, 0, false), nil)
		require.Nil(t, xerr)

		go func() {
			time.Sleep(time.Duration(trigger) * time.Millisecond)
			cafu()
		}()

		_, _, xerr = single.WaitFor(5 * time.Second)
		totalEnd := time.Since(begin)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrAborted:
			default:
				t.Errorf("Unexpected error occurred in %s (%s)", xerr.Error(), reflect.TypeOf(xerr).String())
			}
		}

		if !((xerr != nil) == errorExpected) {
			if xerr != nil {
				if !strings.Contains(xerr.Error(), "inconsistent") {
					t.Errorf("Failure in test %d: %v, %v, %t: wrong error!", ind, sleep, trigger, errorExpected)
				}
			} else {
				t.Errorf("Failure in test %d: %v, %v, %t: wrong error!", ind, sleep, trigger, errorExpected)
			}
		}

		tolerance := func(in float64, percent uint) float32 {
			return float32(in * (100.0 + float64(percent)) / 100.0)
		}

		// is the 20% vs latency ratio important ?
		toleratedDuration := time.Duration(tolerance(math.Min(float64(trigger), float64(sleep)), 20)) * time.Millisecond
		if totalEnd > toleratedDuration {
			t.Logf("Warning in test %d: %v, %v, %t: We waited too much! %v > %v", ind, sleep, trigger, errorExpected, totalEnd, toleratedDuration)
		}
	}

	// tests are right, errorExpected it what it should be
	// previous versions got the work done fast enough, now we don't, why ?
	// if trigger >= (sleep + latency) and we have an error (we should NOT), this is failure
	funk(1, 10, 5, 1, true)
	funk(2, 10, 5, 5, true) // latency matters ?
	funk(3, 10, 5, 6, true) // this test and the previous should be equivalent
	// VPL: Task took 12.22ms to end, cancel hits at 12.16ms -> Aborted
	funk(4, 10, 5, 12, false) // latency matters ?
	funk(5, 10, 5, 13, false)
	funk(6, 50, 10, 80, false)
	funk(7, 50, 10, 300, false)
	funk(8, 50, 10, 3000, false)
	funk(9, 50, 10, 6000, false)
	funk(10, 50, 10, 46, true) // latency matters, this sometimes fails
	funk(11, 50, 10, 47, true) // latency matters, this sometimes fails
	// VPL: on macM1, cancel signal hits at 51.80ms, task detects abort at 57.11ms -> Aborted
	funk(12, 60, 20, 62, false) // latency matters, this sometimes fails
	// VPL: on macM1, cancel signals hits at 52.13ms, task detects abort at 57.36ms -> Aborted
	funk(13, 60, 20, 63, false) // latency matters, this sometimes fails
	funk(14, 60, 20, 70, false) // latency matters, this sometimes fails
	// VPL: on macM1, task ended its work after 62.71ms, before cancel hits -> no error
	funk(15, 60, 20, 73, false) // if we go far enough, no errors
	funk(16, 60, 20, 83, false) // if we go far enough, no errors
}

func TestDoesAbortReallyAbortOrIsJustFakeNewsWF(t *testing.T) {
	single, xerr := NewTask()
	require.NotNil(t, single)
	require.Nil(t, xerr)

	single, xerr = single.StartWithTimeout(taskgen(100, 250, 10, 0, 0, 0, false), nil, time.Duration(90)*time.Millisecond)
	require.Nil(t, xerr)

	time.Sleep(time.Duration(300) * time.Millisecond)
	// by now single should have finished with timeouts, so...

	xerr = single.Abort()
	if xerr != nil {
		t.Errorf("How could it fail if the task was already finished longtime ago ?")
	}

	_, _, xerr = single.WaitFor(5 * time.Second)
	require.NotNil(t, xerr) // Task ended on timeout, before abort signal comes, so an error is expected
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
		default:
			t.Errorf("Where is the timeout error ??: %s", spew.Sdump(xerr))
		}
	}
}

func TestLikeBeforeWithoutAbortButContextWF(t *testing.T) {
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
			status, xerr := t.Status()
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

	stat, err := single.Status()
	if err != nil {
		t.Errorf("Problem retrieving status ?")
	}

	if stat != TIMEOUT {
		t.Errorf("Where is the timeout ??, that's the textbook definition")
	}

	_, _, xerr = single.WaitFor(5 * time.Second)
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

func TestLikeBeforeWithoutLettingFinishWF(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	single, xerr := NewTask()
	require.NotNil(t, single)
	require.Nil(t, xerr)

	single, xerr = single.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		for {
			time.Sleep(time.Duration(10) * time.Millisecond)
			if t.Aborted() {
				fmt.Println("There can be only one...")
				return "There can be only one", fail.AbortedError(nil)
			}

			fmt.Println("Forever young...")
		}
	}, nil, time.Duration(200)*time.Millisecond)
	require.Nil(t, xerr)

	_, _, xerr = single.WaitFor(5 * time.Second)
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
	// nah := strings.Split(outString, "\n")

	// if !strings.Contains(nah[len(nah)-3], "Forever young") {
	if !strings.Contains(outString, "Forever young") {
		t.Fail()
	}

	//	if !strings.Contains(nah[len(nah)-2], "only one") {
	if !strings.Contains(outString, "only one") {
		t.Fail()
	}
}

func TestCheckTimeoutStatusWF(t *testing.T) {
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

	_, _, xerr = single.WaitFor(5 * time.Second)
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

func TestStartWithTimeoutWithTimeToFinishWF(t *testing.T) {
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
	}, nil, time.Duration(400)*time.Millisecond)
	require.Nil(t, xerr)

	time.Sleep(time.Duration(100) * time.Millisecond)
	xerr = single.Abort()
	if xerr != nil {
		t.Errorf("There was a failure aborting: %v", xerr)
	}

	// Nothing wrong should happen after this point...
	time.Sleep(time.Duration(100) * time.Millisecond)

	_, _, xerr = single.WaitFor(5 * time.Second)
	require.NotNil(t, xerr)
	switch xerr.(type) {
	case *fail.ErrAborted:
		// expected
	default:
		t.Errorf("unexpected error '%s'", reflect.TypeOf(xerr).String())
	}
}

func TestStartWithTimeoutThatTimeoutsWF(t *testing.T) {
	single, xerr := NewTask()
	require.NotNil(t, single)
	require.Nil(t, xerr)

	single, xerr = single.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		for {
			time.Sleep(time.Duration(10) * time.Millisecond)
			if t.Aborted() {
				return "aborted", fail.AbortedError(nil)
			}
			fmt.Println("Forever young...")
		}
	}, nil, time.Duration(100)*time.Millisecond)
	require.Nil(t, xerr)

	// sleep more than duration defined in the timeout...
	time.Sleep(time.Duration(150) * time.Millisecond)

	// Abort, but too late, task already finished with timeout (hopefully)
	xerr = single.Abort()
	if xerr != nil {
		t.Errorf("There was a failure aborting: %v", xerr)
	}

	_, _, xerr = single.WaitFor(5 * time.Second)
	if xerr == nil {
		t.Errorf("Wait should have failed but didn't")
	} else {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			// expected
		default:
			t.Errorf("This should have failed by design with a Timeout error")
		}
	}
}

// VPL: now that Task is working on this matter, maybe we should prepare a benchmark to compare Task method and this method?
func TestAbortButThisTimeUsingTrueAbortChannelWF(t *testing.T) {
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

	_, _, xerr = single.WaitFor(5 * time.Second)
	require.NotNil(t, xerr)

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	// Here, last 3 lines of the output should be:
	// Forever young...
	// I'm Gotham's reckoning. Here to end the borrowed time you all have been living on.
	// Aborted

	outString := string(out)

	// nah := strings.Split(outString, "\n")

	// if !strings.Contains(nah[len(nah)-4], "Forever young") {
	if !strings.Contains(outString, "Forever young") {
		t.Fail()
	}

	if !strings.Contains(outString, "I'm Gotham's reckoning") {
		t.Fail()
	}

	if !strings.Contains(outString, "Aborted") {
		t.Fail()
	}

	if t.Failed() {
		fmt.Println(outString)
	}
}
