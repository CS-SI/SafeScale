//go:build alltests
// +build alltests

/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

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

	single, xerr = single.StartWithTimeout(
		func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
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
		}, nil, time.Duration(200)*time.Millisecond,
	)
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

func TestChildrenWaitingGameWithContextTimeouts(t *testing.T) {
	funk := func(ind int, timeout int, sleep int, trigger int, errorExpected bool) {
		ctx, cafu := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
		defer cafu()

		single, err := NewTaskWithContext(ctx)
		require.NotNil(t, single)
		require.Nil(t, err)

		begin := time.Now()

		_, xerr := single.Start(taskgen(sleep, sleep, 4, 0, 0, 0, false), nil)
		require.Nil(t, xerr)

		go func() {
			time.Sleep(time.Duration(trigger) * time.Millisecond)
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
			t.Errorf(
				"Failure in test %d (in error expected): %v, %v, %v, %t", ind, timeout, sleep, trigger, errorExpected,
			)
		}

		tolerance := func(in float64, percent uint) float32 {
			return float32(in * (100.0 + float64(percent)) / 100.0)
		}

		// the minimum of the 3 wins, so
		min := math.Min(math.Min(float64(timeout), float64(sleep)), float64(trigger))
		tolerated := time.Duration(tolerance(min, 20)) * time.Millisecond

		if end > tolerated {
			t.Logf(
				"Failure in test %d: %v, %v, %v, %t: We waited too much! %v > %v", ind, timeout, sleep, trigger,
				errorExpected, end, tolerated,
			)
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

	funk(1, 30, 50, 10, true) // canceled
	funk(2, 10, 50, 30, true) // timeout
	funk(3, 30, 50, 80, true) // timeout
	funk(4, 80, 50, 10, true) // canceled
	funk(5, 40, 20, 10, true) // canceled
	funk(
		6, 40, 20, 30, false,
	) // cancel is triggered AFTER we are done (in 20ms), less longer than the timeout -> so no error
	funk(7, 140, 20, 240 /*40*/, false) // same thing here
	funk(8, 140, 20, 100, false)        // same thing here
	funk(9, 140, 20, 120, false)        // same thing here
	funk(10, 140, 20, 50, false)        // same thing here
	funk(11, 140, 50, 10, true)         // canceled
}

func TestChildrenWaitingGameWithContextTimeoutsWF(t *testing.T) {
	funk := func(ind int, timeout int, sleep int, trigger int, errorExpected bool) {
		ctx, cafu := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
		defer cafu()

		single, err := NewTaskWithContext(ctx)
		require.NotNil(t, single)
		require.Nil(t, err)

		begin := time.Now()

		_, xerr := single.Start(taskgen(sleep, sleep, 4, 0, 0, 0, false), nil)
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
			t.Errorf(
				"Failure in test %d (in error expected): %v, %v, %v, %t", ind, timeout, sleep, trigger, errorExpected,
			)
		}

		tolerance := func(in float64, percent uint) float32 {
			return float32(in * (100.0 + float64(percent)) / 100.0)
		}

		// the minimum of the 3 wins, so
		min := math.Min(math.Min(float64(timeout), float64(sleep)), float64(trigger))
		tolerated := time.Duration(tolerance(min, 20)) * time.Millisecond

		if end > tolerated {
			t.Logf(
				"Failure in test %d: %v, %v, %v, %t: We waited too much! %v > %v", ind, timeout, sleep, trigger,
				errorExpected, end, tolerated,
			)
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

	funk(1, 30, 50, 10, true) // canceled
	funk(2, 10, 50, 30, true) // timeout
	funk(3, 30, 50, 80, true) // timeout
	funk(4, 80, 50, 10, true) // canceled
	funk(5, 40, 20, 10, true) // canceled
	funk(
		6, 40, 20, 30, false,
	) // cancel is triggered AFTER we are done (in 20ms), less longer than the timeout -> so no error
	funk(7, 140, 20, 240 /*40*/, false) // same thing here
	funk(8, 140, 20, 100, false)        // same thing here
	funk(9, 140, 20, 120, false)        // same thing here
	funk(10, 140, 20, 50, false)        // same thing here
	funk(11, 140, 50, 10, true)         // canceled
}

func TestChildrenWaitingGameWithContextDeadlinesWF(t *testing.T) {
	funk := func(ind int, timeout uint, sleep uint, trigger uint, errorExpected bool) {
		ctx, cafu := context.WithDeadline(context.Background(), time.Now().Add(time.Duration(timeout)*time.Millisecond))
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
				t.Errorf(
					"Unexpected error occurred in test #%d: %s (%s)", ind, xerr.Error(), reflect.TypeOf(xerr).String(),
				)
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
			t.Logf(
				"Failure in test %d: %v, %v, %v, %t: We waited too much! %v > %v", ind, timeout, sleep, trigger,
				errorExpected, end, tolerated,
			)
		}
	}
	funk(1, 30, 50, 10, true)   // cancel (aborted)
	funk(2, 30, 50, 90, true)   // timeout
	funk(3, 50, 30, 10, true)   // cancel (aborted)
	funk(4, 50, 10, 30, false)  // terminate normally // FAIL
	funk(5, 70, 30, 10, true)   // cancel (aborted)
	funk(6, 40, 10, 30, false)  // terminate normally // FAIL
	funk(7, 140, 20, 40, false) // terminate normally // FAIL
	funk(8, 140, 40, 20, true)  // cancel (aborted)
	funk(9, 140, 40, 10, true)  // cancel (aborted)
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
					t.Errorf(
						"Failure in test %d: %v, %v, %t: wrong error: %v!", ind, sleep, trigger, errorExpected, xerr,
					)
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

	for i := 0; i < 5; i++ {
		// tests are right, errorExpected it what it should be
		// previous versions got the work done fast enough, now we don't, why ?
		// if trigger >= (sleep + latency) and we have an error (we should NOT), this is failure
		funk(1, 10, 5, 1, true)
		funk(2, 10, 5, 5, true) // latency matters ?
		funk(3, 10, 5, 6, true) // this test and the previous should be equivalent
		// VPL: Task took 12.22ms to end, cancel hits at 12.16ms -> Aborted
		funk(4, 10, 5, 20, false) // latency matters ?
		funk(5, 10, 5, 21, false)
		funk(6, 50, 10, 80, false)
		funk(7, 50, 10, 300, false)
		funk(8, 50, 10, 3000, false)
		funk(9, 50, 10, 6000, false)
		funk(10, 50, 10, 45, true) // latency matters, this sometimes fails
		funk(11, 50, 10, 46, true) // latency matters, this sometimes fails
		// VPL: on macM1, cancel signal hits at 51.80ms, task detects abort at 57.11ms -> Aborted
		funk(12, 60, 20, 63, false) // latency matters, this sometimes fails
		// VPL: on macM1, cancel signals hits at 52.13ms, task detects abort at 57.36ms -> Aborted
		funk(13, 60, 20, 64, false) // latency matters, this sometimes fails
		funk(14, 60, 20, 70, false) // latency matters, this sometimes fails
		// VPL: on macM1, task ended its work after 62.71ms, before cancel hits -> no error
		funk(15, 60, 20, 73, false) // if we go far enough, no errors
		funk(16, 60, 20, 83, false) // if we go far enough, no errors
	}
}

func TestChildrenWaitingGameEnoughTimeTooManyFailures(t *testing.T) {
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
				t.Logf("WaitFor failed: %s", xerr)
				if childrenStartDuration > 5*time.Millisecond { // however, it grows with gcpressure
					t.Logf("Launching children took %v", childrenStartDuration)
				}
				t.Logf("WaitFor really waited %v/%v", waitForRealDuration, timeout)
				t.Logf("Test %d, It should be enough time but it wasn't at iteration #%d", index, iter)
				failures++
				if failures > (75 * rounds / 100) {
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
	funk(1, 10, 100, 125, 25, 25, 10)
	funk(2, 10, 100, 125, 25, 25, 10)
	funk(3, 10, 100, 125, 25, 25, 10)
	funk(4, 10, 100, 125, 25, 25, 10)
}
