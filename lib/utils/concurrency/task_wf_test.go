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
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
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

		theTask, err := got.Start(
			func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
				time.Sleep(time.Duration(randomInt(50, 250)) * time.Millisecond)
				return "waiting game", nil
			}, nil,
		)
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

	_, err = got.StartWithTimeout(
		func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(randomInt(50, 250)) * time.Millisecond)
			return "waiting game", nil
		}, nil, 10*time.Millisecond,
	)
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

func TestSingleTaskWF(t *testing.T) {
	single, err := NewUnbreakableTask()
	require.NotNil(t, single)
	require.Nil(t, err)

	single, err = single.Start(
		func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(30) * time.Millisecond)
			return "Ahhhh", nil
		}, nil,
	)
	require.Nil(t, err)

	begin := time.Now()
	_, res, err := single.WaitFor(5 * time.Second)
	end := time.Since(begin)

	require.NotNil(t, res)
	require.Nil(t, err)

	if end >= (time.Millisecond*70) || end < (time.Millisecond*20) {
		t.Errorf("It should have finished near 30 ms but it didn't !!: %s", end)
	}
}

func TestDoesAbortReallyAbortOrIsJustFakeNewsWF(t *testing.T) {
	single, xerr := NewTask()
	require.NotNil(t, single)
	require.Nil(t, xerr)

	single, xerr = single.StartWithTimeout(
		taskgen(100, 250, 10, 0, 0, 0, false), nil, time.Duration(90)*time.Millisecond,
	)
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

func TestLikeBeforeWithoutLettingFinishWF(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	single, xerr := NewTask()
	require.NotNil(t, single)
	require.Nil(t, xerr)

	single, xerr = single.StartWithTimeout(
		func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			for {
				time.Sleep(time.Duration(10) * time.Millisecond)
				if t.Aborted() {
					fmt.Println("There can be only one...")
					return "There can be only one", fail.AbortedError(nil)
				}

				fmt.Println("Forever young...")
			}
		}, nil, time.Duration(200)*time.Millisecond,
	)
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

	_, xerr = single.StartWithTimeout(
		func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			for {
				time.Sleep(time.Duration(10) * time.Millisecond)
				if t.Aborted() {
					break
				}
				fmt.Println("Forever young...")
			}
			return "I want to be forever young", nil
		}, nil, time.Duration(40)*time.Millisecond,
	)
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

	single, xerr = single.StartWithTimeout(
		func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			for {
				time.Sleep(time.Duration(10) * time.Millisecond)
				if t.Aborted() {
					return nil, fail.AbortedError(nil)
				}
				fmt.Println("Forever young...")
			}
		}, nil, time.Duration(400)*time.Millisecond,
	)
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

	single, xerr = single.StartWithTimeout(
		func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			for {
				time.Sleep(time.Duration(10) * time.Millisecond)
				if t.Aborted() {
					return "aborted", fail.AbortedError(nil)
				}
				fmt.Println("Forever young...")
			}
		}, nil, time.Duration(100)*time.Millisecond,
	)
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
	single, xerr = single.StartWithTimeout(
		func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
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
		}, nil, time.Duration(40)*time.Millisecond,
	)
	require.Nil(t, xerr)

	time.Sleep(time.Duration(200) * time.Millisecond)

	xerr = single.Abort()
	require.Nil(t, xerr)
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
