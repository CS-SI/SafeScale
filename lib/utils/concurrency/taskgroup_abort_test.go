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
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

func problemsHappen(t Task, parameters TaskParameters) (result TaskResult, xerr fail.Error) {
	return heavyDutyTaskThatFails(40*time.Millisecond, true, true)
}

func happyPath(t Task, parameters TaskParameters) (result TaskResult, xerr fail.Error) {
	return heavyDutyTaskThatFails(40*time.Millisecond, true, false)
}

// this function performs sequentially 3 huge time consuming operations 'heavyDutyTask' and checks if abortion is requested between operations
func goodTaskActionCitizen(t Task, parameters TaskParameters) (result TaskResult, xerr fail.Error) {
	var iRes int

	defer func(err *fail.Error) {
		if t.Aborted() {
			if iRes > 1 {
				*err = fail.NewError("failure: the action must check the status from time to time")
			}
		}
	}(&xerr)

	if t.Aborted() {
		fmt.Println("Exiting before real execution")
		return iRes, nil
	}

	_, xerr = heavyDutyTask(10*time.Millisecond, true)
	if xerr != nil {
		return nil, xerr
	}
	iRes++

	if t.Aborted() {
		fmt.Println("Exiting before 2nd execution")
		return iRes, nil
	}

	_, xerr = heavyDutyTask(10*time.Millisecond, true)
	if xerr != nil {
		return nil, xerr
	}
	iRes++

	if t.Aborted() {
		fmt.Println("Exiting before 3rd execution")
		return iRes, nil
	}

	_, xerr = heavyDutyTask(10*time.Millisecond, true)
	if xerr != nil {
		return nil, xerr
	}
	iRes++

	if t.Aborted() {
		fmt.Println("Exiting before function return")
		return iRes, nil
	}

	return result, xerr
}

// this function performs sequentially 3 huge time consuming operations 'heavyDutyTask' but doesn't care checking for abortion
func badTaskActionCitizen(t Task, parameters TaskParameters) (result TaskResult, xerr fail.Error) {
	var iRes int

	defer func(err *fail.Error) {
		if st, _ := t.Status(); st == ABORTED {
			if iRes > 1 {
				*err = fail.NewError("failure: the action must check the status from time to time")
			}
		}
	}(&xerr)

	_, xerr = heavyDutyTask(10*time.Millisecond, true)
	if xerr != nil {
		return nil, xerr
	}
	iRes++

	_, xerr = heavyDutyTask(10*time.Millisecond, true)
	if xerr != nil {
		return nil, xerr
	}
	iRes++

	_, xerr = heavyDutyTask(10*time.Millisecond, true)
	if xerr != nil {
		return nil, xerr
	}
	iRes++

	return result, xerr
}

// this function never returns, it just leaks
func horribleTaskActionCitizen(t Task, parameters TaskParameters) (result TaskResult, xerr fail.Error) {
	var iRes int

	defer func(err *fail.Error) {
		if t.Aborted() {
			if iRes > 1 {
				*err = fail.NewError("failure: the action must check the status from time to time")
			}
		}
	}(&xerr)

	theCh := parameters.(chan string)

	for {
		theCh <- "Living forever"
		_, _ = heavyDutyTask(10*time.Millisecond, true)
	}
}

func heavyDutyTask(duration time.Duration, wantedResult bool) (bool, fail.Error) {
	time.Sleep(duration * 2)

	return wantedResult, nil
}

func heavyDutyTaskThatFails(duration time.Duration, wantedResult bool, withError bool) (bool, fail.Error) {
	time.Sleep(duration * 2)

	if withError {
		return wantedResult, fail.NewError("An error !!, damn !!")
	}

	return wantedResult, nil
}

func TestSomethingFails(t *testing.T) {
	overlord, xerr := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, xerr)

	theID, xerr := overlord.GetID()
	require.Nil(t, xerr)
	require.NotEmpty(t, theID)

	fmt.Println("Begin")

	numChild := 10
	for ind := 0; ind < numChild; ind++ {
		_, xerr := overlord.Start(happyPath, nil)
		if xerr != nil {
			t.Errorf("Unexpected: %s", xerr)
		}
	}
	_, xerr = overlord.Start(problemsHappen, nil)
	if xerr != nil {
		t.Errorf("Unexpected: %s", xerr)
	}
	_, xerr = overlord.Start(problemsHappen, nil)
	if xerr != nil {
		t.Errorf("Unexpected: %s", xerr)
	}

	_, xerr = overlord.WaitGroup()
	require.NotNil(t, xerr)
	if xerr != nil {
		switch cerr := xerr.(type) {
		case *fail.ErrorList:
			if len(cerr.ToErrorSlice()) != 2 {
				t.Fail()
			}
		default:
			t.Errorf("Unexpected error %s (%s)", xerr.Error(), reflect.TypeOf(xerr).String())
		}
	}
}

func TestGoodTaskActionCitizen(t *testing.T) {
	overlord, xerr := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, xerr)

	theID, xerr := overlord.GetID()
	require.Nil(t, xerr)
	require.NotEmpty(t, theID)

	fmt.Println("Begin")

	numChild := 10
	for ind := 0; ind < numChild; ind++ {
		_, xerr := overlord.Start(goodTaskActionCitizen, nil)
		if xerr != nil {
			t.Errorf("Unexpected: %s", xerr)
			t.FailNow()
		}
	}

	begin := time.Now()
	time.Sleep(12 * time.Millisecond)
	xerr = overlord.Abort()
	if xerr != nil {
		t.Errorf("Unable to abort")
		t.FailNow()
	}

	end := time.Since(begin)

	time.Sleep(12 * time.Millisecond)

	_, xerr = overlord.WaitGroup()
	if xerr != nil {
		if eab, ok := xerr.(*fail.ErrAborted); ok {
			cause := eab.Cause()
			if causes, ok := cause.(*fail.ErrorList); ok {
				errList := causes.ToErrorSlice()
				errFound := false
				for _, err := range errList {
					if strings.Contains(err.Error(), "must check the status") {
						errFound = true
					}
				}

				if errFound {
					t.Errorf("There should be NO errors")
					t.FailNow()
				}
			}
		}
	}

	time.Sleep(100 * time.Millisecond)

	if end >= (time.Millisecond * 300) {
		t.Errorf("It should have finished in less than 3s ms but it didn't, it was %s !!", end)
	}
}

func TestBadTaskActionCitizen(t *testing.T) {
	overlord, xerr := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, xerr)

	theID, xerr := overlord.GetID()
	require.Nil(t, xerr)
	require.NotEmpty(t, theID)

	fmt.Println("Begin")

	numChild := 10
	for ind := 0; ind < numChild; ind++ {
		_, xerr := overlord.Start(badTaskActionCitizen, nil)
		if xerr != nil {
			t.Errorf("Unexpected: %s", xerr)
		}
	}

	begin := time.Now()
	time.Sleep(10 * time.Millisecond)
	xerr = overlord.Abort()
	if xerr != nil {
		t.Fail()
	}

	end := time.Since(begin)

	time.Sleep(60 * time.Millisecond)

	_, xerr = overlord.WaitGroup()
	if xerr != nil {
		if eab, ok := xerr.(*fail.ErrAborted); ok {
			cause := eab.Cause()
			if causes, ok := cause.(*fail.ErrorList); ok {
				errList := causes.ToErrorSlice()
				errFound := false
				for _, err := range errList {
					if strings.Contains(err.Error(), "must check the status") {
						errFound = true
					}
				}

				if !errFound {
					t.Errorf("no message checking for status !!")
					t.Fail()
				}

				if len(errList) != numChild {
					t.Errorf("didn't wait for all the children !!: %d", len(errList))
					t.Fail()
				}
			}
		}
	}

	time.Sleep(100 * time.Millisecond)

	if end >= (time.Millisecond * 300) {
		t.Errorf("It should have finished in less than 3s ms but it didn't, it was %s !!", end)
	}
}

// VPL: as coded, this test never stop... There is no way to kill the goroutines
func TestAwfulTaskActionCitizen(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	overlord, xerr := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, xerr)

	theID, xerr := overlord.GetID()
	require.Nil(t, xerr)
	require.NotEmpty(t, theID)

	fmt.Println("Begin")

	stCh := make(chan string, 100)

	numChild := 4 // No need to push it
	for ind := 0; ind < numChild; ind++ {
		_, xerr := overlord.Start(horribleTaskActionCitizen, stCh)
		if xerr != nil {
			t.Errorf("Unexpected: %s", xerr)
		}
	}

	time.Sleep(10 * time.Millisecond)
	xerr = overlord.Abort()
	if xerr != nil {
		t.Fail()
	}

	time.Sleep(60 * time.Millisecond)

	// VPL: waiting on a taskgroup running task that cannot end will deadlock... As expected...
	ended, _, xerr := overlord.WaitGroupFor(5 * time.Second)
	if xerr == nil { // It should fail because it's an aborted task...
		t.Fail()
	}
	if !ended {
		t.Logf("TaskGroup hasn't ended after 5s")
	}
	switch xerr.(type) {
	case *fail.ErrTimeout:
		t.Logf("timeout occurred as expected, TaskGroup cannot end because of the way TaskActions have been coded")
	default:
		t.Errorf("unexpected error occurred: %v", xerr)
	}

	time.Sleep(1000 * time.Millisecond)

	_ = w.Close()

	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout
	_ = out

	count := len(stCh)
	if count < 5 {
		t.Fail()
	}
}
