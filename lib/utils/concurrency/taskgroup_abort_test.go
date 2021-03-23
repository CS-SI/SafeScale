package concurrency

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// this function performs sequentially 3 huge time consuming operations 'heavyDutyTask' and checks if abortion is requested between operations
func goodTaskActionCitizen(t Task, parameters TaskParameters) (result TaskResult, xerr fail.Error) {
	var iRes int

	defer func(err *fail.Error) {
		if st, _ := t.GetStatus(); st == ABORTED {
			if iRes > 1 {
				*err = fail.NewError("failure: the action must check the status from time to time")
			}
		}
	}(&xerr)

	if st, _ := t.GetStatus(); st == ABORTED {
		fmt.Println("Exiting before real execution")
		return iRes, nil
	}

	_, xerr = heavyDutyTask(10*time.Millisecond, true)
	if xerr != nil {
		return nil, xerr
	}
	iRes++

	if st, _ := t.GetStatus(); st == ABORTED {
		fmt.Println("Exiting before 2nd execution")
		return iRes, nil
	}

	_, xerr = heavyDutyTask(10*time.Millisecond, true)
	if xerr != nil {
		return nil, xerr
	}
	iRes++

	if st, _ := t.GetStatus(); st == ABORTED {
		fmt.Println("Exiting before 3rd execution")
		return iRes, nil
	}

	_, xerr = heavyDutyTask(10*time.Millisecond, true)
	if xerr != nil {
		return nil, xerr
	}
	iRes++

	if st, _ := t.GetStatus(); st == ABORTED {
		fmt.Println("Exiting before function return")
		return iRes, nil
	}

	return result, xerr
}

// this function performs sequentially 3 huge time consuming operations 'heavyDutyTask' but doesn't care checking for abortion
func badTaskActionCitizen(t Task, parameters TaskParameters) (result TaskResult, xerr fail.Error) {
	var iRes int

	defer func(err *fail.Error) {
		if st, _ := t.GetStatus(); st == ABORTED {
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
		if st, _ := t.GetStatus(); st == ABORTED {
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

func TestGoodTaskActionCitizen(t *testing.T) {
	overlord, xerr := NewTaskGroup(nil)
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
		}
	}

	begin := time.Now()
	time.Sleep(12 * time.Millisecond)
	xerr = overlord.Abort()
	if xerr != nil {
		t.Fail()
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
					t.Fail()
				}

				if len(errList) != 1 {
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

func TestBadTaskActionCitizen(t *testing.T) {
	overlord, xerr := NewTaskGroup(nil)
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
					t.Fail()
				}

				if len(errList) != (numChild + 1) {
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

func TestAwfulTaskActionCitizen(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	overlord, xerr := NewTaskGroup(nil)
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

	_, xerr = overlord.WaitGroup()
	if xerr == nil { // It should fail because it's an aborted task...
		t.Fail()
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
