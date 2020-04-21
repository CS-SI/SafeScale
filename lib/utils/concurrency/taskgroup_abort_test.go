package concurrency

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/stretchr/testify/require"
)

// this function performs sequentially 3 huge time consuming operations 'heavyDutyTask' and checks if abortion is requested between operations
func goodTaskActionCitizen(t Task, parameters TaskParameters) (result TaskResult, err error) {
	var iRes int

	defer func(err *error) {
		if st, _ := t.GetStatus(); st == ABORTED {
			if iRes > 1 {
				*err = fmt.Errorf("failure: the action must check the status from time to time")
			}
		}
	}(&err)

	if st, _ := t.GetStatus(); st == ABORTED {
		fmt.Println("Exiting before real execution")
		return iRes, nil
	}

	_, err = heavyDutyTask(10*time.Millisecond, true)
	if err != nil {
		return nil, err
	}
	iRes++

	if st, _ := t.GetStatus(); st == ABORTED {
		fmt.Println("Exiting before 2nd execution")
		return iRes, nil
	}

	_, err = heavyDutyTask(10*time.Millisecond, true)
	if err != nil {
		return nil, err
	}
	iRes++

	if st, _ := t.GetStatus(); st == ABORTED {
		fmt.Println("Exiting before 3rd execution")
		return iRes, nil
	}

	_, err = heavyDutyTask(10*time.Millisecond, true)
	if err != nil {
		return nil, err
	}
	iRes++

	if st, _ := t.GetStatus(); st == ABORTED {
		fmt.Println("Exiting before function return")
		return iRes, nil
	}

	return result, err
}

// this function performs sequentially 3 huge time consuming operations 'heavyDutyTask' but doesn't care checking for abortion
func badTaskActionCitizen(t Task, parameters TaskParameters) (result TaskResult, err error) {
	var iRes int

	defer func(err *error) {
		if st, _ := t.GetStatus(); st == ABORTED {
			if iRes > 1 {
				*err = fmt.Errorf("failure: the action must check the status from time to time")
			}
		}
	}(&err)

	_, err = heavyDutyTask(10*time.Millisecond, true)
	if err != nil {
		return nil, err
	}
	iRes++

	_, err = heavyDutyTask(10*time.Millisecond, true)
	if err != nil {
		return nil, err
	}
	iRes++

	_, err = heavyDutyTask(10*time.Millisecond, true)
	if err != nil {
		return nil, err
	}
	iRes++

	return result, err
}

// this function never returns, it just leaks
func horribleTaskActionCitizen(t Task, parameters TaskParameters) (result TaskResult, err error) {
	var iRes int

	defer func(err *error) {
		if st, _ := t.GetStatus(); st == ABORTED {
			if iRes > 1 {
				*err = fmt.Errorf("failure: the action must check the status from time to time")
			}
		}
	}(&err)

	keep := true
	for keep {
		fmt.Println("Living forever")
		_, _ = heavyDutyTask(10*time.Millisecond, true)
	}

	return result, err
}

func heavyDutyTask(duration time.Duration, wantedResult bool) (bool, error) {
	time.Sleep(duration * 2)

	return wantedResult, nil
}

func TestGoodTaskActionCitizen(t *testing.T) {
	overlord, err := NewTaskGroup(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	fmt.Println("Begin")

	numChild := 10
	for ind := 0; ind < numChild; ind++ {
		_, err := overlord.Start(goodTaskActionCitizen, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
	}

	begin := time.Now()
	time.Sleep(12 * time.Millisecond)
	err = overlord.Abort()
	if err != nil {
		t.Fail()
	}

	end := time.Since(begin)

	time.Sleep(12 * time.Millisecond)

	_, err = overlord.WaitGroup()
	if err != nil {
		if eab, ok := err.(scerr.ErrAborted); ok {
			cause := eab.Cause()
			if causes, ok := cause.(scerr.ErrList); ok {
				errList := causes.ToErrors()
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

// func typeof(v interface{}) string {
// 	return fmt.Sprintf("%T", v)
// }

func TestBadTaskActionCitizen(t *testing.T) {
	overlord, err := NewTaskGroup(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	fmt.Println("Begin")

	numChild := 10
	for ind := 0; ind < numChild; ind++ {
		_, err := overlord.Start(badTaskActionCitizen, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
	}

	begin := time.Now()
	time.Sleep(10 * time.Millisecond)
	err = overlord.Abort()
	if err != nil {
		t.Fail()
	}

	end := time.Since(begin)

	time.Sleep(60 * time.Millisecond)

	_, err = overlord.WaitGroup()
	if err != nil {
		if eab, ok := err.(scerr.ErrAborted); ok {
			cause := eab.Cause()
			if causes, ok := cause.(scerr.ErrList); ok {
				errList := causes.ToErrors()
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

	overlord, err := NewTaskGroup(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theID, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	fmt.Println("Begin")

	numChild := 4 // No need to push it
	for ind := 0; ind < numChild; ind++ {
		_, err := overlord.Start(horribleTaskActionCitizen, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
	}

	time.Sleep(10 * time.Millisecond)
	err = overlord.Abort()
	if err != nil {
		t.Fail()
	}

	time.Sleep(60 * time.Millisecond)

	_, err = overlord.WaitGroup()
	if err == nil { // It should fail because it's an aborted task...
		t.Fail()
	}

	time.Sleep(100 * time.Millisecond)

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	count := strings.Count(string(out), "Living forever")
	fmt.Println(count)
	if count < 5 {
		t.Fail()
	}
}
