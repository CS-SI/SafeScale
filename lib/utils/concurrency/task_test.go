package concurrency

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDoesAbortReallyAbortOrIsJustFakeNews(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	single, err := NewTask(nil)
	require.NotNil(t, single)
	require.Nil(t, err)

	single, err = single.StartWithTimeout(
		func(t Task, parameters TaskParameters) (result TaskResult, err error) {
			for {
				if t.Aborted() {
					break
				}
				fmt.Println("Forever young...")
				time.Sleep(time.Duration(90) * time.Millisecond)
			}
			return "I want to be forever young", nil
		}, nil, time.Duration(4000)*time.Millisecond,
	)
	require.Nil(t, err)

	time.Sleep(time.Duration(2000) * time.Millisecond)
	// by now single should succeed
	err = single.Abort()

	fmt.Println("Aborted")

	// Nothing wrong should happen after this point...
	time.Sleep(time.Duration(2000) * time.Millisecond)

	require.Nil(t, err)

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	// Here, last 2 lines of the output should be:
	// Forever young...
	// Aborted

	outString := string(out)
	nah := strings.Split(outString, "\n")

	if !strings.Contains(nah[len(nah)-2], "Aborted") {
		t.Fail()
	}
}

func TestDoesItLeakWhenTimeouts(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	single, err := NewTask(nil)
	require.NotNil(t, single)
	require.Nil(t, err)

	single, err = single.StartWithTimeout(
		func(t Task, parameters TaskParameters) (result TaskResult, err error) {
			for {
				if t.Aborted() {
					break
				}
				fmt.Println("Forever young...")
				time.Sleep(time.Duration(10) * time.Millisecond)
			}
			return "I want to be forever young", nil
		}, nil, time.Duration(100)*time.Millisecond,
	)
	require.Nil(t, err)

	time.Sleep(time.Duration(200) * time.Millisecond)
	// by now single should finish on timeout
	err = single.Abort()
	fmt.Println("Aborted")

	// Nothing wrong should happen after this point...
	time.Sleep(time.Duration(1000) * time.Millisecond)

	require.Nil(t, err)

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	// Here, last 2 lines of the output should be:
	// Forever young...
	// Aborted

	outString := string(out)
	nah := strings.Split(outString, "\n")
	if !strings.Contains(nah[len(nah)-2], "Aborted") {
		t.Fail()
	}
}

func TestAbortButThisTimeUsingTrueAbortChannel(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	single, err := NewTask(nil)
	require.NotNil(t, single)
	require.Nil(t, err)

	trueAbort := make(chan struct{})
	single, err = single.StartWithTimeout(
		func(t Task, parameters TaskParameters) (result TaskResult, err error) {
			forever := true
			for forever {
				select {
				case <-trueAbort:
					fmt.Println("I'm Gotham's reckoning. Here to end the borrowed time you all have been living on.")
					forever = false
					break
				default:
					fmt.Println("Forever young...")
					time.Sleep(time.Duration(10) * time.Millisecond)
				}
			}
			return "I want to be forever young", nil
		}, nil, time.Duration(40)*time.Millisecond,
	)
	require.Nil(t, err)

	time.Sleep(time.Duration(200) * time.Millisecond)

	err = single.Abort()
	trueAbort <- struct{}{}

	fmt.Println("Aborted")

	require.Nil(t, err)

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
}
