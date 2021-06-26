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
	done, res, err := single.TryWait()
	end := time.Since(begin)

	require.True(t, done)
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

		single, xerr := NewTaskWithContext(ctx)
		require.NotNil(t, single)
		require.Nil(t, xerr)

		begin := time.Now()

		single, xerr = single.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			tempo := sleep / 100
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
			time.Sleep(trigger)
			cafu()
		}()

		_, xerr = single.Wait()
		end := time.Since(begin)
		// VPL: what's the point? We raise an error in the switch later...
		// if xerr != nil {
		// 	if !strings.Contains(xerr.Error(), "abort") {
		// 		t.Errorf("Why so serious? it's just a failure cancelling a goroutine: %s", xerr.Error())
		// 	}
		// }

		if errorExpected {
			require.NotNil(t, xerr)
			switch xerr.(type) {
			case *fail.ErrAborted:
			case *fail.ErrTimeout:
			default:
				t.Errorf("Failure in test: %v, %v, %v, %t", timeout, sleep, trigger, errorExpected)
			}
		} else {
			require.Nil(t, xerr)
		}

		if !((xerr != nil) == errorExpected) {
			t.Errorf("Failure in test: %v, %v, %v, %t", timeout, sleep, trigger, errorExpected)
		}
		require.True(t, (xerr != nil) == errorExpected)

		// the minimum of the 3 wins, so
		min := math.Min(math.Min(float64(timeout), float64(sleep)), float64(trigger))

		if end > time.Duration(min+10)*time.Millisecond {
			t.Errorf("Failure in test: %v, %v, %v, %t: We waited too much! %v > %v", timeout, sleep, trigger, errorExpected, end, trigger+20*time.Millisecond)
		}
	}

	// No errors here, look at TestChildrenWaitingGameWithContextCancelfuncs for more information
	// there is a performance degradation problem in Task/TaskGroup that impact the timings
	funk(30*time.Millisecond, 50*time.Millisecond, 10*time.Millisecond, true)   // abort (canceled)
	funk(30*time.Millisecond, 50*time.Millisecond, 80*time.Millisecond, true)   // timeout
	funk(80*time.Millisecond, 50*time.Millisecond, 10*time.Millisecond, true)   // abort (canceled)
	funk(40*time.Millisecond, 20*time.Millisecond, 10*time.Millisecond, true)   // abort (canceled)
	funk(40*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, false)  // no error (cancel is triggered AFTER we are done (in 20ms), less that the timeout)
	funk(140*time.Millisecond, 20*time.Millisecond, 40*time.Millisecond, false) // same thing here
	funk(140*time.Millisecond, 50*time.Millisecond, 10*time.Millisecond, true)  // abort (canceled)
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
	funk(7, 14, 2, 4, true)
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
					time.Sleep(time.Duration(tools.RandomInt(20, 30)) * time.Millisecond)
					if t.Aborted() {
						// Cleaning up first before leaving... ;)
						time.Sleep(time.Duration(tools.RandomInt(100, 800)) * time.Millisecond)
						break
					}
				}

				// We are using the classic 'send on closed channel' trick to see if Wait actually waits until everyone is DONE.
				// If it does we will never see a panic, but if Abort doesn't mean TellYourChildrenToAbort but
				// actually means AbortYourChildrenAndQuitNOWWithoutWaiting, then we have a problem
				acha := parameters.(chan string)
				acha <- "Bailing out"

				// flip a coin, true and we panic, false we don't
				if tools.RandomInt(0, 2) == 1 {
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

		/*res*/ _, xerr = single.Wait() // 100 ms after this, .Abort() should hit
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
		time.Sleep(1*time.Second)
		return nil, nil
	}, nil)
	require.Nil(b, xerr)

	for i := 0; i < b.N; i++ {
		_, _, xerr = single.TryWait()
	}
}