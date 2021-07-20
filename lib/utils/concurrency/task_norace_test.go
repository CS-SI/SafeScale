// +build !race

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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestAbortThatActuallyTakeTimeCleaningUpAndFailWhenWeAlreadyStartedWaitingWF(t *testing.T) {
	enough := false
	iter := 0
	panicReported := false

	for !enough {
		iter++
		if iter > 8 {
			break
		}

		t.Log("--- Next ---") // Each time we iterate we see this line, sometimes this doesn't fail at 1st iteration
		single, xerr := NewTask()
		require.NotNil(t, single)
		require.Nil(t, xerr)

		bailout := make(chan string, 80) // a buffered channel

		_, xerr = single.Start(taskgenWithCustomFunc(20, 50, 10, 2, 0.5, 0, false, func(in chan string) error {
			in <- "Bailing out"
			return nil
		}), bailout)
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
		_, _, xerr = single.WaitFor(5 * time.Second) // 100 ms after this, .Abort() should hit
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
		go func(in chan string) {
			close(in) // If Wait actually waits, this is closed AFTER all Tasks filled the channel, so no panics
		}(bailout)
		// If not..., well...

		if panicReported {
			enough = true
		}
		time.Sleep(600 * time.Millisecond)
	}
	if !panicReported {
		t.Logf("No panic reported, good")
	} else {
		t.Errorf("panics have been reported, bad!!!")
	}
}

func TestAbortThatActuallyTakeTimeCleaningUpAndFailWhenWeAlreadyStartedWaiting(t *testing.T) {
	enough := false
	iter := 0
	panicReported := false

	for !enough {
		iter++
		if iter > 8 {
			break
		}

		t.Log("--- Next ---") // Each time we iterate we see this line, sometimes this doesn't fail at 1st iteration
		single, xerr := NewTask()
		require.NotNil(t, single)
		require.Nil(t, xerr)

		bailout := make(chan string, 80) // a buffered channel

		_, xerr = single.Start(taskgenWithCustomFunc(20, 50, 10, 2, 0.5, 0, false, func(in chan string) error {
			in <- "Bailing out"
			return nil
		}), bailout)
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
		go func(in chan string) {
			close(in) // If Wait actually waits, this is closed AFTER all Tasks filled the channel, so no panics
		}(bailout)
		// If not..., well...

		if panicReported {
			enough = true
		}
		time.Sleep(600 * time.Millisecond)
	}
	if !panicReported {
		t.Logf("No panic reported, good")
	} else {
		t.Errorf("panics have been reported, bad!!!")
	}
}
