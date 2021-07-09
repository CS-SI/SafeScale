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
	"reflect"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

// Do we handle the results well ??
func TestKeepRecords(t *testing.T) {
	iter := 0

	for {
		iter++
		if iter > 4 {
			break
		}

		t.Log("Next") // Each time we iterate we see this line, sometimes this doesn't fail at 1st iteration
		overlord, xerr := NewTaskGroup()
		require.NotNil(t, overlord)
		require.Nil(t, xerr)
		xerr = overlord.SetID(fmt.Sprintf("/parent-%d", iter))
		require.Nil(t, xerr)

		for ind := 0; ind < 5; ind++ { // work with 5 tasks
			_, xerr = overlord.Start(
				func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
					mylimit := randomInt(5, 15)
					for { // iterate only a few times: mylimit
						// some work
						time.Sleep(time.Duration(randomInt(20, 30)) * time.Millisecond)

						if t.Aborted() || mylimit <= 0 {
							// Cleaning up first before leaving... ;)
							time.Sleep(time.Duration(randomInt(100, 800)) * time.Millisecond)
							break
						}

						mylimit--
					}

					// flip a coin, true and there is an error, false if it's not
					if randomInt(0, 2) == 1 {
						return "mistakes happen", fail.NewError("It was head")
					}

					return "who cares", nil
				}, nil, InheritParentIDOption, AmendID(fmt.Sprintf("/child-%d", ind)),
			)
			require.Nil(t, xerr)
		}

		// wait a little until we call wait
		time.Sleep(time.Duration(100) * time.Millisecond)

		res, xerr := overlord.Wait()
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrAborted:
				t.Errorf("Seriously ?, Are we confusing that a group is aborted and that are reported errors in the results ??, nobody is aborting in this test")
				t.FailNow()
			case *fail.ErrTimeout:
				t.Logf("%v", xerr)
			case *fail.ErrorList:
				t.Logf("%v", xerr)
			default:
				t.Errorf("Unexpected error: %v", xerr)
				t.FailNow()
			}
		} else {
			require.NotNil(t, res)
			require.NotEmpty(t, res)
		}
	}
}

// Same as before but now with timeouts
func TestKeepRecordsWhenTimeouts(t *testing.T) {
	iter := 0

	for {
		iter++
		if iter > 4 {
			break
		}

		t.Log("Next") // Each time we iterate we see this line, sometimes this doesn't fail at 1st iteration
		overlord, xerr := NewTaskGroup()
		require.NotNil(t, overlord)
		require.Nil(t, xerr)
		xerr = overlord.SetID(fmt.Sprintf("/parent-%d", iter))
		require.Nil(t, xerr)

		for ind := 0; ind < 10; ind++ { // work with 10 tasks
			_, xerr = overlord.Start(
				func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
					mylimit := randomInt(5, 15)
					for { // iterate only a few times: mylimit
						// some work
						time.Sleep(time.Duration(randomInt(20, 30)) * time.Millisecond)

						if t.Aborted() || mylimit <= 0 {
							// Cleaning up first before leaving... ;)
							time.Sleep(time.Duration(randomInt(100, 800)) * time.Millisecond)
							break
						}

						mylimit--
					}

					// flip a coin, true and there is an error, false if it's not
					if randomInt(0, 2) == 1 {
						return "mistakes happen", fail.NewError("It was head")
					}

					return "who cares", nil
				}, nil, InheritParentIDOption, AmendID(fmt.Sprintf("/child-%d", ind)),
			)
			require.Nil(t, xerr)
		}

		for ind := 0; ind < 10; ind++ { // and 10 unfortunate ones that will likely timeout
			_, xerr = overlord.StartWithTimeout(
				func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
					mylimit := randomInt(5, 15)
					for { // iterate only a few times: mylimit
						// some work
						time.Sleep(time.Duration(randomInt(20, 30)) * time.Millisecond)

						if t.Aborted() || mylimit <= 0 {
							// Cleaning up first before leaving... ;)
							time.Sleep(time.Duration(randomInt(100, 800)) * time.Millisecond)
							break
						}

						mylimit--
					}

					// flip a coin, true and there is an error, false if it's not
					if randomInt(0, 2) == 1 {
						return "too late", fail.NewError("It was head")
					}

					return "who cares about timeout", nil
				}, nil, 100*time.Millisecond, InheritParentIDOption, Normalizer(), AmendID(fmt.Sprintf("/child-with-timeout-%d", ind)),
			)
			require.Nil(t, xerr)
		}

		// wait a little until we call wait
		time.Sleep(time.Duration(100) * time.Millisecond)

		res, xerr := overlord.Wait()
		if xerr != nil {
			switch cerr := xerr.(type) {
			case *fail.ErrAborted:
				t.Errorf("Seriously ?, Are we confusing that a group is aborted and that are reported errors in the results ??, nobody is aborting in this test")
				t.FailNow()
			case *fail.ErrTimeout:
				t.Logf("%v (%s)", xerr, reflect.TypeOf(xerr).String())
			case *fail.ErrorList:
				for _, v := range cerr.ToErrorSlice() {
					t.Logf("%s (%s)", v.Error(), reflect.TypeOf(v).String())
				}
			default:
				t.Errorf("Unexpected error: %v (%s)", xerr, reflect.TypeOf(xerr).String())
				t.FailNow()
			}
		} else {
			require.NotNil(t, res)
			require.NotEmpty(t, res)
		}
	}
}

func Normalizer() data.ImmutableKeyValue {
	return data.NewImmutableKeyValue("normalize_error", func(err error) error {
		if err != nil {
			switch err.(type) {
			case *fail.ErrNotFound:
				return nil
			default:
			}
		}
		return err
	})
}
