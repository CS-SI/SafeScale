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

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

// Tasks with patent Task don't play well with parent aborts
func TestAbortNotStartedTask(t *testing.T) {
	parent, xerr := NewTask()
	require.NotNil(t, parent)
	require.Nil(t, xerr)

	xerr = parent.SetID("/parent")
	require.Nil(t, xerr)

	child, xerr := NewTaskWithParent(parent)
	require.Nil(t, xerr)
	_, xerr = child.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(400) * time.Millisecond)
		if t.Aborted() {
			return "A", fail.AbortedError(nil)
		}
		return "B", nil
	}, nil, InheritParentIDOption, AmendID("/child"))
	require.Nil(t, xerr)

	time.Sleep(time.Duration(50) * time.Millisecond)

	// parent is not started, cannot ask it to Abort...
	xerr = parent.Abort()
	require.NotNil(t, xerr)

	// and should not return true if asked if it has been Aborted
	require.False(t, parent.Aborted())

	// abort signal not sent by parent task
	require.False(t, child.Aborted())

	// Now abort the child
	xerr = child.Abort()
	require.Nil(t, xerr)

	// abort signal sent directly to child
	require.True(t, child.Aborted())

	// Waiting parent should return *fail.ErrAborted
	res, xerr := parent.Wait()
	require.NotNil(t, xerr)
	require.Nil(t, res) // Nothing produced, so no result

	// child received abort signal, so it finished abnormally
	res, xerr = child.Wait()
	require.NotNil(t, xerr)
	require.NotNil(t, res)
}

func TestAbortStartedTaskWithChildren(t *testing.T) {
	iter := 8
	for i := 0; i < iter; i++ {
		fmt.Println("--- NEXT ---")

		parent, xerr := NewTask()
		require.NotNil(t, parent)
		require.Nil(t, xerr)

		xerr = parent.SetID("/parent")
		require.Nil(t, xerr)

		_, xerr = parent.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(700) * time.Millisecond)
			return "B", nil
		}, nil)
		require.Nil(t, xerr)

		child, xerr := NewTaskWithParent(parent)
		require.Nil(t, xerr)
		_, xerr = child.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(400) * time.Millisecond)
			if t.Aborted() {
				return "A", fail.AbortedError(nil)
			}
			return "B", nil
		}, nil, InheritParentIDOption, AmendID("/child"))
		require.Nil(t, xerr)

		sibling, xerr := NewTaskWithParent(parent)
		require.Nil(t, xerr)
		_, xerr = sibling.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(500) * time.Millisecond)
			if t.Aborted() {
				return "A", fail.AbortedError(nil)
			}
			return "B", nil
		}, nil, InheritParentIDOption, AmendID("/sibling"))
		require.Nil(t, xerr)

		time.Sleep(time.Duration(50) * time.Millisecond)

		xerr = parent.Abort() // Abort the stated parent, should succeed
		require.Nil(t, xerr)

		time.Sleep(10 * time.Millisecond) // let abort propagation occurs
		require.True(t, parent.Aborted()) // parent should be aborted
		require.True(t, child.Aborted())
		require.True(t, sibling.Aborted())

		res, xerr := parent.Wait()
		require.NotNil(t, xerr) // parent aborted, should return *fail.ErrAborted
		if res == nil {
			t.Errorf("result is nil, it shouldn't (xerr = %v (%s))", xerr, reflect.TypeOf(xerr).String())
		}
		require.NotNil(t, res) // result produced, must not be nil

		res, xerr = child.Wait() // parent.Wait() should have told child to terminate on abort
		require.NotNil(t, xerr)  // should return *fail.ErrAborted
		require.NotNil(t, res)   // result produced, must bot be nil

		res, xerr = sibling.Wait() // idem for sibling
		require.NotNil(t, xerr)
		require.NotNil(t, res)
	}
}

// Taskgroups work well instead
func TestAbortFatherTaskGroup(t *testing.T) {
	iter := 8
	for i := 0; i < iter; i++ {
		fmt.Println("--- NEXT ---")

		overlord, xerr := NewTaskGroup()
		require.NotNil(t, overlord)
		require.Nil(t, xerr)

		xerr = overlord.SetID("/overlord")
		require.Nil(t, xerr)

		aborted := overlord.Aborted()
		if aborted {
			t.Errorf("Not started TaskGroup cannot be aborted on iter #%d", i)
			t.FailNow()
		}

		xerr = overlord.Abort() // Not started TaskGroup can be aborted
		require.Nil(t, xerr)

		aborted = overlord.Aborted()
		if !aborted {
			t.Errorf("Not started TaskGroup that has been aborted should report it on iter #%d", i)
			t.FailNow()
		}

		// aborted not started TaskGroup cannot start anything
		_, xerr = overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(400) * time.Millisecond)
			if t.Aborted() {
				return "A", fail.AbortedError(nil)
			}
			return "B", nil
		}, nil, InheritParentIDOption, AmendID("/child"))
		require.NotNil(t, xerr)

		// create new TaskGroup
		overlord, xerr = NewTaskGroup()
		require.NotNil(t, overlord)
		require.Nil(t, xerr)

		xerr = overlord.SetID("/overlord")
		require.Nil(t, xerr)

		_, xerr = overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(400) * time.Millisecond)
			if t.Aborted() {
				return "A", fail.AbortedError(nil)
			}
			return "B", nil
		}, nil, InheritParentIDOption, AmendID("/child"))
		require.Nil(t, xerr)

		_, xerr = overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
			time.Sleep(time.Duration(500) * time.Millisecond)
			if t.Aborted() {
				return "A", fail.AbortedError(nil)
			}
			return "B", nil
		}, nil, InheritParentIDOption, AmendID("/sibling"))
		require.Nil(t, xerr)

		time.Sleep(time.Duration(50) * time.Millisecond)
		xerr = overlord.Abort()
		require.Nil(t, xerr)

		aborted = overlord.Aborted()
		if !aborted {
			t.Errorf("not aborted on iter #%d", i)
			t.FailNow()
		}

		res, xerr := overlord.Wait()
		require.NotNil(t, xerr)
		require.NotNil(t, res)
	}
}
