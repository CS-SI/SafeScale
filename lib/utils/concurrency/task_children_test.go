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
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

// make sure children cannot wait after father is aborted
func TestTaskFatherAbortion(t *testing.T) {
	parent, xerr := NewTaskGroup()
	_ = parent.SetID("/parent")
	require.NotNil(t, parent)
	require.Nil(t, xerr)

	xerr = parent.SetID("/parent")
	require.Nil(t, xerr)

	count := 0

	child, xerr := parent.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		fmt.Println("child started.")
		time.Sleep(time.Duration(400) * time.Millisecond)
		if t.Aborted() {
			fmt.Println("child aborts.")
			return "A", fail.AbortedError(nil)
		}
		count++
		fmt.Println("child done.")
		return "B", nil
	}, nil, InheritParentIDOption, AmendID("/child"))
	require.Nil(t, xerr)

	sibling, xerr := parent.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		fmt.Println("sibling started.")
		time.Sleep(time.Duration(500) * time.Millisecond)
		fmt.Println("Evaluating...")
		if t.Aborted() {
			fmt.Println("sibling aborts.")
			return "A", fail.AbortedError(nil)
		}
		count++
		fmt.Println("sibling done.")
		return "B", nil
	}, nil, InheritParentIDOption, AmendID("/sibling"))
	require.Nil(t, xerr)

	time.Sleep(time.Duration(50) * time.Millisecond)

	xerr = parent.Abort()
	require.Nil(t, xerr)

	_, xerr = child.Wait()
	require.NotNil(t, xerr)
	_, xerr = sibling.Wait()
	require.NotNil(t, xerr)

	require.Equal(t, 0, count)
}

// if a children doesn't listen to abort, it keeps running
func TestTaskFatherAbortionNoAbort(t *testing.T) {
	parent, xerr := NewTaskGroup()
	require.NotNil(t, parent)
	require.Nil(t, xerr)
	xerr = parent.SetID("/parent")
	require.Nil(t, xerr)

	count := make(chan int, 4)

	child, xerr := parent.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(400) * time.Millisecond)
		count <- 1
		return "B", nil
	}, nil, InheritParentIDOption, AmendID("/child"))
	require.Nil(t, xerr)

	sibling, xerr := parent.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(500) * time.Millisecond)
		fmt.Println("Evaluating...")
		count <- 1
		return "B", nil
	}, nil, InheritParentIDOption, AmendID("/sibling)"))
	require.Nil(t, xerr)

	time.Sleep(time.Duration(50) * time.Millisecond)

	xerr = parent.Abort()
	require.Nil(t, xerr)

	_, xerr = child.Wait()
	require.Nil(t, xerr)
	_, xerr = sibling.Wait()
	require.Nil(t, xerr)

	// the subtasks keep working because don't listen to abort
	time.Sleep(time.Duration(600) * time.Millisecond)
	require.Equal(t, 2, len(count))
}

// make sure that if subtasks listen, aborting a parent also aborts its children
func TestTaskFatherAbortionLater(t *testing.T) {
	parent, xerr := NewTaskGroup()
	require.NotNil(t, parent)
	require.Nil(t, xerr)

	xerr = parent.SetID("/parent")
	require.Nil(t, xerr)

	count := make(chan int, 4)

	_, xerr = parent.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(400) * time.Millisecond)
		fmt.Println("Evaluating...")
		if t.Aborted() {
			return "A", fail.AbortedError(nil)
		}
		count <- 1
		return "B", nil
	}, nil, InheritParentIDOption, AmendID("/child"))
	require.Nil(t, xerr)

	_, xerr = parent.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(500) * time.Millisecond)
		fmt.Println("Evaluating...")
		if t.Aborted() {
			return "A", fail.AbortedError(nil)
		}
		count <- 1
		return "B", nil
	}, nil)
	require.Nil(t, xerr)

	go func() {
		time.Sleep(time.Duration(200) * time.Millisecond)
		fmt.Println("Aborting...")
		_ = parent.Abort()
		return
	}()

	_, xerr = parent.WaitGroup()
	require.NotNil(t, xerr)

	require.Equal(t, 0, len(count))
}
