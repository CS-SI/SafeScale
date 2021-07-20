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
func TestTaskGroupFatherAbortion(t *testing.T) {
	overlord, xerr := NewTaskGroup()
	_ = overlord.SetID("/overlord")
	require.NotNil(t, overlord)
	require.Nil(t, xerr)

	count := 0

	child, xerr := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		fmt.Println("child started.")
		time.Sleep(time.Duration(400) * time.Millisecond)
		fmt.Println("Evaluating...")
		if t.Aborted() {
			fmt.Println("child aborts.")
			return "A", fail.AbortedError(nil)
		}
		count++
		fmt.Println("child done.")
		return "B", nil
	}, nil, InheritParentIDOption, AmendID("/child"))
	require.Nil(t, xerr)

	sibling, xerr := overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
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

	time.Sleep(time.Duration(50) * time.Millisecond) // definitively weird: with 40ms of sleep, everything is working as expected...
	// something occurs after 40ms that delay channel read with select...
	xerr = overlord.Abort()
	require.Nil(t, xerr)

	res, xerr := child.Wait()
	require.NotNil(t, xerr)
	require.NotNil(t, res)

	res, xerr = sibling.Wait()
	require.NotNil(t, xerr)
	require.NotNil(t, res)

	require.Equal(t, 0, count)

	_, xerr = overlord.Wait()
	require.NotNil(t, xerr)
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
	require.NotNil(t, xerr) // parent aborted, child should report aborted error also, even if it doesn't really processed the signal
	switch xerr.(type) {
	case *fail.ErrAborted:
		// expected
	default:
		t.Errorf("Unexpected error for child: %v", xerr)
	}

	_, xerr = sibling.Wait()
	require.NotNil(t, xerr) // parent aborted, sibling should report aborted error also, even if it doesn't really processed the signal
	switch xerr.(type) {
	case *fail.ErrAborted:
		// expected
	default:
		t.Errorf("Unexpected error for sibling: %v", xerr)
	}

	// the subtasks keep working because don't listen to abort
	time.Sleep(time.Duration(600) * time.Millisecond)
	require.Equal(t, 2, len(count))

	_, xerr = parent.Wait()
	require.NotNil(t, xerr) // parent aborted, should report aborter error
	switch xerr.(type) {
	case *fail.ErrAborted:
		// expected
	default:
		t.Errorf("Unexpected error for sibling: %v", xerr)
	}
}

// make sure that if subtasks listen, aborting a parent also aborts its children
func TestTaskFatherAbortionLater(t *testing.T) {
	overlord, xerr := NewTaskGroup()
	require.NotNil(t, overlord)
	require.Nil(t, xerr)

	xerr = overlord.SetID("/overlord")
	require.Nil(t, xerr)

	count := make(chan int, 4)

	_, xerr = overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(400) * time.Millisecond)
		fmt.Println("Evaluating...")
		if t.Aborted() {
			return "A", fail.AbortedError(nil)
		}
		count <- 1
		return "B", nil
	}, nil, InheritParentIDOption, AmendID("/child"))
	require.Nil(t, xerr)

	_, xerr = overlord.Start(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(500) * time.Millisecond)
		fmt.Println("Evaluating...")
		if t.Aborted() {
			return "A", fail.AbortedError(nil)
		}
		count <- 1
		return "B", nil
	}, nil, InheritParentIDOption, AmendID("/sibling"))
	require.Nil(t, xerr)

	go func() {
		time.Sleep(time.Duration(200) * time.Millisecond) // definitively weird: with 40ms of sleep, everything is working as expected...
		// something occurs after 40ms that delay channel read with select...
		fmt.Println("Aborting...")
		_ = overlord.Abort()
		return
	}()

	_, xerr = overlord.WaitGroup()
	require.NotNil(t, xerr)

	require.Equal(t, 0, len(count))
}
