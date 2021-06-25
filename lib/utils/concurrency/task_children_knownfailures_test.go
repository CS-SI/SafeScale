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
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

// tasks with subtasks don't play well with aborts
func TestAbortFatherTask(t *testing.T) {
	parent, err := NewTask()
	require.NotNil(t, parent)
	require.Nil(t, err)

	count := 0

	child, err := parent.StartInSubtask(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(400) * time.Millisecond)
		if t.Aborted() {
			return "A", nil
		}
		count++
		return "B", nil
	}, nil)
	require.Nil(t, err)

	sibling, err := parent.StartInSubtask(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(500) * time.Millisecond)
		if t.Aborted() {
			return "A", nil
		}
		count++
		return "B", nil
	}, nil)
	require.Nil(t, err)

	time.Sleep(time.Duration(50) * time.Millisecond)

	err = parent.Abort()
	require.Nil(t, err)

	require.True(t, parent.Aborted())

	_ = parent
	_ = child
	_ = sibling
}

// taskgroups work well instead
func TestAbortFatherTaskGroup(t *testing.T) {
	parent, err := NewTaskGroupWithParent(nil)
	require.NotNil(t, parent)
	require.Nil(t, err)

	count := 0

	child, err := parent.StartInSubtask(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(400) * time.Millisecond)
		if t.Aborted() {
			return "A", nil
		}
		count++
		return "B", nil
	}, nil)
	require.Nil(t, err)

	sibling, err := parent.StartInSubtask(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(500) * time.Millisecond)
		if t.Aborted() {
			return "A", nil
		}
		count++
		return "B", nil
	}, nil)
	require.Nil(t, err)

	time.Sleep(time.Duration(50) * time.Millisecond)

	err = parent.Abort()
	require.Nil(t, err)

	require.True(t, parent.Aborted())

	_ = parent
	_ = child
	_ = sibling
}
