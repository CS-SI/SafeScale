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

	"github.com/stretchr/testify/require"
)

func generator() Task {
	return &task{}
}

func tgGenerator() TaskGroup {
	return &taskGroup{}
}

func IsATask(i interface{}) bool {
	if _, ok := i.(Task); ok {
		return true
	}
	if _, ok := i.(*Task); ok {
		return true
	}
	return false
}

func IsATaskGroup(i interface{}) bool {
	if _, ok := i.(TaskGroup); ok {
		return true
	}
	if _, ok := i.(*TaskGroup); ok {
		return true
	}
	return false
}

func TestAGroupIsATask(t *testing.T) {
	require.False(t, IsATask(taskGroup{}))
}

func TestATaskIsAGroup(t *testing.T) {
	require.False(t, IsATaskGroup(task{}))
}

func TestAGroupIsATask2(t *testing.T) {
	require.True(t, IsATask(&taskGroup{}))
}

func TestATaskIsAGroup2(t *testing.T) {
	require.False(t, IsATaskGroup(&task{}))
}

func TestInvalidTask(t *testing.T) {
	got := generator()

	_, err := got.IsSuccessful()
	require.NotNil(t, err)

	_, err = got.Result()
	require.NotNil(t, err)

	_, _, err = got.WaitFor(0)
	require.NotNil(t, err)

	err = got.Abort()
	require.NotNil(t, err)

	_, err = got.Abortable()
	require.NotNil(t, err)

	got.Aborted()

	_ = got.DisarmAbortSignal()

	_, err = got.ID()
	require.NotNil(t, err)

	_ = got.Signature()

	_, err = got.Status()
	require.NotNil(t, err)

	_ = got.Context()
	require.NotNil(t, err)

	_, err = got.LastError()
	require.NotNil(t, err)

	_, err = got.Result()
	require.NotNil(t, err)

	err = got.SetID("")
	require.NotNil(t, err)

	_, err = got.Run(nil, nil)
	require.NotNil(t, err)

	_, err = got.Start(nil, nil)
	require.NotNil(t, err)

	_, err = got.StartWithTimeout(nil, nil, 0)
	require.NotNil(t, err)

	_, err = got.Start(nil, nil)
	require.NotNil(t, err)

	_, err = got.Wait()
	require.NotNil(t, err)

	_, _, err = got.TryWait()
	require.NotNil(t, err)
}

func TestInvalidTaskCtx(t *testing.T) {
	ta, err := NewTaskWithContext(nil)
	require.Nil(t, ta)
	require.NotNil(t, err)
}

func TestInvalidTaskGroup(t *testing.T) {
	got := tgGenerator()

	err := got.Abort()
	require.NotNil(t, err)

	_, err = got.Abortable()
	require.NotNil(t, err)

	got.Aborted()

	_ = got.DisarmAbortSignal()

	_, err = got.ID()
	require.NotNil(t, err)

	_ = got.Signature()

	_, err = got.Status()
	require.NotNil(t, err)

	_ = got.Context()
	require.NotNil(t, err)

	_, err = got.LastError()
	require.NotNil(t, err)

	_, err = got.Result()
	require.NotNil(t, err)

	err = got.SetID("")
	require.NotNil(t, err)

	_, err = got.Run(nil, nil)
	require.NotNil(t, err)

	_, err = got.Start(nil, nil)
	require.NotNil(t, err)

	_, err = got.StartWithTimeout(nil, nil, 0)
	require.NotNil(t, err)

	_, err = got.Wait()
	require.NotNil(t, err)

	_, _, err = got.WaitGroupFor(0)
	require.NotNil(t, err)

	_, _, err = got.WaitGroupFor(5 * time.Second)
	require.NotNil(t, err)

	_, err = got.WaitGroup()
	require.NotNil(t, err)

	_, _, err = got.TryWaitGroup()
	require.NotNil(t, err)
}
