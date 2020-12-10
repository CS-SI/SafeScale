/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"strconv"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// TaskGroupResult is a map of the TaskResult of each task
// The index is the ID of the sub-Task running the action.
type TaskGroupResult map[string]TaskResult

// TaskGroupGuard is the task group interface defining method to wait the taskgroup
type TaskGroupGuard interface {
	TryWaitGroup() (bool, map[string]TaskResult, fail.Error)
	WaitGroup() (map[string]TaskResult, fail.Error)
	WaitGroupFor(time.Duration) (bool, map[string]TaskResult, fail.Error)
}

//go:generate moq -out taskgroup_moq_test.go . TaskGroup

// TaskGroup is the task group interface
type TaskGroup interface {
	TaskCore
	TaskGroupGuard

	Stats() (map[TaskStatus][]string, fail.Error)
}

// task is a structure allowing to identify (indirectly) goroutines
type taskGroup struct {
	last uint
	*task
	result TaskGroupResult

	subtasksLock TaskedLock
	subtasks     []Task
}

// NewTaskGroup ...
func NewTaskGroup(parentTask Task) (*taskGroup, fail.Error) { // nolint
	return newTaskGroup(context.TODO(), parentTask)
}

// NewTaskGroupWithParent ...
func NewTaskGroupWithParent(parentTask Task) (*taskGroup, fail.Error) { // nolint
	return newTaskGroup(context.TODO(), parentTask)
}

// NewTaskGroupWithContext ...
func NewTaskGroupWithContext(ctx context.Context, parentTask Task) (*taskGroup, fail.Error) { // nolint
	return newTaskGroup(ctx, parentTask)
}

func newTaskGroup(ctx context.Context, parentTask Task) (tg *taskGroup, err fail.Error) {
	var t Task

	if parentTask == nil {
		if ctx == nil {
			t, err = NewTask()
		} else {
			t, err = NewTaskWithContext(ctx, nil)
		}
	} else {
		switch parentTask := parentTask.(type) {
		case *task:
			p := parentTask
			t, err = NewTaskWithParent(p)
		case *taskGroup:
			p := parentTask
			t, err = NewTaskWithParent(p.task)
		}
	}
	tg = &taskGroup{
		task:         t.(*task),
		subtasksLock: NewTaskedLock(),
	}
	return tg, err
}

// IsNull ...
func (tg *taskGroup) IsNull() bool {
	return tg == nil || tg.task.IsNull()
}

// GetID returns an unique id for the task
func (tg *taskGroup) GetID() (string, fail.Error) {
	if tg.IsNull() {
		return "", fail.InvalidInstanceError()
	}

	return tg.task.GetID()
}

// GetSignature builds the "signature" of the task group, ie a string representation of the task ID in the format "{taskgroup <id>}".
func (tg *taskGroup) GetSignature() string {
	if tg.IsNull() {
		return ""
	}

	tid, err := tg.GetID()
	if err != nil {
		return ""
	}

	return `{taskgroup ` + tid + `}`
}

// GetStatus returns the current task status
func (tg *taskGroup) GetStatus() (TaskStatus, fail.Error) {
	if tg.IsNull() {
		return TaskStatus(0), fail.InvalidInstanceError()
	}

	return tg.task.GetStatus()
}

// GetContext returns the current task status
func (tg *taskGroup) GetContext() (context.Context, fail.Error) {
	if tg.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	return tg.task.GetContext()
}

// SetID allows to specify task ID. The uniqueness of the ID through all the tasks
// becomes the responsibility of the developer...
func (tg *taskGroup) SetID(id string) fail.Error {
	if tg.IsNull() {
		return fail.InvalidInstanceError()
	}

	return tg.task.SetID(id)
}

func (tg *taskGroup) StartInSubtask(action TaskAction, params TaskParameters) (Task, fail.Error) {
	if tg.IsNull() {
		return tg, fail.InvalidInstanceError()
	}

	return tg.Start(action, params)
}

// Start runs in goroutine the function with parameters
// Each sub-Task created has its ID forced to TaskGroup ID + "-<index>".
func (tg *taskGroup) Start(action TaskAction, params TaskParameters) (Task, fail.Error) {
	if tg.IsNull() {
		return tg, fail.InvalidInstanceError()
	}

	status, err := tg.task.GetStatus()
	if err != nil {
		return tg, err
	}

	tg.last++
	subtask, err := NewTaskWithParent(tg.task)
	if err != nil {
		return tg, err
	}

	if err = subtask.SetID(tg.task.id + "-" + strconv.Itoa(int(tg.last))); err != nil {
		return tg, err
	}

	if subtask, err = subtask.Start(action, params); err != nil {
		return tg, err
	}

	tg.subtasksLock.SafeLock(tg.task)
	defer tg.subtasksLock.SafeUnlock(tg.task)

	tg.subtasks = append(tg.subtasks, subtask)
	if status != RUNNING {
		tg.task.mu.Lock()
		tg.task.status = RUNNING
		tg.task.mu.Unlock()
	}
	return tg, nil
}

// Wait ...
func (tg *taskGroup) Wait() (TaskResult, fail.Error) {
	if tg.IsNull() {
		return tg, fail.InvalidInstanceError()
	}
	return tg.WaitGroup()
}

// WaitGroup waits for the task to end, and returns the error (or nil) of the execution
// Note: this function may lead to go routine leaks, because we do not want a taskgroup to be locked because of
//       a subtask not responding; if a subtask is designed to run forever, it will never end.
//       It's highly recommended to use task.Aborted() in the body of a task to check
//       for abortion signal and quit the go routine accordingly to reduce the risk (a taskgroup remains abortable with
//       this recommandation).
func (tg *taskGroup) WaitGroup() (map[string]TaskResult, fail.Error) {
	if tg.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	tid, err := tg.GetID()
	if err != nil {
		return nil, err
	}

	taskStatus, err := tg.task.GetStatus()
	if err != nil {
		return nil, err
	}

	errs := make(map[string]string)
	results := make(map[string]TaskResult)

	if taskStatus == DONE {
		tg.task.mu.Lock()
		defer tg.task.mu.Unlock()

		results[tid] = tg.result
		return results, tg.task.err
	}
	if taskStatus == ABORTED {
		var errors []error

		tg.task.mu.Lock()
		if tg.task.err != nil {
			errors = append(errors, tg.task.err)
		}
		tg.task.mu.Unlock()

		tg.subtasksLock.SafeLock(tg.task)
		defer tg.subtasksLock.SafeUnlock(tg.task)

		for _, s := range tg.subtasks {
			lerr, _ := s.GetLastError()
			if lerr != nil {
				errors = append(errors, lerr)
			}
		}
		return nil, fail.AbortedError(fail.NewErrorList(errors), "taskgroup was already aborted")
	}
	if taskStatus != RUNNING && taskStatus != READY {
		return nil, fail.ForbiddenError("cannot wait task group '%s': not running", tid)
	}

	tg.subtasksLock.SafeLock(tg.task)
	defer tg.subtasksLock.SafeUnlock(tg.task)

	doneWaitSize := len(tg.subtasks)
	doneWaitStates := make(map[int]bool, doneWaitSize)
	for k := range tg.subtasks {
		doneWaitStates[k] = false
	}
	doneWaitCount := 0

	for {
		stop := false
		for k, s := range tg.subtasks {
			if tg.Aborted() {
				stop = true
				break
			}

			if doneWaitStates[k] {
				continue
			}

			sid, err := s.GetID()
			if err != nil {
				continue
			}

			done, result, err := s.TryWait()
			if done {
				if err != nil {
					errs[sid] = err.Error()
				}

				results[sid] = result
				doneWaitStates[k] = true
				doneWaitCount++
			}
		}

		if stop || doneWaitCount >= doneWaitSize {
			break
		}

		time.Sleep(1 * time.Millisecond)
	}

	var errors []string
	for i, e := range errs {
		errors = append(errors, fmt.Sprintf("%s: %s", i, e))
	}

	tg.task.mu.Lock()
	defer tg.task.mu.Unlock()

	tg.task.result = results
	if len(errors) > 0 {
		tg.task.err = fail.NewError(strings.Join(errors, "\n"))
	} else {
		tg.task.err = nil
	}

	if tg.task.status != ABORTED {
		tg.task.status = DONE
	}
	tg.result = results
	return results, tg.task.err
}

// TryWait ...
func (tg *taskGroup) TryWait() (bool, TaskResult, fail.Error) {
	if tg.IsNull() {
		return false, nil, fail.InvalidInstanceError()
	}

	return tg.TryWaitGroup()
}

// TryWaitGroup tries to wait on a task; if done returns the error and true, if not returns nil and false
func (tg *taskGroup) TryWaitGroup() (bool, map[string]TaskResult, fail.Error) {
	if tg.IsNull() {
		return false, nil, fail.InvalidInstanceError()
	}

	tid, err := tg.GetID()
	if err != nil {
		return false, nil, err
	}

	results := make(map[string]TaskResult)

	taskStatus, err := tg.task.GetStatus()
	if err != nil {
		return false, nil, err
	}
	if taskStatus != RUNNING {
		return false, nil, fail.NewError("cannot wait task group '%s': not running", tid)
	}

	tg.subtasksLock.SafeLock(tg.task)
	defer tg.subtasksLock.SafeUnlock(tg.task)

	for _, s := range tg.subtasks {
		ok, _, _ := s.TryWait()
		if !ok {
			return false, nil, nil
		}
	}

	result, err := tg.Wait()
	results[tid] = result
	return true, results, err
}

// WaitFor ...
func (tg *taskGroup) WaitFor(duration time.Duration) (bool, TaskResult, fail.Error) {
	if tg.IsNull() {
		return false, nil, fail.InvalidInstanceError()
	}

	return tg.WaitGroupFor(duration)
}

// WaitGroupFor waits for the task to end, for 'duration' duration
// If duration elapsed, returns (false, nil, nil)
func (tg *taskGroup) WaitGroupFor(duration time.Duration) (bool, map[string]TaskResult, fail.Error) {
	if tg.IsNull() {
		return false, nil, fail.InvalidInstanceError()
	}

	tid, err := tg.GetID()
	if err != nil {
		return false, nil, err
	}

	results := make(map[string]TaskResult)

	taskStatus, err := tg.task.GetStatus()
	if err != nil {
		return false, nil, err
	}
	if taskStatus != RUNNING {
		return false, nil, fail.InvalidRequestError("cannot wait task '%s': not running", tid)
	}

	// FIXME: go routine never ends if timeout occurs!
	c := make(chan struct{})
	go func() {
		results, err = tg.WaitGroup()
		c <- struct{}{} // done
		close(c)
	}()

	select {
	case <-time.After(duration):
		return false, nil, fail.TimeoutError(nil, duration, fmt.Sprintf("timeout waiting for task group '%s'", tid))
	case <-c:
		return true, results, err
	}
}

// Abort aborts the task execution
func (tg *taskGroup) Abort() fail.Error {
	if tg.IsNull() {
		return fail.InvalidInstanceError()
	}

	var errors []error

	// Send abort signal to subtasks
	tg.subtasksLock.SafeLock(tg.task)
	for _, st := range tg.subtasks {
		if xerr := st.Abort(); xerr != nil {
			errors = append(errors, xerr)
		}
	}
	tg.subtasksLock.SafeUnlock(tg.task)

	// Send abort signal to subtask parent task
	if xerr := tg.task.Abort(); xerr != nil {
		errors = append(errors, xerr)
	}

	if len(errors) > 0 {
		return fail.NewErrorList(errors)
	}
	return nil
}

// Aborted tells if the task group is aborted
func (tg *taskGroup) Aborted() bool {
	if tg.IsNull() || tg.task.IsNull() {
		return false
	}
	return tg.task.Aborted()
}

// New creates a subtask from current task
func (tg *taskGroup) New() (Task, fail.Error) {
	if tg.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	return newTask(context.TODO(), tg.task)
}

func (tg *taskGroup) Stats() (map[TaskStatus][]string, fail.Error) {
	if tg.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	tg.subtasksLock.SafeLock(tg.task)
	defer tg.subtasksLock.SafeUnlock(tg.task)

	status := make(map[TaskStatus][]string)
	for _, sub := range tg.subtasks {
		if tid, err := sub.GetID(); err == nil {
			st, _ := sub.GetStatus()
			if len(status[st]) == 0 {
				status[st] = []string{}
			}
			status[st] = append(status[st], tid)
		}
	}
	return status, nil
}
