/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// TaskGroupResult is a map of the TaskResult of each task
// The index is the ID of the sub-Task running the action.
type TaskGroupResult map[string]TaskResult

// TaskGroupGuard is the task group interface defining method to wait the taskgroup
type TaskGroupGuard interface {
	TryWaitGroup() (bool, map[string]TaskResult, error)
	WaitGroup() (map[string]TaskResult, error)
	WaitGroupFor(time.Duration) (bool, map[string]TaskResult, error)
}

//go:generate moq -out taskgroup_moq_test.go . TaskGroup

// TaskGroup is the task group interface
type TaskGroup interface {
	TaskCore
	TaskGroupGuard

	Stats() (map[TaskStatus][]string, error)
}

// task is a structure allowing to identify (indirectly) goroutines
type taskGroup struct {
	groupLock sync.Mutex // FIXME This breaks the world
	last      uint
	*task
	result TaskGroupResult

	subtasksLock sync.RWMutex
	subtasks     []Task
}

// NewTaskGroup ...
func NewTaskGroup(parentTask Task) (*taskGroup, error) { // nolint
	return newTaskGroup(context.TODO(), parentTask)
}

// NewTaskGroup ...
func NewTaskGroupWithParent(parentTask Task) (*taskGroup, error) { // nolint
	return newTaskGroup(context.TODO(), parentTask)
}

// NewTaskGroupWithContext ...
func NewTaskGroupWithContext(ctx context.Context, parentTask Task) (*taskGroup, error) { // nolint
	return newTaskGroup(ctx, parentTask)
}

func newTaskGroup(ctx context.Context, parentTask Task) (tg *taskGroup, err error) {
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
	return &taskGroup{task: t.(*task)}, err
}

// GetID returns an unique id for the task
func (tg *taskGroup) GetID() (string, error) {
	if tg == nil {
		return "", scerr.InvalidInstanceError()
	}

	return tg.task.GetID()
}

// GetSignature builds the "signature" of the task passed as parameter,
// ie a string representation of the task ID in the format "{taskgroup <id>}".
func (tg *taskGroup) GetSignature() (string, error) {
	if tg == nil {
		return "", scerr.InvalidInstanceError()
	}
	tid, err := tg.GetID()
	if err != nil {
		return "", err
	}

	if !debug.ShouldTrace("concurrency.task") {
		return "", nil
	}

	return fmt.Sprintf("{taskgroup %s}", tid), nil
}

// GetStatus returns the current task status
func (tg *taskGroup) GetStatus() (TaskStatus, error) {
	if tg == nil {
		return TaskStatus(0), scerr.InvalidInstanceError()
	}

	return tg.task.GetStatus()
}

// GetContext returns the current task status
func (tg *taskGroup) GetContext() (context.Context, error) {
	if tg == nil {
		return nil, scerr.InvalidInstanceError()
	}

	return tg.task.GetContext()
}

// SetID allows to specify task ID. The uniqueness of the ID through all the tasks
// becomes the responsibility of the developer...
func (tg *taskGroup) SetID(id string) error {
	if tg == nil {
		return scerr.InvalidInstanceError()
	}

	tg.groupLock.Lock()
	defer tg.groupLock.Unlock()

	return tg.task.SetID(id)
}

func (tg *taskGroup) StartInSubtask(action TaskAction, params TaskParameters) (Task, error) {
	if tg == nil {
		return nil, scerr.InvalidInstanceError()
	}

	return tg.Start(action, params)
}

// Start runs in goroutine the function with parameters
// Each sub-Task created has its ID forced to TaskGroup ID + "-<index>".
func (tg *taskGroup) Start(action TaskAction, params TaskParameters) (Task, error) {
	if tg == nil {
		return nil, scerr.InvalidInstanceError()
	}

	tg.groupLock.Lock()
	defer tg.groupLock.Unlock()

	status, err := tg.task.GetStatus()
	if err != nil {
		return nil, err
	}

	tg.last++
	subtask, err := NewTaskWithParent(tg.task)
	if err != nil {
		return nil, err
	}
	err = subtask.SetID(tg.task.id + "-" + strconv.Itoa(int(tg.last)))
	if err != nil {
		return nil, err
	}
	subtask, err = subtask.Start(action, params)
	if err != nil {
		return nil, err
	}

	tg.subtasksLock.Lock()
	defer tg.subtasksLock.Unlock()

	tg.subtasks = append(tg.subtasks, subtask)
	if status != RUNNING {
		tg.task.mu.Lock()
		tg.task.status = RUNNING
		tg.task.mu.Unlock()
	}
	return tg, nil
}

func (tg *taskGroup) Wait() (TaskResult, error) {
	if tg == nil {
		return nil, scerr.InvalidInstanceError()
	}
	return tg.WaitGroup()
}

// Wait waits for the task to end, and returns the error (or nil) of the execution
func (tg *taskGroup) WaitGroup() (map[string]TaskResult, error) {
	if tg == nil {
		return nil, scerr.InvalidInstanceError()
	}

	tg.groupLock.Lock()
	defer tg.groupLock.Unlock()

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
		if tg.task.err != nil {
			errors = append(errors, tg.task.err)
		}

		for _, s := range tg.subtasks {
			lerr, _ := s.GetLastError()
			if lerr != nil {
				errors = append(errors, lerr)
			}
		}
		return nil, scerr.AbortedError(scerr.ErrListError(errors), "taskgroup was already aborted")
	}
	if taskStatus != RUNNING && taskStatus != READY {
		return nil, scerr.ForbiddenError("cannot wait task group '%s': not running", tid)
	}

	for _, s := range tg.subtasks {
		sid, err := s.GetID()
		if err != nil {
			continue
		}

		result, err := s.Wait()
		if err != nil {
			errs[sid] = err.Error()
		}

		results[sid] = result
	}

	var errors []string
	for i, e := range errs {
		errors = append(errors, fmt.Sprintf("%s: %s", i, e))
	}

	tg.task.mu.Lock()
	defer tg.task.mu.Unlock()

	tg.task.result = results
	if len(errors) > 0 {
		tg.task.err = scerr.NewError(strings.Join(errors, "\n"))
	} else {
		tg.task.err = nil
	}

	tg.task.status = DONE
	tg.result = results
	return results, tg.task.err
}

func (tg *taskGroup) TryWait() (bool, TaskResult, error) {
	if tg == nil {
		return false, nil, scerr.InvalidInstanceError()
	}

	return tg.TryWaitGroup()
}

// TryWait tries to wait on a task; if done returns the error and true, if not returns nil and false
func (tg *taskGroup) TryWaitGroup() (bool, map[string]TaskResult, error) {
	if tg == nil {
		return false, nil, scerr.InvalidInstanceError()
	}

	tg.groupLock.Lock()
	defer tg.groupLock.Unlock()

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
		return false, nil, scerr.NewError("cannot wait task group '%s': not running", tid)
	}
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

func (tg *taskGroup) WaitFor(duration time.Duration) (bool, TaskResult, error) {
	if tg == nil {
		return false, nil, scerr.InvalidInstanceError()
	}

	return tg.WaitGroupFor(duration)
}

// WaitFor waits for the task to end, for 'duration' duration
// If duration elapsed, returns (false, nil, nil)
func (tg *taskGroup) WaitGroupFor(duration time.Duration) (bool, map[string]TaskResult, error) {
	if tg == nil {
		return false, nil, scerr.InvalidInstanceError()
	}

	tg.groupLock.Lock()
	defer tg.groupLock.Unlock()

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
		return false, nil, scerr.InvalidRequestError("cannot wait task '%s': not running", tid)
	}

	c := make(chan struct{})
	go func() {
		results, err = tg.WaitGroup()
		c <- struct{}{} // done
		close(c)
	}()

	select {
	case <-time.After(duration):
		return false, nil, scerr.TimeoutError(nil, duration, fmt.Sprintf("timeout waiting for task group '%s'", tid))
	case <-c:
		return true, results, err
	}
}

// Abort aborts the task execution
func (tg *taskGroup) Abort() error {
	if tg == nil {
		return scerr.InvalidInstanceError()
	}

	tg.groupLock.Lock()
	defer tg.groupLock.Unlock()

	var errors []error

	for _, st := range tg.subtasks {
		subErr := st.Abort()
		if subErr != nil {
			errors = append(errors, subErr)
		}
	}

	err := tg.task.Abort()
	if err != nil {
		errors = append(errors, err)
	}

	return scerr.ErrListError(errors)
}

// New creates a subtask from current task
func (tg *taskGroup) New() (Task, error) {
	if tg == nil {
		return nil, scerr.InvalidInstanceError()
	}

	tg.groupLock.Lock()
	defer tg.groupLock.Unlock()

	return newTask(context.TODO(), tg.task)
}

func (tg *taskGroup) Stats() (map[TaskStatus][]string, error) {
	if tg == nil {
		return nil, scerr.InvalidInstanceError()
	}

	tg.subtasksLock.RLock()
	defer tg.subtasksLock.RUnlock()

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
