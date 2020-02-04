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

	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// TaskGroupResult is a map of the TaskResult of each task
// The index is the ID of the sub-Task running the action.
type TaskGroupResult map[string]TaskResult

// TaskGroup is the task group interface
type TaskGroup interface {
	TryWaitGroup() (bool, TaskGroupResult, error)
	WaitGroup() (TaskGroupResult, error)
	WaitGroupFor(time.Duration) (bool, TaskGroupResult, error)
}

// task is a structure allowing to identify (indirectly) goroutines
type taskGroup struct {
	lock sync.Mutex
	last uint
	*task
	subtasks []Task
}

// NewTaskGroup ...
func NewTaskGroup(parentTask Task) (*taskGroup, error) {
	return newTaskGroup(nil, nil, parentTask)
}

// NewTaskGroupWithParent ...
func NewTaskGroupWithParent(parentTask Task) (*taskGroup, error) {
	return newTaskGroup(nil, nil, parentTask)
}

// NewTaskGroupWithContext ...
func NewTaskGroupWithContext(ctx context.Context, cancel context.CancelFunc) (*taskGroup, error) {
	return newTaskGroup(ctx, cancel, nil)
}

func newTaskGroup(ctx context.Context, cancel context.CancelFunc, parentTask Task) (tg *taskGroup, err error) {
	var t Task

	if parentTask != nil {
		t, err = NewTaskWithParent(parentTask)
	} else {
		if ctx != nil {
			t, err = NewTaskWithContext(ctx, cancel)
		} else {
			t, err = NewUnbreakableTask()
		}
	}
	return &taskGroup{task: t.(*task)}, err
}

// GetID returns an unique id for the task
func (tg *taskGroup) GetID() (string, error) {
	return tg.task.GetID()
}

// GetSignature builds the "signature" of the task passed as parameter,
// ie a string representation of the task ID in the format "{taskgroup <id>}".
func (tg *taskGroup) GetSignature() (string, error) {
	tid, err := tg.GetID()
	if err != nil {
		return "", err
	}

	if !Trace.Tasks {
		return "", nil
	}

	return fmt.Sprintf("{taskgroup %s}", tid), nil
}

// GetStatus returns the current task status
func (tg *taskGroup) GetStatus() (TaskStatus, error) {
	tg.task.mu.Lock()
	defer tg.task.mu.Unlock()
	return tg.task.status, nil
}

// GetContext returns the current task status
func (tg *taskGroup) GetContext() (context.Context, context.CancelFunc, error) {
	tg.task.mu.Lock()
	defer tg.task.mu.Unlock()

	return tg.task.GetContext()
}

// ForceID allows to specify task ID. The uniqueness of the ID through all the tasks
// becomes the responsibility of the developer...
func (tg *taskGroup) ForceID(id string) error {
	return tg.task.ForceID(id)
}

// Start runs in goroutine the function with parameters
// Each sub-Task created has its ID forced to TaskGroup ID + "-<index>".
func (tg *taskGroup) Start(action TaskAction, params TaskParameters) (Task, error) {
	tg.mu.Lock()
	defer tg.mu.Unlock()

	tid, err := tg.GetID()
	if err != nil {
		return nil, err
	}

	taskStatus, err := tg.task.GetStatus()
	if err != nil {
		return nil, err
	}
	if taskStatus != READY && taskStatus != RUNNING {
		return nil, scerr.InvalidRequestError(fmt.Sprintf("cannot start new task in group '%s': neither ready nor running", tid))
	}

	tg.last++
	subtask, err := NewTaskWithParent(tg.task)
	if err != nil {
		return nil, err
	}
	err = subtask.ForceID(tg.task.id + "-" + strconv.Itoa(int(tg.last)))
	if err != nil {
		return nil, err
	}
	_, err = subtask.Start(action, params)
	if err != nil {
		return nil, err
	}
	tg.subtasks = append(tg.subtasks, subtask)
	if taskStatus != RUNNING {
		tg.task.mu.Lock()
		tg.task.status = RUNNING
		tg.task.mu.Unlock()
	}
	return tg, nil
}

func (tg *taskGroup) Wait() (TaskResult, error) {
	return tg.WaitGroup()
}

// Wait waits for the task to end, and returns the error (or nil) of the execution
func (tg *taskGroup) WaitGroup() (TaskGroupResult, error) {
	tid, err := tg.GetID()
	if err != nil {
		return nil, err
	}

	errs := make(map[string]string)
	results := make(map[string]TaskResult)

	taskStatus, err := tg.task.GetStatus()
	if err != nil {
		return nil, err
	}

	if taskStatus == DONE {
		tg.task.mu.Lock()
		defer tg.task.mu.Unlock()
		results[tid] = tg.result
		return results, tg.task.err
	}
	if taskStatus == ABORTED {
		return nil, scerr.AbortedError("aborted", nil)
	}
	if taskStatus != RUNNING {
		return nil, fmt.Errorf("cannot wait task group '%s': not running", tid)
	}

	tg.mu.Lock()
	defer tg.mu.Unlock()

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
		tg.task.err = fmt.Errorf(strings.Join(errors, "\n"))
	} else {
		tg.task.err = nil
	}
	tg.task.status = DONE
	tg.result = results
	return results, tg.task.err
}

// TryWait tries to wait on a task; if done returns the error and true, if not returns nil and false
//
// satisfies interface concurrency.Task
func (tg *taskGroup) TryWait() (bool, TaskResult, error) {
	return tg.TryWaitGroup()
}

// TryWaitGroup tries to wait on a task; if done returns the error and true, if not returns nil and false
func (tg *taskGroup) TryWaitGroup() (bool, TaskGroupResult, error) {
	tid, err := tg.GetID()
	if err != nil {
		return false, nil, err
	}

	results := make(map[string]TaskResult)

	status, err := tg.task.GetStatus()
	if err != nil {
		return false, nil, err
	}
	if status != RUNNING {
		return false, nil, fmt.Errorf("cannot wait task group '%s': not running", tid)
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

// WaitFor waits for the task to end, for 'duration' duration
// If duration elapsed, returns (false, nil, nil)
// satisfies interface concurrency.Task
func (tg *taskGroup) WaitFor(duration time.Duration) (bool, TaskGroupResult, error) {
	return tg.WaitGroupFor(duration)
}

// WaitGroupFor waits for the task to end, for 'duration' duration
// If duration elapsed, returns (false, nil, nil)
func (tg *taskGroup) WaitGroupFor(duration time.Duration) (bool, TaskGroupResult, error) {
	tid, err := tg.GetID()
	if err != nil {
		return false, nil, err
	}

	status, err := tg.task.GetStatus()
	if err != nil {
		return false, nil, err
	}
	if status != RUNNING {
		return false, nil, fmt.Errorf("cannot wait task '%s': not running", tid)
	}

	results := make(map[string]TaskResult)
	c := make(chan struct{})
	go func() {
		results, err = tg.WaitGroup()
		c <- struct{}{} // done
		close(c)
	}()

	select {
	case <-time.After(duration):
		return false, nil, scerr.TimeoutError(fmt.Sprintf("timeout waiting for task group '%s'", tid), duration, nil)
	case <-c:
		return true, results, err
	}
}

// Reset resets the task for reuse
func (tg *taskGroup) Reset() error {
	tid, err := tg.GetID()
	if err != nil {
		return err
	}

	status, err := tg.task.GetStatus()
	if err != nil {
		return err
	}

	if status == RUNNING {
		return fmt.Errorf("cannot reset task group '%s': group is running", tid)
	}

	tg.task.mu.Lock()
	defer tg.task.mu.Unlock()
	tg.task.status = READY
	tg.task.err = nil
	tg.task.result = nil
	tg.subtasks = []Task{}
	return nil
}

// Abort aborts the task execution
func (tg *taskGroup) Abort() error {
	return tg.task.Abort()
}

// // New creates a subtask from current task
// func (tg *taskGroup) New() (Task, error) {
// 	return newTask(context.TODO(), tg.task)
// }

func (tg *taskGroup) Stats() map[TaskStatus][]string {
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
	return status
}

// Close cleans up tasks
func (tg *taskGroup) Close() {
	for _, t := range tg.subtasks {
		t.Close()
	}
}
