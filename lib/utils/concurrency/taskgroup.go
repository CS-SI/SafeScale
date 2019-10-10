/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	TryWaitGroup() (bool, map[string]TaskResult, error)
	WaitGroup() (map[string]TaskResult, error)
	WaitForGroup(time.Duration) (bool, map[string]TaskResult, error)
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
	return newTaskGroup(context.TODO(), parentTask)
}

// NewTaskGroupWithContext ...
func NewTaskGroupWithContext(ctx context.Context) (*taskGroup, error) {
	return newTaskGroup(ctx, nil)
}

func newTaskGroup(ctx context.Context, parentTask Task) (tg *taskGroup, err error) {
	var t Task

	if parentTask == nil {
		if ctx == nil {
			t, err = NewTask(nil)
		} else {
			t, err = NewTaskWithContext(ctx)
		}
	} else {
		switch parentTask := parentTask.(type) {
		case *task:
			p := parentTask
			t, err = NewTask(p)
		case *taskGroup:
			p := parentTask
			t, err = NewTask(p.task)
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
	tg.task.lock.Lock()
	defer tg.task.lock.Unlock()
	return tg.task.status, nil
}

// GetContext returns the current task status
func (tg *taskGroup) GetContext() (context.Context, error) {
	tg.task.lock.Lock()
	defer tg.task.lock.Unlock()

	return tg.task.GetContext()
}

// ForceID allows to specify task ID. The uniqueness of the ID through all the tasks
// becomes the responsibility of the developer...
func (tg *taskGroup) ForceID(id string) (Task, error) {
	return tg.task.ForceID(id)
}

// Start runs in goroutine the function with parameters
// Each sub-Task created has its ID forced to TaskGroup ID + "-<index>".
func (tg *taskGroup) Start(action TaskAction, params TaskParameters) (Task, error) {
	tg.lock.Lock()
	defer tg.lock.Unlock()

	tid, err := tg.GetID()
	if err != nil {
		return nil, err
	}

	status, _ := tg.task.GetStatus()
	if status != READY && status != RUNNING {
		panic(fmt.Sprintf("Can't start new task in group '%s': neither ready nor running!", tid))
	}

	tg.last++
	subtask, err := tg.task.New()
	if err != nil {
		return nil, err
	}
	subtask, err = subtask.ForceID(tg.task.id + "-" + strconv.Itoa(int(tg.last)))
	if err != nil {
		return nil, err
	}
	subtask, err = subtask.Start(action, params)
	if err != nil {
		return nil, err
	}
	tg.subtasks = append(tg.subtasks, subtask)
	if status != RUNNING {
		tg.task.lock.Lock()
		tg.task.status = RUNNING
		tg.task.lock.Unlock()
	}
	return tg, nil
}

func (tg *taskGroup) Wait() (TaskResult, error) {
	return tg.WaitGroup()
}

// Wait waits for the task to end, and returns the error (or nil) of the execution
func (tg *taskGroup) WaitGroup() (map[string]TaskResult, error) {
	tid, err := tg.GetID()
	if err != nil {
		return nil, err
	}

	errs := make(map[string]string)
	results := make(map[string]TaskResult)

	if tg.task.status == DONE {
		tg.task.lock.Lock()
		defer tg.task.lock.Unlock()
		results[tid] = tg.result
		return results, tg.task.err
	}
	if tg.task.status != RUNNING {
		return nil, fmt.Errorf("cannot wait task group '%s': not running", tid)
	}

	tg.lock.Lock()
	defer tg.lock.Unlock()

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
	errors := []string{}
	for i, e := range errs {
		errors = append(errors, fmt.Sprintf("%s: %s", i, e))
	}
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

func (tg *taskGroup) TryWait() (bool, TaskResult, error) {
	return tg.TryWaitGroup()
}

// TryWait tries to wait on a task; if done returns the error and true, if not returns nil and false
func (tg *taskGroup) TryWaitGroup() (bool, map[string]TaskResult, error) {
	tid, err := tg.GetID()
	if err != nil {
		return false, nil, err
	}

	results := make(map[string]TaskResult)

	if tg.task.status != RUNNING {
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

func (tg *taskGroup) WaitFor(duration time.Duration) (bool, TaskResult, error) {
	return tg.WaitForGroup(duration)
}

// WaitFor waits for the task to end, for 'duration' duration
// If duration elapsed, returns (false, nil, nil)
// By design, duration cannot be less than 1ms.
// BROKEN, Do not use
func (tg *taskGroup) WaitForGroup(duration time.Duration) (bool, map[string]TaskResult, error) {
	tid, err := tg.GetID()
	if err != nil {
		return false, nil, err
	}

	results := make(map[string]TaskResult)

	if tg.task.status != RUNNING {
		return false, nil, fmt.Errorf("cannot wait task '%s': not running", tid)
	}

	if duration < time.Millisecond {
		duration = time.Millisecond
	}

	// FIXME Broken do not use

	for {
		select {
		case <-time.After(duration):
			return false, nil, scerr.TimeoutError(fmt.Sprintf("timeout waiting for task group '%s'", tid), duration, nil)
		default:
			ok, result, err := tg.TryWait()
			if ok {
				results[tid] = result
				return ok, results, err
			}
			// Waits 1 ms between checks...
			time.Sleep(time.Millisecond)
		}
	}
}

// Reset resets the task for reuse
func (tg *taskGroup) Reset() (Task, error) {
	tid, err := tg.GetID()
	if err != nil {
		return nil, err
	}

	if tg.task.status == RUNNING {
		return nil, fmt.Errorf("can't reset task group '%s': group running", tid)
	}

	tg.task.lock.Lock()
	defer tg.task.lock.Unlock()

	tg.task.status = READY
	tg.task.err = nil
	tg.task.result = nil
	tg.subtasks = []Task{}
	return tg, nil
}

// // Result returns the result of the task action
// func (tg *taskGroup) Result() TaskResult {
// 	status := tg.GetStatus()
// 	if status == READY {
// 		panic("Can't get result of task group '%s': no task started!")
// 	}
// 	if status != DONE {
// 		panic("Can't get result of task group '%s': group not done!")
// 	}
// 	return tg.task.Result()
// }

// Abort aborts the task execution
func (tg *taskGroup) Abort() error {
	return tg.task.Abort()
}

// New creates a subtask from current task
func (tg *taskGroup) New() (Task, error) {
	return newTask(context.TODO(), tg.task)
}

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
