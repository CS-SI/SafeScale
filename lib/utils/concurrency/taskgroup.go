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
	TryWait() (bool, map[string]TaskResult, error)
	Wait() (map[string]TaskResult, error)
	WaitFor(time.Duration) (bool, map[string]TaskResult, error)
}

// task is a structure allowing to identify (indirectly) goroutines
type taskGroup struct {
	lock sync.Mutex
	last uint
	*task
	subtasks []Task
}

// NewTaskGroup ...
func NewTaskGroup(parentTask Task) (Task, error) {
	return newTaskGroup(context.TODO(), parentTask)
}

// NewTaskGroupWithContext ...
func NewTaskGroupWithContext(ctx context.Context) (Task, error) {
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
func (tg *taskGroup) Signature() string {
	tid, _ := tg.GetID() // FIXME Later
	if !Trace.Tasks {
		return ""
	}
	return fmt.Sprintf("{taskgroup %s}", tid)
}

// GetStatus returns the current task status
func (tg *taskGroup) GetStatus() TaskStatus {
	tg.task.lock.Lock()
	defer tg.task.lock.Unlock()
	return tg.task.status
}

// GetContext returns the current task status
func (tg *taskGroup) GetContext() context.Context {
	tg.task.lock.Lock()
	defer tg.task.lock.Unlock()
	return tg.task.GetContext()
}

// ForceID allows to specify task ID. The unicity of the ID through all the tasks
// becomes the responsability of the developer...
func (tg *taskGroup) ForceID(id string) (Task, error) {
	return tg.task.ForceID(id)
}

// Start runs in goroutine the function with parameters
// Each sub-Task created has its ID forced to TaskGroup ID + "-<index>".
func (tg *taskGroup) Start(action TaskAction, params TaskParameters) (Task, error) {
	tg.lock.Lock()
	defer tg.lock.Unlock()

	tid, _ := tg.GetID() // FIXME Later

	status := tg.task.GetStatus()
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

// Wait waits for the task to end, and returns the error (or nil) of the execution
func (tg *taskGroup) Wait() (TaskResult, error) {
	tid, _ := tg.GetID() // FIXME Later

	if tg.task.status == DONE {
		tg.task.lock.Lock()
		defer tg.task.lock.Unlock()
		return tg.result, tg.task.err
	}
	if tg.task.status != RUNNING {
		return nil, fmt.Errorf("cannot wait task group '%s': not running", tid)
	}

	errs := make(map[string]string)
	results := make(map[string]TaskResult)

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
	tg.task.err = fmt.Errorf(strings.Join(errors, "\n"))
	tg.task.status = DONE
	tg.result = results
	return results, tg.task.err
}

// TryWait tries to wait on a task; if done returns the error and true, if not returns nil and false
func (tg *taskGroup) TryWait() (bool, TaskResult, error) {
	tid, _ := tg.GetID() // FIXME Later

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
	return true, result, err
}

// WaitFor waits for the task to end, for 'duration' duration
// If duration elapsed, returns (false, nil, nil)
// By design, duration cannot be less than 1ms.
func (tg *taskGroup) WaitFor(duration time.Duration) (bool, TaskResult, error) {
	tid, _ := tg.GetID() // FIXME Later

	if tg.task.status != RUNNING {
		return false, nil, fmt.Errorf("cannot wait task '%s': not running", tid)
	}

	if duration < time.Millisecond {
		duration = time.Millisecond
	}

	for {
		select {
		case <-time.After(duration):
			return false, nil, scerr.TimeoutError(fmt.Sprintf("timeout waiting for task group '%s'", tid), duration, nil)
		default:
			ok, result, err := tg.TryWait()
			if ok {
				return ok, result, err
			}
			// Waits 1 ms between checks...
			time.Sleep(time.Millisecond)
		}
	}
}

// Reset resets the task for reuse
func (tg *taskGroup) Reset() (Task, error) {
	tid, _ := tg.GetID() // FIXME Later

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
func (tg *taskGroup) Abort() {
	tg.task.Abort()
}

// New creates a subtask from current task
func (tg *taskGroup) New() (Task, error) {
	return newTask(context.TODO(), tg.task)
}
