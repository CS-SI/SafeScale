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
	"strings"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils"
)

// TaskGroup is the task group interface
type TaskGroup interface {
	ForceID(string) Task
	GetID() string
	GetSignature() string
	GetStatus() TaskStatus
	GetContext() context.Context
	Reset() Task
	Submit(TaskAction, TaskParameters)
	Start()
	TryWait() (bool, error)
	Wait() error
	WaitFor() (bool, error)
}

// task is a structure allowing to identify (indirectly) goroutines
type taskGroup struct {
	lock sync.Mutex
	*task
	subtasks []Task
}

// NewTaskGroup ...
func NewTaskGroup(parentTask Task) Task {
	return newTaskGroup(nil, parentTask)
}

// NewTaskGroupWithContext ...
func NewTaskGroupWithContext(ctx context.Context) Task {
	return newTaskGroup(ctx, nil)
}
func newTaskGroup(ctx context.Context, parentTask Task) *taskGroup {
	var t Task

	if parentTask == nil {
		if ctx == nil {
			t = NewTask(nil)
		} else {
			t = NewTaskWithContext(ctx)
		}
	} else {
		switch parentTask.(type) {
		case *task:
			p := parentTask.(*task)
			t = NewTask(p)
		case *taskGroup:
			p := parentTask.(*taskGroup)
			t = NewTask(p.task)
		}
	}
	return &taskGroup{task: t.(*task)}
}

// GetID returns an unique id for the task
func (tg *taskGroup) GetID() string {
	return tg.task.GetID()
}

// GetSignature builds the "signature" of the task passed as parameter,
// ie a string representation of the task ID in the format "{task <id>}".
func (tg *taskGroup) Signature() string {
	if !Trace.Tasks {
		return ""
	}
	return fmt.Sprintf("{taskgroup %s}", tg.GetID())
}

// GetStatus returns the current task status
func (tg *taskGroup) GetStatus() TaskStatus {
	return tg.task.GetStatus()
}

// GetContext returns the current task status
func (tg *taskGroup) GetContext() context.Context {
	return tg.task.GetContext()
}

// ForceID allows to specify task ID. The unicity of the ID through all the tasks
// becomes the responsability of the developer...
func (tg *taskGroup) ForceID(id string) Task {
	return tg.task.ForceID(id)
}

// Start runs in goroutine the function with parameters
func (tg *taskGroup) Start(action TaskAction, params TaskParameters) Task {
	tg.lock.Lock()
	defer tg.lock.Unlock()

	status := tg.task.GetStatus()
	if status != READY && status != RUNNING {
		panic(fmt.Sprintf("Can't start new task in group '%s': neither ready nor running!", tg.GetID()))
	}

	subtask := tg.task.New().Start(action, params)
	tg.subtasks = append(tg.subtasks, subtask)
	if status != RUNNING {
		tg.task.lock.Lock()
		tg.task.status = RUNNING
		tg.task.lock.Unlock()
	}
	return tg
}

// Wait waits for the task to end, and returns the error (or nil) of the execution
func (tg *taskGroup) Wait() (TaskResult, error) {
	status := tg.task.GetStatus()
	if status == DONE {
		tg.task.lock.Lock()
		defer tg.task.lock.Unlock()
		return tg.result, tg.task.err
	}
	if status != RUNNING {
		return nil, fmt.Errorf("can't wait task group '%s': not running", tg.GetID())
	}

	errs := make(map[string]string)
	results := make(map[string]TaskResult)

	tg.lock.Lock()
	defer tg.lock.Unlock()

	for _, s := range tg.subtasks {
		result, err := s.Wait()
		if err != nil {
			errs[s.GetID()] = err.Error()
		}
		results[s.GetID()] = result
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
	status := tg.GetStatus()
	if status != RUNNING {
		return false, nil, fmt.Errorf("can't wait task group '%s': not running", tg.GetID())
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
// If duration elapsed, returns (false, nil)
func (tg *taskGroup) WaitFor(duration time.Duration) (bool, TaskResult, error) {
	status := tg.GetStatus()
	if status != RUNNING {
		return false, nil, fmt.Errorf("can't wait task '%s': not running", tg.GetID())
	}

	for {
		select {
		case <-time.After(duration):
			return false, nil, utils.TimeoutError(fmt.Sprintf("timeout waiting for task group '%s'", tg.GetID()))
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
func (tg *taskGroup) Reset() Task {
	status := tg.GetStatus()
	if status == RUNNING {
		panic(fmt.Sprintf("Can't reset task group '%s': group running!", tg.GetID()))
	}

	tg.task.lock.Lock()
	defer tg.task.lock.Unlock()

	tg.task.status = READY
	tg.task.err = nil
	tg.task.result = nil
	tg.subtasks = []Task{}
	return tg
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
func (tg *taskGroup) New() Task {
	return newTask(nil, tg.task)
}
