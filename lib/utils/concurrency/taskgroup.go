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
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// TaskGroupResult is a map of the TaskResult of each task
// The index is the ID of the sub-Task running the action.
type TaskGroupResult map[string]TaskResult

// TaskGroupGuard is the task group interface defining method to wait the taskgroup
type TaskGroupGuard interface {
	TryWaitGroup() (bool, TaskGroupResult, error)
	WaitGroup() (TaskGroupResult, error)
	WaitGroupFor(time.Duration) (bool, TaskGroupResult, error)
}

// TaskGroup is the task group interface
type TaskGroup interface {
	TaskCore
	TaskGroupGuard
}

// task is a structure allowing to identify (indirectly) goroutines
type taskGroup struct {
	lock sync.Mutex
	last uint
	*task
	result   TaskGroupResult
	subtasks []Task
}

// NewTaskGroup ...
func NewTaskGroup(parentTask Task) (TaskGroup, error) {
	return newTaskGroup(context.Background(), parentTask)
}

// NewTaskGroupWithContext ...
func NewTaskGroupWithContext(ctx context.Context) (TaskGroup, error) {
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
	tid, _ := tg.GetID() // FIXME: Later
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

	tid, _ := tg.GetID() // FIXME: Later

	taskStatus := tg.task.GetStatus()
	if taskStatus != READY && taskStatus != RUNNING {
		return nil, fail.InvalidRequestError(
			fmt.Sprintf(
				"cannot start new task in group '%s': neither ready nor running", tid,
			),
		)
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
	if taskStatus != RUNNING {
		tg.task.lock.Lock()
		tg.task.status = RUNNING
		tg.task.lock.Unlock()
	}
	return tg, nil
}

// WaitGroup waits for the task to end, and returns the error (or nil) of the execution
func (tg *taskGroup) WaitGroup() (TaskGroupResult, error) {
	tid, _ := tg.GetID() // FIXME: Later

	taskStatus := tg.task.GetStatus()
	if taskStatus == ABORTED {
		return nil, fail.AbortedError("", nil)
	}
	if taskStatus != RUNNING {
		return nil, fmt.Errorf("cannot wait task group '%s': not running", tid)
	}
	if taskStatus == DONE {
		tg.task.lock.Lock()
		defer tg.task.lock.Unlock()
		return tg.result, tg.task.err
	}

	errs := make(map[string]string)
	results := make(TaskGroupResult)

	tg.lock.Lock()
	defer tg.lock.Unlock()

	type result struct {
		tgr  TaskGroupResult
		errs map[string]string
	}

	resCh := make(chan result)

	go func() {
		ierrs := make(map[string]string)
		iresults := make(TaskGroupResult)

		for _, s := range tg.subtasks {
			sid, err := s.GetID()
			if err != nil {
				continue
			}

			result, err := s.Wait()
			if err != nil {
				ierrs[sid] = err.Error()
			}
			iresults[sid] = result
		}

		resCh <- result{
			tgr:  iresults,
			errs: ierrs,
		}

		return
	}()

	select {
	case <-tg.ctx.Done():
		taskStatus = tg.task.GetStatus()
		if taskStatus == ABORTED {
			return nil, fail.AbortedError("", nil)
		}
		if taskStatus != RUNNING {
			return nil, fmt.Errorf("cannot wait task group '%s': not running", tid)
		}
		return nil, fail.AbortedError(fmt.Sprintf("aborting with a task status of %d", taskStatus), nil)
	case res := <-resCh:
		results = res.tgr
		errs = res.errs
	}

	var errors []string
	for i, e := range errs {
		errors = append(errors, fmt.Sprintf("%s: %s", i, e))
	}

	tg.task.lock.Lock()
	defer tg.task.lock.Unlock()
	tg.task.result = results
	if len(errors) > 0 {
		tg.task.err = fmt.Errorf(strings.Join(errors, "\n"))
	}
	tg.task.status = DONE
	tg.result = results
	return results, tg.task.err
}

// TryWaitGroup tries to wait on a task; if done returns the error and true, if not returns nil and false
func (tg *taskGroup) TryWaitGroup() (bool, TaskGroupResult, error) {
	tid, _ := tg.GetID() // FIXME: Later

	if tg.task.GetStatus() != RUNNING {
		return false, nil, fmt.Errorf("cannot wait task group '%s': not running", tid)
	}
	for _, s := range tg.subtasks {
		ok, _, _ := s.TryWait()
		if !ok {
			return false, nil, nil
		}
	}
	result, err := tg.WaitGroup()
	return true, result, err
}

// WaitFor waits for the task to end, for 'duration' duration
// If duration elapsed, returns (false, nil, nil)
// By design, duration cannot be less than 1ms.
func (tg *taskGroup) WaitGroupFor(duration time.Duration) (bool, TaskGroupResult, error) {
	tid, _ := tg.GetID() // FIXME: Later

	if tg.task.GetStatus() != RUNNING {
		return false, nil, fmt.Errorf("cannot wait task '%s': not running", tid)
	}

	if duration < time.Millisecond {
		duration = time.Millisecond
	}

	type result struct {
		tr  TaskGroupResult
		err error
	}

	chRes := make(chan result)

	go func() {
		wgR, err := tg.WaitGroup()
		chRes <- result{
			tr:  wgR,
			err: err,
		}
		return
	}()

	select {
	case <-time.After(duration):
		return false, nil, fail.TimeoutError(
			fmt.Sprintf("timeout waiting for task group '%s'", tid), duration, nil,
		)
	case res := <-chRes:
		return true, res.tr, res.err
	}
}

// Abort aborts the task execution
func (tg *taskGroup) Abort() error {
	return tg.task.Abort()
}

func (tg *taskGroup) Aborted() bool {
	return tg.task.Aborted()
}

func (tg *taskGroup) Finished() bool {
	return tg.task.Finished()
}

// New creates a subtask from current task
func (tg *taskGroup) New() (Task, error) {
	return newTask(context.Background(), tg.task)
}

func (tg *taskGroup) NewWithContext(ctx context.Context) (Task, error) {
	return newTask(ctx, tg.task)
}
