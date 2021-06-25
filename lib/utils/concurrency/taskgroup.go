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
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/sirupsen/logrus"
)

// TaskGroupResult is a map of the TaskResult of each task
// The index is the ID of the sub-Task running the action.
type TaskGroupResult map[string]TaskResult

// TaskGroupGuard is the task group interface defining method to wait the taskgroup
type TaskGroupGuard interface {
	GetStarted() (uint, fail.Error)
	TryWaitGroup() (bool, map[string]TaskResult, fail.Error)
	WaitGroup() (map[string]TaskResult, fail.Error)
	WaitGroupFor(time.Duration) (bool, map[string]TaskResult, fail.Error)
}

//go:generate minimock -o ../mocks/mock_taskgroup.go -i github.com/CS-SI/SafeScale/lib/utils/concurrency.TaskGroup

// TaskGroup is the task group interface
type TaskGroup interface {
	TaskCore
	TaskGroupGuard

	GetGroupStatus() (map[TaskStatus][]string, fail.Error)
}

type subTask struct {
	task           Task
	normalizeError func(error) error
}

type subTasks struct {
	lock  sync.RWMutex
	tasks []subTask
}

// task is a structure allowing to identify (indirectly) goroutines
type taskGroup struct {
	last uint
	*task
	result TaskGroupResult

	children subTasks

	options []data.ImmutableKeyValue
}

// FUTURE: next version of TaskGroup will allow using options

var (
	// FailEarly tells the TaskGroup to fail as soon as a child fails
	FailEarly = data.NewImmutableKeyValue("fail", "early")
	// FailLately tells the TaskGroup to end all children before determine if TaskGroup has failed
	FailLately = data.NewImmutableKeyValue("fail", "lately")
)

// NewTaskGroup ...
func NewTaskGroup(options ...data.ImmutableKeyValue) (*taskGroup, fail.Error) { // nolint
	return newTaskGroup(context.TODO(), nil, options...)
}

// NewTaskGroupWithParent ...
func NewTaskGroupWithParent(parentTask Task, options ...data.ImmutableKeyValue) (*taskGroup, fail.Error) { // nolint
	return newTaskGroup(context.TODO(), parentTask, options...)
}

// NewTaskGroupWithContext ...
func NewTaskGroupWithContext(ctx context.Context, options ...data.ImmutableKeyValue) (*taskGroup, fail.Error) { // nolint
	return newTaskGroup(ctx, nil, options...)
}

func newTaskGroup(ctx context.Context, parentTask Task, options ...data.ImmutableKeyValue) (tg *taskGroup, err fail.Error) {
	defer fail.OnPanic(&err)
	var t Task

	if parentTask == nil {
		if ctx == nil {
			t, err = NewTask()
		} else {
			t, err = NewTaskWithContext(ctx)
		}
	} else {
		if parentTask.Aborted() {
			return nil, fail.AbortedError(nil, "aborted")
		}

		switch parentTask := parentTask.(type) {
		case *task:
			p := parentTask
			t, err = NewTaskWithParent(p)
		case *taskGroup:
			p := parentTask
			t, err = NewTaskWithParent(p.task)
		}
	}

	if len(options) > 0 {
		for _, v := range options {
			switch v.Key() {
			case keywordInheritParentIDOption:
				// this option orders to copy ParentTask.ID to children; the latter are responsible to update their own ID
				value, ok := v.Value().(bool)
				if ok && value && parentTask != nil {
					id, xerr := parentTask.GetID()
					if xerr != nil {
						return nil, xerr
					}

					xerr = t.SetID(id)
					if xerr != nil {
						return nil, xerr
					}
				}
			}
		}
	}

	tg = &taskGroup{
		task:     t.(*task),
		children: subTasks{},
		options:  options,
	}

	if len(options) > 0 {
		for _, v := range options {
			switch v.Key() {
			case keywordAmendID:
				value, ok := v.Value().(string)
				if ok {
					tg.task.id += "+" + value
				}
			}
		}
	}

	return tg, err
}

// isNull ...
func (instance *taskGroup) isNull() bool {
	return instance == nil || instance.task == nil || instance.task.IsNull()
}

// GetID returns an unique id for the task
func (instance *taskGroup) GetID() (string, fail.Error) {
	if instance.isNull() {
		return "", fail.InvalidInstanceError()
	}

	return instance.task.GetID()
}

// GetSignature builds the "signature" of the task group, ie a string representation of the task ID in the format "{taskgroup <id>}".
func (instance *taskGroup) GetSignature() string {
	if instance.isNull() {
		return ""
	}

	tid, err := instance.GetID()
	if err != nil {
		return ""
	}

	return `{taskGroup ` + tid + `}`
}

// GetStatus returns the current task status
func (instance *taskGroup) GetStatus() (TaskStatus, fail.Error) {
	if instance.isNull() {
		return TaskStatus(0), fail.InvalidInstanceError()
	}

	return instance.task.GetStatus()
}

// GetContext returns the current task status
func (instance *taskGroup) GetContext() context.Context {
	if instance.isNull() {
		return context.TODO()
	}

	return instance.task.GetContext()
}

// SetID allows to specify task ID. The uniqueness of the ID through all the tasks
// becomes the responsibility of the developer...
func (instance *taskGroup) SetID(id string) fail.Error {
	if instance.isNull() {
		return fail.InvalidInstanceError()
	}

	return instance.task.SetID(id)
}

// StartInSubtask starts an action in a subtask
func (instance *taskGroup) StartInSubtask(action TaskAction, params TaskParameters, options ...data.ImmutableKeyValue) (Task, fail.Error) {
	if instance.isNull() {
		return instance, fail.InvalidInstanceError()
	}
	return instance.Start(action, params, options...)
}

// Start runs in goroutine the function with parameters
// Returns the subtask created to run the action (should be ignored in most cases)
func (instance *taskGroup) Start(action TaskAction, params TaskParameters, options ...data.ImmutableKeyValue) (tg Task, xerr fail.Error) {
	defer fail.OnPanic(&xerr)
	if instance.isNull() {
		return instance, fail.InvalidInstanceError()
	}

	status, err := instance.task.GetStatus()
	if err != nil {
		return instance, err
	}

	instance.last++
	subtask, err := NewTaskWithParent(instance.task, options...)
	if err != nil {
		return nil, err
	}

	newChild := subTask{
		task: subtask,
	}

	if len(options) > 0 {
		for _, v := range options {
			switch v.Key() {
			// case keywordInheritParentIDOption:
			// 	value, ok := v.Value().(bool)
			// 	if ok && value {
			// 		id, xerr := instance.task.GetID()
			// 		if xerr != nil {
			// 			return nil, xerr
			// 		}
			//
			// 		xerr = subtask.SetID(id)
			// 		if xerr != nil {
			// 			return nil, xerr
			// 		}
			// 	}
			case "normalize_error":
				newChild.normalizeError = v.Value().(func(error) error)
			default:
			}
		}
	}

	_, xerr = subtask.Start(action, params)
	if xerr != nil {
		return nil, err
	}

	instance.children.lock.Lock()
	instance.children.tasks = append(instance.children.tasks, newChild)
	instance.children.lock.Unlock()

	if status != RUNNING {
		fnNOP := func(t Task, _ TaskParameters) (TaskResult, fail.Error) {
			for !t.Aborted() {
				time.Sleep(50 * time.Millisecond)
			}
			return nil, nil
		}

		_, stErr := instance.task.Start(fnNOP, nil)
		if stErr != nil {
			logrus.Tracef("ignored task start error: %v", stErr)
		}

	}

	return subtask, nil
}

// Wait is a synonym to WaitGroup (exists to satisfy interface Task)
func (instance *taskGroup) Wait() (TaskResult, fail.Error) {
	if instance.isNull() {
		return instance, fail.InvalidInstanceError()
	}

	return instance.WaitGroup()
}

// WaitGroup waits for the task to end, and returns the error (or nil) of the execution
// Note: this function may lead to go routine leaks, because we do not want a taskgroup to be locked because of
//       a subtask not responding; if a subtask is designed to run forever, it will never end.
//       It's highly recommended to use task.Aborted() in the body of a task to check
//       for abortion signal and quit the go routine accordingly to reduce the risk (a taskgroup remains abortable with
//       this recommendation).
func (instance *taskGroup) WaitGroup() (map[string]TaskResult, fail.Error) {
	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}

	tid, err := instance.GetID()
	if err != nil {
		return nil, err
	}

	taskStatus, err := instance.task.GetStatus()
	if err != nil {
		return nil, err
	}

	errs := make(map[string]error)
	results := make(TaskGroupResult, len(instance.children.tasks))

	switch taskStatus {
	case DONE:
		instance.task.mu.Lock()
		defer instance.task.mu.Unlock()

		results = instance.result
		return results, instance.task.err

	case READY:
		return nil, fail.InconsistentError("cannot wait a TaskGroup that has not been started")

	case ABORTED:
		fallthrough
	case RUNNING:
		doneWaitSize := len(instance.children.tasks)
		doneWaitStates := make(map[int]bool, doneWaitSize)
		for k := range instance.children.tasks {
			doneWaitStates[k] = false
		}
		doneWaitCount := 0

		instance.children.lock.RLock()
		defer instance.children.lock.RUnlock()

		for {
			for k, s := range instance.children.tasks {
				if doneWaitStates[k] {
					continue
				}

				sid, err := s.task.GetID()
				if err != nil {
					continue
				}

				done, result, err := s.task.TryWait()
				if done {
					if err != nil {
						if s.normalizeError != nil {
							if normalizedError := s.normalizeError(err); normalizedError != nil {
								errs[sid] = normalizedError
							}
						} else {
							errs[sid] = err
						}
					}

					results[sid] = result
					doneWaitStates[k] = true
					doneWaitCount++
					break
				}

				time.Sleep(1 * time.Millisecond)
			}

			if doneWaitCount >= doneWaitSize {
				break
			}
		}

		var errors []error
		instance.task.mu.Lock()
		if instance.task.err != nil {
			errors = append(errors, instance.task.err)
		}
		instance.task.result = results
		instance.task.mu.Unlock()
		for i, e := range errs {
			switch cerr := e.(type) {
			case *fail.ErrAborted:
				cause := fail.ConvertError(cerr.Cause())
				if cause != nil {
					errors = append(errors, fail.Wrap(cause, "%s", i))
				} else {
					errors = append(errors, fail.Wrap(e, "%s", i))
				}
			default:
				errors = append(errors, fail.Wrap(e, "%s", i))
			}
		}

		taskStatus, err := instance.task.GetStatus()
		if err != nil {
			return nil, err
		}
		switch taskStatus {
		case ABORTED:
			if len(errors) > 0 {
				instance.task.mu.Lock()
				instance.task.err = fail.AbortedError(fail.NewErrorList(errors), "taskgroup ended with failures")
				instance.task.mu.Unlock()
			}

		case TIMEOUT:
			fallthrough
		case READY:
			fallthrough
		case RUNNING:
			// parent task is running, we need to abort it, even if abort was disable, now that all the children have terminated
			instance.task.mu.Lock()
			previousErr := instance.task.err
			abortSaved := instance.task.abortDisengaged
			instance.task.abortDisengaged = false
			instance.task.mu.Unlock()

			taErr := instance.task.Abort()
			if taErr != nil {
				logrus.Tracef("ignored error aborting task: %v", taErr)
			}
			_, tawErr := instance.task.Wait()
			if tawErr != nil {
				logrus.Tracef("ignored error waiting for task: %v", tawErr)
			}

			instance.task.mu.Lock()
			instance.task.abortDisengaged = abortSaved
			if len(errors) > 0 {
				instance.task.err = fail.AbortedError(fail.NewErrorList(errors), "TaskGroup ended with failures")
			} else {
				instance.task.err = previousErr
			}
			instance.task.mu.Unlock()

		case UNKNOWN:
			return nil, fail.InconsistentError("cannot wait on TaskGroup in 'UNKNOWN' state")

		case DONE:
			// task done, WaitGroup successful
			instance.task.mu.Lock()
			defer instance.task.mu.Unlock()
			return instance.result, instance.task.err
		}

		instance.task.mu.Lock()
		defer instance.task.mu.Unlock()

		instance.task.status = DONE

		instance.result = results
		return results, instance.task.err

	default:
		return nil, fail.ForbiddenError("cannot wait task group '%s': not running (%d)", tid, taskStatus)
	}
}

// TryWait executes TryWaitGroup
func (instance *taskGroup) TryWait() (bool, TaskResult, fail.Error) {
	if instance.isNull() {
		return false, nil, fail.InvalidInstanceError()
	}

	return instance.TryWaitGroup()
}

// TryWaitGroup tries to wait on a TaskGroup
// If TaskGroup done, returns (true, TaskResult, <error from the task>)
// If TaskGroup aborted, returns (false, nil, *fail.ErrAborted) (subsequent calls of TryWaitGroup may be necessary)
// If TaskGroup still running, returns (false, nil, nil)
// if TaskGroup is not started, returns (false, nil, *fail.ErrInconsistent)
func (instance *taskGroup) TryWaitGroup() (bool, map[string]TaskResult, fail.Error) {
	if instance.isNull() {
		return false, nil, fail.InvalidInstanceError()
	}

	tid, xerr := instance.GetID()
	if xerr != nil {
		return false, nil, xerr
	}

	results := make(map[string]TaskResult)

	taskStatus, xerr := instance.task.GetStatus()
	if xerr != nil {
		return false, nil, xerr
	}
	if taskStatus != RUNNING && taskStatus != ABORTED {
		return false, nil, fail.NewError("cannot wait task group '%s': not running (%d)", tid, taskStatus)
	}

	{
		instance.children.lock.RLock()
		defer instance.children.lock.RUnlock()

		for _, s := range instance.children.tasks {
			if ok, _, twErr := s.task.TryWait(); !ok {
				if twErr != nil {
					logrus.Tracef("ignored trywait error: %v", twErr)
				}
				return false, nil, nil
			}
		}
	}

	result, xerr := instance.Wait()
	results[tid] = result
	return true, results, xerr
}

// WaitFor ...
func (instance *taskGroup) WaitFor(duration time.Duration) (bool, TaskResult, fail.Error) {
	if instance.isNull() {
		return false, nil, fail.InvalidInstanceError()
	}

	return instance.WaitGroupFor(duration)
}

// WaitGroupFor waits for the task to end, for 'duration' duration
// If duration elapsed, returns (false, nil, nil)
func (instance *taskGroup) WaitGroupFor(duration time.Duration) (bool, map[string]TaskResult, fail.Error) {
	if instance.isNull() {
		return false, nil, fail.InvalidInstanceError()
	}

	tid, err := instance.GetID()
	if err != nil {
		return false, nil, err
	}

	results := make(map[string]TaskResult)

	taskStatus, err := instance.task.GetStatus()
	if err != nil {
		return false, nil, err
	}

	switch taskStatus {
	case READY:
		return false, nil, fail.InconsistentError("cannot wait TaskGroup '%s': not started", tid)

	case TIMEOUT:
		fallthrough
	case DONE:
		return true, instance.result, nil

	case ABORTED:
		fallthrough
	case RUNNING:
		c := make(chan struct{})
		go func() {
			results, err = instance.WaitGroup()
			c <- struct{}{} // done
			close(c)
		}()

		if duration > 0 {
			select {
			case <-time.After(duration):
				tout := fail.TimeoutError(nil, duration, fmt.Sprintf("timeout of %s waiting for task group '%s'", duration, tid))
				abErr := instance.Abort()
				if abErr != nil {
					_ = tout.AddConsequence(abErr)
				}
				return false, nil, tout
			case <-c:
				return true, results, err
			}
		}

		select { // nolint
		case <-c:
			return true, results, err
		}

	case UNKNOWN:
		fallthrough
	default:
		return false, nil, fail.InvalidRequestError("cannot wait task group '%s': not running (%d)", tid, taskStatus)
	}
}

// Abort aborts the task execution
func (instance *taskGroup) Abort() fail.Error {
	if instance.isNull() {
		return fail.InvalidInstanceError()
	}

	var errors []error
	if !instance.task.Aborted() {
		// Send abort signal to subtasks' parent task
		if xerr := instance.task.Abort(); xerr != nil {
			errors = append(errors, xerr)
		}
	}

	if len(errors) > 0 {
		return fail.NewErrorList(errors)
	}
	return nil
}

// Aborted tells if the task group is aborted
func (instance *taskGroup) Aborted() bool {
	if instance.isNull() || instance.task.IsNull() {
		return false
	}

	return instance.task.Aborted()
}

// New creates a subtask from current task
func (instance *taskGroup) New() (Task, fail.Error) {
	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}

	return newTask(context.TODO(), instance.task)
}

// GetGroupStatus returns the status of all tasks running in TaskGroup
func (instance *taskGroup) GetGroupStatus() (map[TaskStatus][]string, fail.Error) {
	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}

	instance.children.lock.RLock()
	defer instance.children.lock.RUnlock()

	status := make(map[TaskStatus][]string)
	for _, sub := range instance.children.tasks {
		if tid, err := sub.task.GetID(); err == nil {
			st, _ := sub.task.GetStatus()
			if len(status[st]) == 0 {
				status[st] = []string{}
			}
			status[st] = append(status[st], tid)
		}
	}
	return status, nil
}

// GetStarted returns the number of subtasks started in the TaskGroup
func (instance *taskGroup) GetStarted() (uint, fail.Error) {
	if instance.isNull() {
		return 0, fail.InvalidInstanceError()
	}

	instance.children.lock.RLock()
	defer instance.children.lock.RUnlock()

	return uint(len(instance.children.tasks)), nil
}
