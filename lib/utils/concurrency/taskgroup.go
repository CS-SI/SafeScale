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

	children subTasks //[]subTask

	options []data.ImmutableKeyValue
}

var (
	// FUTURE: next version of TaskGroup will allow to use options
	// FailEarly tells the TaskGroup to fail as soon as a child fails
	FailEarly = data.NewImmutableKeyValue("fail", "early")
	// FailLately tells the TaskGroup to end all children before determine if TaskGroup has failed
	FailLately = data.NewImmutableKeyValue("fail", "lately")
)

// NewTaskGroup ...
func NewTaskGroup(parentTask Task, options ...data.ImmutableKeyValue) (*taskGroup, fail.Error) { // nolint
	return newTaskGroup(context.TODO(), parentTask, options...)
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
	tg = &taskGroup{
		task:     t.(*task),
		children: subTasks{
			// lock: NewTaskedLock(),
		},
		options: options,
	}
	return tg, err
}

// isNull ...
func (tg *taskGroup) isNull() bool {
	return tg == nil || tg.task.IsNull()
}

// GetID returns an unique id for the task
func (tg *taskGroup) GetID() (string, fail.Error) {
	if tg.isNull() {
		return "", fail.InvalidInstanceError()
	}

	return tg.task.GetID()
}

// GetSignature builds the "signature" of the task group, ie a string representation of the task ID in the format "{taskgroup <id>}".
func (tg *taskGroup) GetSignature() string {
	if tg.isNull() {
		return ""
	}

	tid, err := tg.GetID()
	if err != nil {
		return ""
	}

	return `{taskGroup ` + tid + `}`
}

// GetStatus returns the current task status
func (tg *taskGroup) GetStatus() (TaskStatus, fail.Error) {
	if tg.isNull() {
		return TaskStatus(0), fail.InvalidInstanceError()
	}

	return tg.task.GetStatus()
}

// GetContext returns the current task status
func (tg *taskGroup) GetContext() context.Context {
	if tg.isNull() {
		return context.TODO()
	}

	return tg.task.GetContext()
}

// SetID allows to specify task ID. The uniqueness of the ID through all the tasks
// becomes the responsibility of the developer...
func (tg *taskGroup) SetID(id string) fail.Error {
	if tg.isNull() {
		return fail.InvalidInstanceError()
	}

	return tg.task.SetID(id)
}

// StartInSubtask starts an action in a subtask
func (tg *taskGroup) StartInSubtask(action TaskAction, params TaskParameters, options ...data.ImmutableKeyValue) (Task, fail.Error) {
	if tg.isNull() {
		return tg, fail.InvalidInstanceError()
	}
	return tg.Start(action, params, options...)
}

// Start runs in goroutine the function with parameters
// Returns the subtask created to run the action (should be ignored in majority of cases)
func (tg *taskGroup) Start(action TaskAction, params TaskParameters, options ...data.ImmutableKeyValue) (Task, fail.Error) {
	if tg.isNull() {
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

	newChild := subTask{
		task: subtask,
	}

	if len(options) > 0 {
		for _, v := range options {
			switch v.Key() {
			case "normalizeError":
				newChild.normalizeError = v.Value().(func(error) error)
			default:
			}
		}
	}

	_, xerr := subtask.Start(action, params)
	if xerr != nil {
		return tg, err
	}

	tg.children.lock.Lock()
	tg.children.tasks = append(tg.children.tasks, newChild)
	tg.children.lock.Unlock()

	if status != RUNNING {
		tg.task.mu.Lock()
		tg.task.status = RUNNING
		tg.task.mu.Unlock()
	}

	return subtask, nil
}

// Wait is a synonym to WaitGroup (exists to satisfy interface Task)
func (tg *taskGroup) Wait() (TaskResult, fail.Error) {
	if tg.isNull() {
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
	if tg.isNull() {
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

	errs := make(map[string]error)
	results := make(TaskGroupResult, len(tg.children.tasks))

	switch taskStatus {
	case DONE:
		tg.task.mu.Lock()
		defer tg.task.mu.Unlock()

		results = tg.result
		return results, tg.task.err

	//case ABORTED:
	//	var errors []error
	//
	//	tg.task.mu.Lock()
	//	if tg.task.err != nil {
	//		errors = append(errors, tg.task.err)
	//	}
	//	tg.task.mu.Unlock()
	//
	//	tg.children.lock.RLock()
	//	defer tg.children.lock.RUnlock()
	//
	//	for _, s := range tg.children.tasks {
	//		if lerr, _ := s.task.GetLastError(); lerr != nil {
	//			errors = append(errors, lerr)
	//		}
	//	}
	//	return nil, fail.AbortedError(fail.NewErrorList(errors), "taskgroup was already aborted")
	//}
	case RUNNING, READY, ABORTED:
		doneWaitSize := len(tg.children.tasks)
		doneWaitStates := make(map[int]bool, doneWaitSize)
		for k := range tg.children.tasks {
			doneWaitStates[k] = false
		}
		doneWaitCount := 0

		tg.children.lock.RLock()
		defer tg.children.lock.RUnlock()

		for {
			//stop := false
			for k, s := range tg.children.tasks {
				//if tg.Aborted() {
				//	stop = true
				//	break
				//}

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
				}
			}

			if /*stop || */ doneWaitCount >= doneWaitSize {
				break
			}

			time.Sleep(1 * time.Millisecond)
		}

		var errors []error
		for i, e := range errs {
			errors = append(errors, fail.Wrap(e, "%s", i))
		}

		tg.task.mu.Lock()
		defer tg.task.mu.Unlock()

		tg.task.result = results
		if len(errors) > 0 {
			if taskStatus == ABORTED {
				tg.task.err = fail.AbortedError(fail.NewErrorList(errors), "aborted")
			}
		} else {
			tg.task.err = nil
		}

		if tg.task.status != ABORTED {
			tg.task.status = DONE
		}
		tg.result = results
		return results, tg.task.err

	default:
		return nil, fail.ForbiddenError("cannot wait task group '%s': not running (%d)", tid, taskStatus)
	}
}

// TryWait ...
func (tg *taskGroup) TryWait() (bool, TaskResult, fail.Error) {
	if tg.isNull() {
		return false, nil, fail.InvalidInstanceError()
	}

	return tg.TryWaitGroup()
}

// TryWaitGroup tries to wait on a task; if done returns the error and true, if not returns nil and false
func (tg *taskGroup) TryWaitGroup() (bool, map[string]TaskResult, fail.Error) {
	if tg.isNull() {
		return false, nil, fail.InvalidInstanceError()
	}

	tid, xerr := tg.GetID()
	if xerr != nil {
		return false, nil, xerr
	}

	results := make(map[string]TaskResult)

	taskStatus, xerr := tg.task.GetStatus()
	if xerr != nil {
		return false, nil, xerr
	}
	if taskStatus != RUNNING && taskStatus != ABORTED {
		return false, nil, fail.NewError("cannot wait task group '%s': not running (%d)", tid, taskStatus)
	}

	{
		tg.children.lock.RLock()
		defer tg.children.lock.RUnlock()

		for _, s := range tg.children.tasks {
			if ok, _, _ := s.task.TryWait(); !ok {
				return false, nil, nil
			}
		}
	}

	result, xerr := tg.Wait()
	results[tid] = result
	return true, results, xerr
}

// WaitFor ...
func (tg *taskGroup) WaitFor(duration time.Duration) (bool, TaskResult, fail.Error) {
	if tg.isNull() {
		return false, nil, fail.InvalidInstanceError()
	}

	return tg.WaitGroupFor(duration)
}

// WaitGroupFor waits for the task to end, for 'duration' duration
// If duration elapsed, returns (false, nil, nil)
func (tg *taskGroup) WaitGroupFor(duration time.Duration) (bool, map[string]TaskResult, fail.Error) {
	if tg.isNull() {
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
		return false, nil, fail.InvalidRequestError("cannot wait task '%s': not running (%d)", tid, taskStatus)
	}

	c := make(chan struct{})
	go func() {
		results, err = tg.WaitGroup()
		c <- struct{}{} // done
		close(c)
	}()

	if duration > 0 {
		select {
		case <-time.After(duration):
			tout := fail.TimeoutError(nil, duration, fmt.Sprintf("timeout of %s waiting for task group '%s'", duration, tid))
			abErr := tg.Abort()
			if abErr != nil {
				_ = tout.AddConsequence(abErr)
			}
			return false, nil, tout
		case <-c:
			return true, results, err
		}
	}

	select { //nolint
	case <-c:
		return true, results, err
	}
}

// Abort aborts the task execution
func (tg *taskGroup) Abort() fail.Error {
	if tg.isNull() {
		return fail.InvalidInstanceError()
	}

	var errors []error

	// TODO: check if sending Abort to parent task is not sufficient (it should because of use of context)
	// Send abort signal to subtasks
	tg.children.lock.RLock()
	for _, st := range tg.children.tasks {
		if xerr := st.task.Abort(); xerr != nil {
			errors = append(errors, xerr)
		}
	}
	tg.children.lock.RUnlock()

	// Send abort signal to subtasks' parent task
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
	if tg.isNull() || tg.task.IsNull() {
		return false
	}
	return tg.task.Aborted()
}

// New creates a subtask from current task
func (tg *taskGroup) New() (Task, fail.Error) {
	if tg.isNull() {
		return nil, fail.InvalidInstanceError()
	}

	return newTask(context.TODO(), tg.task)
}

// GetGroupStatus returns the status of all tasks running in TaskGroup
func (tg *taskGroup) GetGroupStatus() (map[TaskStatus][]string, fail.Error) {
	if tg.isNull() {
		return nil, fail.InvalidInstanceError()
	}

	tg.children.lock.RLock()
	defer tg.children.lock.RUnlock()

	status := make(map[TaskStatus][]string)
	for _, sub := range tg.children.tasks {
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
