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
type TaskGroupResult = map[string]TaskResult

// TaskGroupGuard is the task group interface defining method to wait the TaskGroup
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
	ended bool // set to true when all subtasks are done (set by Abort() to differentiate an Abort to end properly the TaskGroup of a real Abort)
}

// task is a structure allowing to identify (indirectly) goroutines
type taskGroup struct {
	// last uint
	*task
	result TaskGroupResult

	children subTasks

	options []data.ImmutableKeyValue
}

// FUTURE: next version of TaskGroup will allow using options

var (
	// VPL: for future use, I intend to improve TaskGroup to allow these 2 behaviours
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

// Start runs in goroutine the function with parameters
// Returns the subtask created to run the action (should be ignored in most cases)
func (instance *taskGroup) Start(action TaskAction, params TaskParameters, options ...data.ImmutableKeyValue) (tg Task, xerr fail.Error) {
	defer fail.OnPanic(&xerr)
	if instance.isNull() {
		return instance, fail.InvalidInstanceError()
	}

	return instance.StartWithTimeout(action, params, 0, options...)
}

// StartWithTimeout runs in goroutine the function with parameters, with a timeout
// Returns the subtask created to run the action (should be ignored in most cases)
func (instance *taskGroup) StartWithTimeout(action TaskAction, params TaskParameters, timeout time.Duration, options ...data.ImmutableKeyValue) (_ Task, xerr fail.Error) {
	defer fail.OnPanic(&xerr)
	if instance.isNull() {
		return instance, fail.InvalidInstanceError()
	}

	instance.children.lock.Lock()
	defer instance.children.lock.Unlock()

	status, err := instance.GetStatus()
	if err != nil {
		return instance, err
	}

	// Do not try to start a new Task if TaskGroup is aborted or terminated (all children are done and TaskGroup has been waited)
	if status != READY && status != RUNNING {
		return nil, fail.InvalidRequestError("cannot start a new action, TaskGroup is aborted or done (status=%d)", status)
	}

	// instance.last++
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
			case "normalize_error":
				newChild.normalizeError = v.Value().(func(error) error)
			default:
			}
		}
	}

	if timeout > 0 {
		_, xerr = subtask.StartWithTimeout(action, params, timeout, options...)
	} else {
		_, xerr = subtask.Start(action, params)
	}
	if xerr != nil {
		return nil, err
	}

	instance.children.tasks = append(instance.children.tasks, newChild)

	// starts parent Task doing nothing more than waiting for Abort()
	if status != RUNNING {
		fnNOP := func(t Task, _ TaskParameters) (TaskResult, fail.Error) {
			tid, _ := t.GetID()
			for !t.Aborted() {
				fmt.Printf("{%s}: fnNOP: Aborted() == true\n", tid)
				time.Sleep(50 * time.Millisecond) // FIXME: hardcoded value :-(
				return nil, fail.AbortedError(nil)
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

// IsSuccessful tells if the TaskGroup has been executed without error
func (instance *taskGroup) IsSuccessful() (bool, fail.Error) {
	if instance.isNull() {
		return false, fail.InvalidInstanceError()
	}

	instance.task.lock.RLock()
	defer instance.task.lock.RUnlock()

	return instance.task.IsSuccessful()
}

// Wait is a synonym to WaitGroup (exists to satisfy interface Task)
func (instance *taskGroup) Wait() (TaskResult, fail.Error) {
	if instance.isNull() {
		return instance, fail.InvalidInstanceError()
	}

	return instance.WaitGroup()
}

// WaitGroup waits for the task to end, and returns the error (or nil) of the execution
// Returns:
//  - nil, *fail.InconsistentError: if TaskGroup has not started anything
//  - nil, *fail.Error: if anything wrong occurred during the waiting process
//  - TaskGroupResult|nil, *fail.ErrorList: if TaskGroup ended properly but some sub-Tasks fail
//  - TaskGroupResult|nil, *fail.ErrAborted: if TaskGroup has been aborted; ErrAborted Consequences() may contain an ErrorList corresponding to the errors of sub-Tasks
//  - TaskGroupResult|nil, *fail.ErrTimeout: if TaskGroup has reached context deadline
//  - TaskGroupResult|nil, nil: if TaskGroup finished without error
//
// Note: this function may lead to go routine leaks, because we do not want a TaskGroup to be locked due to
//       a sub-Task not responding; if a sub-Task is designed to run forever, it will never end.
//       It's highly recommended to use Task.Aborted() in the body of a TaskAction to check
//       for abortion signal and quit the go routine accordingly to reduce the risk.
func (instance *taskGroup) WaitGroup() (TaskGroupResult, fail.Error) {
	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}

	tid, xerr := instance.GetID()
	if xerr != nil {
		return nil, xerr
	}

	childrenErrors := make(map[string]error)
	results := make(TaskGroupResult, len(instance.children.tasks))

	for {
		status, xerr := instance.GetStatus()
		if xerr != nil {
			return nil, xerr
		}

		switch status {
		case READY:
			return nil, fail.InconsistentError("cannot wait a TaskGroup that has not been started")

		case DONE:
			instance.task.lock.RLock()
			defer instance.task.lock.RUnlock()

			// if instance.task.err != nil {
			// 	switch cerr := instance.task.err.(type) {
			// 	case *fail.ErrAborted:
			// 		consequences := cerr.Consequences()
			// 		if consequences == nil && instance.children.ended {
			// 			// situation where we do not want WaitGroup() to return *fail.ErrAborted, because children terminated properly
			// 			instance.task.err = nil
			// 		}
			// 	}
			// }
			return instance.result, instance.task.err

		case TIMEOUT:
			fallthrough
		case ABORTED:
			fallthrough
		case RUNNING:
			// instance.task.lock.RLock()
			// previousErr := instance.task.err
			// instance.task.lock.RUnlock()

			results, childrenErrors = instance.waitChildren()
			instance.result = results
			if len(childrenErrors) == 0 {
				instance.children.ended = true
			}

			// parent task is running, we need to abort it, even if abort was disable, now that all the children have terminated
			instance.task.lock.Lock()
			instance.task.forceAbort()
			instance.task.lock.Unlock()

			_, _ = instance.task.Wait() // will get *fail.ErrAborted, we know that, we asked for

			var forgedError fail.Error
			if status == ABORTED {
				forgedError = instance.task.err
			}
			instance.task.lock.Lock()
			if len(childrenErrors) > 0 {
				switch forgedError.(type) {
				case *fail.ErrAborted:
					if !instance.children.ended {
						instance.addErrorsAsConsequence(childrenErrors, &forgedError)
					} else {
						forgedError = fail.AbortedError(instance.buildErrorList(childrenErrors), "TaskGroup aborted with failures")
					}
				default:
					forgedError = instance.buildErrorList(childrenErrors)
				}
			}
			instance.task.err = forgedError
			instance.task.status = DONE
			instance.task.lock.Unlock()
			continue

		case UNKNOWN:
			return nil, fail.InconsistentError("cannot wait on TaskGroup in 'UNKNOWN' state")

		default:
			return nil, fail.ForbiddenError("cannot wait task group '%s': not running (%d)", tid, status)
		}
	}
	//
	// instance.task.lock.Lock()
	// defer instance.task.lock.Unlock()
	//
	// switch cerr := instance.task.err.(type) {
	// case *fail.ErrAborted:
	// 	cause := fail.ConvertError(cerr.Cause())
	// 	consequences := cerr.Consequences()
	// 	if cause == nil && instance.children.ended && len(consequences) == 0 {
	// 		// situation where we do not want WaitGroup() to return *fail.ErrAborted, because children terminated properly
	// 		instance.task.err = nil
	// 	}
	// }
	// instance.task.status = DONE
	// return instance.result, instance.task.err
}

// addErrorsAsConsequence adds errors in map 'in' as consequences to the fail.Error 'out'
func (instance *taskGroup) addErrorsAsConsequence(in map[string]error, out *fail.Error) {
	for i, e := range in {
		added := false
		switch cerr := e.(type) {
		case *fail.ErrAborted:
			cause := fail.ConvertError(cerr.Cause())
			if cause != nil {
				_ = (*out).AddConsequence(fail.Wrap(cause, "%s", i))
				added = true
			}
		default:
		}
		if !added {
			_ = (*out).AddConsequence(fail.Wrap(e, "%s", i))
		}
	}
}

// buildErrorList builds an instance of fail.ErrorList from a map[string]error (corresponding to children errors)
func (instance *taskGroup) buildErrorList(in map[string]error) fail.Error {
	var errors []error
	for child, e := range in {
		added := false
		switch cerr := e.(type) {
		case *fail.ErrAborted:
			cause := fail.ConvertError(cerr.Cause())
			if cause != nil {
				errors = append(errors, fail.Wrap(cause, "%s", child))
				added = true
			}
		default:
		}

		if !added {
			errors = append(errors, fail.Wrap(e, "%s", child))
		}
	}
	return fail.NewErrorList(errors)
}

// waitChildren waits all the children to terminate
func (instance *taskGroup) waitChildren() (TaskGroupResult, map[string]error) {
	instance.children.lock.RLock()
	defer instance.children.lock.RUnlock()

	childrenCount := len(instance.children.tasks)
	errorList := make(map[string]error)
	results := make(TaskGroupResult, childrenCount)

	// doneWaitStates := make(map[int]bool, childrenCount)
	// for k := range instance.children.tasks {
	// 	doneWaitStates[k] = false
	// }
	// doneWaitCount := 0
	//
	// for {
	// 	for k, s := range instance.children.tasks {
	// 		if doneWaitStates[k] {
	// 			continue
	// 		}
	//
	// 		sid, err := s.task.GetID()
	// 		if err != nil {
	// 			continue
	// 		}
	//
	// 		done, result, err := s.task.TryWait()
	// 		if done {
	// 			if err != nil {
	// 				if s.normalizeError != nil {
	// 					if normalizedError := s.normalizeError(err); normalizedError != nil {
	// 						errorList[sid] = normalizedError
	// 					}
	// 				} else {
	// 					errorList[sid] = err
	// 				}
	// 			}
	//
	// 			results[sid] = result
	// 			doneWaitStates[k] = true
	// 			doneWaitCount++
	// 			break
	// 		}
	//
	// 		time.Sleep(1 * time.Millisecond)
	// 	}
	//
	// 	if doneWaitCount >= childrenCount {
	// 		break
	// 	}
	// }

	for _, s := range instance.children.tasks {
		for {
			sid, err := s.task.GetID()
			if err != nil {
				break
			}

			result, err := s.task.Wait()
			if err != nil {
				if s.normalizeError != nil {
					if normalizedError := s.normalizeError(err); normalizedError != nil {
						errorList[sid] = normalizedError
					}
				} else {
					errorList[sid] = err
				}
			}

			results[sid] = result
			break
		}
	}

	return results, errorList
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

	taskStatus, xerr := instance.task.GetStatus()
	if xerr != nil {
		return false, nil, xerr
	}
	if taskStatus != RUNNING && taskStatus != ABORTED {
		return false, nil, fail.NewError("cannot wait task group '%s': not running (%d)", tid, taskStatus)
	}

	instance.children.lock.RLock()
	defer instance.children.lock.RUnlock()

	for _, s := range instance.children.tasks {
		s.task.(*task).lock.RLock()
		runTerminated := s.task.(*task).runTerminated
		s.task.(*task).lock.RUnlock()
		if !runTerminated {
			return false, nil, nil
		}
	}

	// all children terminate, now recover results and errors
	results, childrenErrors := instance.waitChildren()
	instance.result = results
	if len(childrenErrors) == 0 {
		instance.children.ended = true
	}

	// parent task is still running, we need to abort it, even if abort was disable, now that all the children have terminated
	instance.task.lock.Lock()
	instance.task.forceAbort()
	instance.task.lock.Unlock()

	_, _ = instance.task.Wait() // will get *fail.ErrErrAborted, we know that, we asked for

	// build error to return for the parent Task
	var forgeError fail.Error
	if taskStatus == ABORTED {
		forgeError = instance.task.err
	}
	instance.task.lock.Lock()
	if len(childrenErrors) > 0 {
		switch forgeError.(type) {
		case *fail.ErrAborted:
			if !instance.children.ended {
				instance.addErrorsAsConsequence(childrenErrors, &forgeError)
			} else {
				forgeError = fail.AbortedError(instance.buildErrorList(childrenErrors), "TaskGroup aborted with failures")
			}
		default:
			forgeError = instance.buildErrorList(childrenErrors)
		}
	}
	instance.task.err = forgeError
	instance.task.lock.Unlock()

	// now constructs
	return true, instance.result, instance.task.err
}

// WaitFor is an alias to WaitGroupFor to satisfy interface TaskCore
func (instance *taskGroup) WaitFor(duration time.Duration) (bool, TaskResult, fail.Error) {
	if instance.isNull() {
		return false, nil, fail.InvalidInstanceError()
	}

	return instance.WaitGroupFor(duration)
}

// WaitGroupFor waits for the task to end, for 'duration' duration
// Returns:
// - true, TaskGroupResult, fail.Error: TaskGroup terminates, but generated an error
// - true, TaskGroupResult, *failErrAborted: Task terminates on Abort
// - false, nil, *fail.ErrTimeout: WaitGroupFor has timed out; TaskGroup is aborted in case of timeout (and eventual error after
//                                 abort signal has been received would be attached to the error as consequence)
func (instance *taskGroup) WaitGroupFor(duration time.Duration) (bool, TaskGroupResult, fail.Error) {
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

	case DONE:
		return true, instance.result, instance.task.err

	case TIMEOUT:
		fallthrough
	case ABORTED:
		fallthrough
	case RUNNING:
		c := make(chan struct{})
		waiterTask, xerr := NewTaskWithParent(instance.task, InheritParentIDOption, AmendID("WaitGroupForHelper"))
		if xerr != nil {
			return false, nil, fail.Wrap(xerr, "failed to create task to wait")
		}
		_, xerr = waiterTask.Start(
			func(t Task, _ TaskParameters) (_ TaskResult, innerXErr fail.Error) {
				// // We do not want abort signal to reach this task
				// t.DisarmAbortSignal()

				var done bool
				for !t.Aborted() && !done {
					done, results, innerXErr = instance.TryWaitGroup()
					if !done {
						time.Sleep(100 * time.Microsecond) // FIXME: hardcoded value :-(
					}
				}
				if done {
					c <- struct{}{}
				}
				return nil, nil
			}, nil,
		)

		if duration > 0 {
			select {
			case <-time.After(duration):
				// // Now we want the waiterTask to react to Abort signal...
				// waiterTask.(*task).lock.Lock()
				// waiterTask.(*task).abortDisengaged = false
				// waiterTask.(*task).lock.Unlock()

				if done, xerr := waiterTask.IsSuccessful(); xerr == nil && done {
					fmt.Println("waiterTask is done but we reached timeout!!!")
				}

				// signal waiterTask to abort (and do not wait for it, it will terminate)
				xerr := waiterTask.Abort()
				tout := fail.TimeoutError(xerr, duration, fmt.Sprintf("timeout of %s waiting for TaskGroup '%s'", duration, tid))

				// Now send abort signal to TaskGroup
				xerr = instance.Abort()
				if xerr != nil {
					_ = tout.AddConsequence(xerr)
				}
				// We do not wait on TaskGroup after the Abort, because if the TaskActions are badly coded and never
				// terminate, WaitGroup would not terminate neither... So bad for leaked go routines but this function has to end...
				return false, nil, tout

			case <-c:
				return true, results, err
			}
		} else {
			select { // nolint
			case <-c:
				return true, results, err
			}
		}

	case UNKNOWN:
		fallthrough
	default:
		return false, nil, fail.InvalidRequestError("cannot wait task group '%s': not running (%d)", tid, taskStatus)
	}
}

// Abort aborts the task execution
// If TaskGroup is already finished, returns nil (and in this case TaskGroup.Wait() will not report a *fail.ErrAborted)
// Otherwise, return error if Abort() was not sent successfully
func (instance *taskGroup) Abort() fail.Error {
	if instance.isNull() {
		return fail.InvalidInstanceError()
	}

	instance.task.lock.RLock()
	tid := instance.task.id
	status := instance.task.status
	instance.task.lock.RUnlock()
	fmt.Printf("{%s}: in Abort()\n", tid)

	// If taskgroup is not started, go directly to Abort
	if status == READY {
		fmt.Printf("{%s}: READY\n", tid)
		instance.task.lock.Lock()
		instance.task.status = DONE
		instance.task.err = fail.AbortedError(nil)
		instance.task.lock.Unlock()
		return nil
	}

	if !instance.task.Aborted() {
		xerr := instance.task.Abort()
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

// Aborted tells if the task group is aborted
func (instance *taskGroup) Aborted() bool {
	if instance.isNull() || instance.task.IsNull() {
		return false
	}

	instance.task.lock.RLock()
	defer instance.task.lock.RUnlock()

	switch instance.task.status {
	case ABORTED:
		fallthrough
	case TIMEOUT:
		return true

	case RUNNING:
		fallthrough
	case DONE:
		switch instance.task.err.(type) {
		case *fail.ErrAborted, *fail.ErrTimeout:
			return true
		default:
		}
	}

	return false
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
