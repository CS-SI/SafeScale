/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"
)

// TaskGroupResult is a map of the TaskResult of each task
// The index is the ID of the sub-Task running the action.
type TaskGroupResult = map[string]TaskResult

// TaskGroupGuard is the task group interface defining method to wait the TaskGroup
type TaskGroupGuard interface {
	Started() (uint, fail.Error)
	TryWaitGroup() (bool, TaskGroupResult, fail.Error)
	WaitGroup() (TaskGroupResult, fail.Error)
	WaitGroupFor(time.Duration) (bool, TaskGroupResult, fail.Error)
}

//go:generate minimock -o mocks/mock_taskgroup.go -i github.com/CS-SI/SafeScale/v22/lib/utils/concurrency.TaskGroup

// TaskGroup is the task group interface
type TaskGroup interface {
	TaskCore
	TaskGuard
	TaskGroupGuard

	GroupStatus() (map[TaskStatus][]string, fail.Error)
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
	*task
	result TaskGroupResult

	children subTasks

	options []data.ImmutableKeyValue
}

// FUTURE: next version of TaskGroup will allow using options

var (
	// VPL: for future use, I intend to improve TaskGroup to allow these 2 behaviors

	// FailEarly tells the TaskGroup to fail as soon as a child fails
	FailEarly = data.NewImmutableKeyValue("fail", "early")
	// FailLately tells the TaskGroup to end all children before determine if TaskGroup has failed
	FailLately = data.NewImmutableKeyValue("fail", "lately")
)

// NewTaskGroup ...
func NewTaskGroup(options ...data.ImmutableKeyValue) (*taskGroup, fail.Error) { // nolint
	return newTaskGroup(context.TODO(), nil, options...) // nolint
}

// NewTaskGroupWithParent ...
func NewTaskGroupWithParent(parentTask Task, options ...data.ImmutableKeyValue) (*taskGroup, fail.Error) { // nolint
	return newTaskGroup(context.TODO(), parentTask, options...) // nolint
}

// NewTaskGroupWithContext ...
func NewTaskGroupWithContext(ctx context.Context, options ...data.ImmutableKeyValue) (*taskGroup, fail.Error) { // nolint
	return newTaskGroup(ctx, nil, options...)
}

func newTaskGroup(ctx context.Context, parentTask Task, options ...data.ImmutableKeyValue) (tg *taskGroup, err fail.Error) {
	defer fail.OnPanic(&err)
	var t Task

	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil!, use context.Background() instead!")
	}

	if parentTask == nil {
		if ctx == context.TODO() { // nolint
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
			switch v.Key() { // nolint
			case keywordInheritParentIDOption:
				// this option orders copying ParentTask.ID to children; the latter are responsible to update their own ID
				value, ok := v.Value().(bool)
				if ok && value && parentTask != nil {
					id, xerr := parentTask.ID()
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
			default:
			}
		}
	}

	return tg, err
}

// isNull ...
func (instance *taskGroup) isNull() bool {
	return instance == nil || instance.task == nil || valid.IsNil(instance.task)
}

// GetID returns an unique id for the task
func (instance *taskGroup) GetID() (string, fail.Error) {
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	return instance.task.ID()
}

// Signature builds the "signature" of the task group, ie a string representation of the task ID in the format "{taskgroup <id>}".
func (instance *taskGroup) Signature() string {
	if valid.IsNil(instance) {
		return ""
	}

	tid, _ := instance.GetID() // cannot fail, because of instance.isNull above

	return `{taskGroup ` + tid + `}`
}

// Status returns the current status of the TaskGroup (ie the parent Task running the children)
func (instance *taskGroup) Status() (TaskStatus, fail.Error) {
	if valid.IsNil(instance) {
		return TaskStatus(0), fail.InvalidInstanceError()
	}

	return instance.task.Status()
}

// Context returns the TaskGroup context
func (instance *taskGroup) Context() context.Context {
	if valid.IsNil(instance) {
		return context.TODO() // nolint
	}

	return instance.task.Context()
}

// SetID allows specifying task ID. The uniqueness of the ID through all the tasks
// becomes the responsibility of the developer...
func (instance *taskGroup) SetID(id string) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	return instance.task.SetID(id)
}

// Start runs in goroutine the function with parameters
// Returns the subtask created to run the action (should be ignored in most cases)
func (instance *taskGroup) Start(action TaskAction, params TaskParameters, options ...data.ImmutableKeyValue) (tg Task, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return instance, fail.InvalidInstanceError()
	}

	return instance.StartWithTimeout(action, params, 0, options...)
}

// StartWithTimeout runs in goroutine the function with parameters, with a timeout
// Returns the subtask created to run the action (should be ignored in most cases)
func (instance *taskGroup) StartWithTimeout(action TaskAction, params TaskParameters, timeout time.Duration, options ...data.ImmutableKeyValue) (_ Task, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return instance, fail.InvalidInstanceError()
	}

	instance.children.lock.Lock()
	defer instance.children.lock.Unlock()

	status, err := instance.Status()
	if err != nil {
		return instance, err
	}

	switch status {
	case DONE:
		return nil, fail.NotAvailableError("cannot start a new Task in a terminated TaskGroup")

	case READY:
		fallthrough
	case RUNNING:
		// can start a new Task
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
					if casted, ok := v.Value().(func(error) error); ok {
						newChild.normalizeError = casted
					}
				default:
				}
			}
		}

		if timeout > 0 {
			var xerr fail.Error
			_, xerr = subtask.StartWithTimeout(action, params, timeout, options...)
			if xerr != nil {
				return nil, xerr
			}
		} else {
			var xerr fail.Error
			_, xerr = subtask.Start(action, params, options...)
			if xerr != nil {
				return nil, xerr
			}
		}

		instance.children.tasks = append(instance.children.tasks, newChild)

		// starts parent Task doing nothing more than waiting for forceAbort()
		if status != RUNNING {
			fnNOP := func(t Task, _ TaskParameters) (TaskResult, fail.Error) {
				// We disarm the cancel signal because we do not want this task to stop prematurely
				// Abort() will be used on it to abort in time
				t.(*task).lock.Lock()
				t.(*task).cancelDisengaged = true
				t.(*task).lock.Unlock() // nolint

				for {
					aborted := t.Aborted()
					if aborted {
						return nil, fail.AbortedError(nil)
					}
					time.Sleep(100 * time.Microsecond) // FIXME: hardcoded value :-(
				}
			}

			_, stErr := instance.task.Start(fnNOP, nil)
			if stErr != nil {
				logrus.Tracef("ignored task start error: %v", stErr)
			}

		}
		return subtask, nil

	case ABORTED:
		fallthrough
	case TIMEOUT:
		return nil, fail.NotAvailableError("cannot start a new Task in an interrupting TaskGroup")

	case UNKNOWN:
		fallthrough
	default:
		return nil, fail.InconsistentError("cannot start a new Task in TaskGroup: unknown status (%s)", status)
	}
}

// Wait is a synonym to WaitGroup (exists to satisfy interface Task)
func (instance *taskGroup) Wait() (TaskResult, fail.Error) {
	if valid.IsNil(instance) {
		return instance, fail.InvalidInstanceError()
	}

	return instance.WaitGroup()
}

// WaitGroup waits for the task to end, and returns the error (or nil) of the execution
// Returns:
//  - nil, *fail.InconsistentError: if TaskGroup has not started anything
//  - nil, *fail.Error: if anything wrong occurred during the waiting process
//  - TaskGroupResult|nil, *fail.ErrorList: if TaskGroup ended properly but some sub-Tasks fail
//  - TaskGroupResult|nil, *fail.ErrAborted: if TaskGroup has been aborted; ErrAborted Consequences() may contain an ErrorList corresponding to the errors of sub-Tasks (if such errors occurred)
//  - TaskGroupResult|nil, *fail.ErrTimeout: if TaskGroup has reached context deadline
//  - TaskGroupResult|nil, nil: if TaskGroup finished without error
//
// Note: this function may lead to go routine leaks, because we do not want a TaskGroup to be locked due to
//       a sub-Task not responding; if a sub-Task is designed to run forever, it will never end.
//       It's highly recommended to use Task.Aborted() in the body of a TaskAction to check
//       for abortion signal and quit the go routine accordingly to reduce the risk.
func (instance *taskGroup) WaitGroup() (TaskGroupResult, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	started, xerr := instance.Started()
	if xerr != nil {
		return nil, xerr
	}
	// If nothing has been started, WaitGroup succeeds immediately
	if started == 0 {
		return nil, nil
	}

	tid, xerr := instance.GetID()
	if xerr != nil {
		return nil, xerr
	}

	for {
		status, xerr := instance.Status()
		if xerr != nil {
			return nil, xerr
		}

		switch status {
		case READY:
			return nil, fail.InconsistentError("cannot wait a TaskGroup that has not been started")

		case DONE:
			instance.task.lock.RLock()
			//goland:noinspection GoDeferInLoop
			defer instance.task.lock.RUnlock() // nolint

			if fail.Cause(instance.task.err) == context.Canceled {
				return instance.result, fail.AbortedError(instance.task.err)
			}

			return instance.result, instance.task.err

		case TIMEOUT:
			fallthrough
		case ABORTED:
			fallthrough
		case RUNNING:
			// instance.task.lock.RLock()
			// previousErr := instance.task.err
			// instance.task.lock.RUnlock()

			results, childrenErrors, waitingFailure := instance.waitChildren()
			if waitingFailure != nil { // TODO: Think how to react to that
				logrus.Warnf(waitingFailure.Error())
			}
			instance.result = results
			if len(childrenErrors) == 0 {
				instance.children.ended = true
			}

			// parent task is running, we need to abort it, even if abort was disable, now that all the children have terminated
			instance.task.forceAbort()

			_, check := instance.task.Wait() // will get *fail.ErrAborted, we know that, we asked for
			if check != nil {
				if _, ok := check.(*fail.ErrAborted); !ok || valid.IsNil(check) {
					logrus.Tracef("BROKEN ASSUMPTION: %v", check)
				}
			}

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
			instance.task.lock.Unlock() // nolint
			continue

		case UNKNOWN:
			return nil, fail.InconsistentError("cannot wait on TaskGroup in 'UNKNOWN' state")

		default:
			return nil, fail.ForbiddenError("cannot wait task group '%s': not running (%s)", tid, status)
		}
	}
}

// addErrorsAsConsequence adds errors in map 'in' as consequences to the fail.Error 'out'
func (instance *taskGroup) addErrorsAsConsequence(in map[string]error, out *fail.Error) {
	if out == nil {
		return
	}
	for i, e := range in {
		added := false
		switch cerr := e.(type) {
		case *fail.ErrAborted:
			cause := fail.ConvertError(fail.Cause(cerr))
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
			cause := fail.ConvertError(fail.Cause(cerr))
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
func (instance *taskGroup) waitChildren() (TaskGroupResult, map[string]error, fail.Error) {
	instance.children.lock.RLock()
	defer instance.children.lock.RUnlock()

	childrenCount := len(instance.children.tasks)
	errorList := make(map[string]error)
	results := make(TaskGroupResult, childrenCount)

	broken := false

	for _, s := range instance.children.tasks {
		sid, err := s.task.ID()
		if err != nil {
			broken = true
			continue
		}

		result, err := s.task.Wait()
		if err != nil {
			if s.normalizeError != nil {
				if normalizedError := s.normalizeError(err); normalizedError != nil {
					if fail.Cause(normalizedError) == context.Canceled {
						errorList[sid] = fail.AbortedError(normalizedError)
					} else {
						errorList[sid] = normalizedError
					}
				}
			} else {
				if fail.Cause(err) == context.Canceled {
					errorList[sid] = fail.AbortedError(err)
				} else {
					errorList[sid] = err
				}
			}
		}

		results[sid] = result
	}

	if broken {
		return results, errorList, fail.NewError("We failed retrieving the ID of some children")
	}

	return results, errorList, nil
}

// TryWait executes TryWaitGroup
func (instance *taskGroup) TryWait() (bool, TaskResult, fail.Error) {
	if valid.IsNil(instance) {
		return false, nil, fail.InvalidInstanceError()
	}

	return instance.TryWaitGroup()
}

// TryWaitGroup tries to wait on a TaskGroup
// If TaskGroup done, returns (true, TaskResult, <error from the task>)
// If TaskGroup aborted, returns (false, nil, *fail.ErrAborted) (subsequent calls of TryWaitGroup may be necessary)
// If TaskGroup still running, returns (false, nil, nil)
// if TaskGroup is not started, returns (false, nil, *fail.ErrInconsistent)
func (instance *taskGroup) TryWaitGroup() (bool, TaskGroupResult, fail.Error) {
	if valid.IsNil(instance) {
		return false, nil, fail.InvalidInstanceError()
	}

	tid, xerr := instance.GetID()
	if xerr != nil {
		return false, nil, xerr
	}

	taskStatus, xerr := instance.task.Status()
	if xerr != nil {
		return false, nil, xerr
	}
	if taskStatus != RUNNING && taskStatus != ABORTED {
		return false, nil, fail.NewError("cannot wait task group '%s': not running (%s)", tid, taskStatus)
	}

	instance.children.lock.RLock()
	defer instance.children.lock.RUnlock()

	for _, s := range instance.children.tasks {
		castedTask, ok := s.task.(*task)
		if !ok {
			return false, nil, fail.InconsistentError("failed to cast s.task to '*task'")
		}

		castedTask.lock.RLock()
		runTerminated := castedTask.runTerminated
		castedTask.lock.RUnlock() // nolint
		if !runTerminated {
			return false, nil, nil
		}
	}

	// all children terminate, now recover results and errors
	results, childrenErrors, waitingFailure := instance.waitChildren()
	if waitingFailure != nil { // TODO: Think how to react to that
		logrus.Warnf(waitingFailure.Error())
	}
	instance.result = results
	if len(childrenErrors) == 0 {
		instance.children.ended = true
	}

	// parent task is still running, we need to abort it, even if abort was disable, now that all the children have terminated
	instance.task.forceAbort()

	_, check := instance.task.Wait() // will get *fail.ErrAborted, we know that, we asked for
	if check != nil {
		if _, ok := check.(*fail.ErrAborted); !ok || valid.IsNil(check) {
			logrus.Tracef("BROKEN ASSUMPTION: %v", check)
		}
	}

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
	instance.task.lock.Unlock() // nolint

	// now constructs
	instance.lock.RLock()
	defer instance.lock.RUnlock()
	return true, instance.result, instance.task.err
}

// WaitFor is an alias to WaitGroupFor to satisfy interface TaskCore
func (instance *taskGroup) WaitFor(duration time.Duration) (bool, TaskResult, fail.Error) {
	if valid.IsNil(instance) {
		return false, nil, fail.InvalidInstanceError()
	}

	return instance.WaitGroupFor(duration)
}

// WaitGroupFor waits for the task to end, for 'timeout' duration
// Note: if 'timeout' is reached, the TaskGroup IS NOT ABORTED. You have to abort then wait for it explicitly if needed.
// Returns:
// - true, TaskGroupResult, nil: Wait worked and TaskGroup generated no error
// - true, TaskGroupResult, *fail.ErrAborted: TaskGroup terminated on Abort (and possible generated error, after
//                                            abort signal has been received, would be attached to the error as consequence)
// - true, TaskGroupResult, fail.Error: TaskGroup terminated, but generated an error
// - false, nil, *fail.ErrInconsistent: cannot wait on a TaskGroup not started
// - false, nil, *fail.ErrTimeout: WaitGroupFor has timed out
func (instance *taskGroup) WaitGroupFor(timeout time.Duration) (bool, TaskGroupResult, fail.Error) {
	if valid.IsNil(instance) {
		return false, nil, fail.InvalidInstanceError()
	}

	tid, xerr := instance.GetID()
	if xerr != nil {
		return false, nil, xerr
	}

	taskStatus, xerr := instance.task.Status()
	if xerr != nil {
		return false, nil, xerr
	}

	var waitGroupErr fail.Error
	results := make(map[string]TaskResult)
	switch taskStatus {
	case READY:
		return false, nil, fail.InconsistentError("cannot wait TaskGroup '%s': not started", tid)

	case DONE:
		instance.task.lock.RLock()
		defer instance.task.lock.RUnlock()
		return true, instance.result, instance.task.err

	case TIMEOUT:
		fallthrough
	case ABORTED:
		fallthrough
	case RUNNING:
		doneWaitingCh := make(chan struct{})
		waiterTask, xerr := NewTaskWithParent(instance.task, InheritParentIDOption, AmendID("WaitGroupForHelper"))
		if xerr != nil {
			return false, nil, fail.Wrap(xerr, "failed to create task to wait")
		}
		_, xerr = waiterTask.Start(
			func(t Task, _ TaskParameters) (_ TaskResult, innerXErr fail.Error) {
				// We do not want abort signal to reach this task
				t.(*task).lock.Lock()
				t.(*task).abortDisengaged = true
				t.(*task).cancelDisengaged = true
				t.(*task).lock.Unlock() // nolint

				var done bool
				for !t.Aborted() && !done {
					done, results, waitGroupErr = instance.TryWaitGroup()
					if !done {
						time.Sleep(100 * time.Microsecond) // FIXME: hardcoded value :-(
					}
				}
				if done {
					doneWaitingCh <- struct{}{}
				}
				return nil, nil
			}, nil,
		)
		if xerr != nil {
			return false, nil, fail.Wrap(xerr, "failed to start task to wait")
		}

		if timeout > 0 {
			select {
			case <-time.After(timeout):
				// VPL: too late...
				// if done, xerr := waiterTask.IsSuccessful(); xerr == nil && done {
				// 	fmt.Println("waiterTask is done but we reached timeout!!!")
				// }

				// signal waiterTask to abort (and do not wait for it, it will terminate)
				waiterTask.(*task).forceAbort()
				forgedError := fail.TimeoutError(nil, timeout, fmt.Sprintf("timeout of %s waiting for TaskGroup '%s'", timeout, tid))

				// // Now send abort signal to TaskGroup
				// xerr = instance.Abort()
				// if xerr != nil {
				// 	_ = forgedError.AddConsequence(xerr)
				// }
				// // We do not wait on TaskGroup after the Abort, because if the TaskActions are badly coded and never
				// // terminate, WaitGroup would not terminate neither... So bad for leaked go routines but this function has to end...
				return false, nil, forgedError

			case <-doneWaitingCh:
				return true, results, waitGroupErr
			}
		} else {
			select { // nolint
			case <-doneWaitingCh:
				return true, results, waitGroupErr
			}
		}

	case UNKNOWN:
		fallthrough
	default:
		return false, nil, fail.InvalidRequestError("cannot wait task group '%s': not running (%s)", tid, taskStatus)
	}
}

// Abort aborts the task execution
// If TaskGroup is already finished, returns nil (and in this case TaskGroup.Wait() will not report a *fail.ErrAborted)
// Otherwise, return error if Abort() was not sent successfully
func (instance *taskGroup) Abort() fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	instance.task.lock.RLock()
	status := instance.task.status
	instance.task.lock.RUnlock() // nolint

	// If taskGroup is not started, go directly to Abort
	if status == READY {
		instance.task.lock.Lock()
		instance.task.status = DONE
		instance.task.err = fail.AbortedError(nil)
		instance.task.lock.Unlock() // nolint
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

func (instance *taskGroup) AbortWithCause(cerr fail.Error) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	instance.task.lock.RLock()
	status := instance.task.status
	instance.task.lock.RUnlock() // nolint

	// If taskGroup is not started, go directly to Abort
	if status == READY {
		instance.task.lock.Lock()
		instance.task.status = DONE
		instance.task.err = fail.AbortedError(cerr)
		instance.task.lock.Unlock() // nolint
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
	if valid.IsNil(instance) || valid.IsNil(instance.task) {
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
			return false
		}
	case READY: // this is awful
		return false
	case UNKNOWN: // this is bad
		return false
	}

	return false
}

// New creates a subtask from current task
func (instance *taskGroup) New() (Task, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	return newTask(context.TODO(), instance.task) // nolint
}

// GroupStatus returns a map of the status of all children running in TaskGroup, ordered by TaskStatus
func (instance *taskGroup) GroupStatus() (map[TaskStatus][]string, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	instance.children.lock.RLock()
	defer instance.children.lock.RUnlock()

	status := make(map[TaskStatus][]string)
	for _, sub := range instance.children.tasks {
		tid, err := sub.task.ID()
		if err != nil {
			continue
		}
		st, err := sub.task.Status()
		if err != nil {
			continue
		}
		if len(status[st]) == 0 {
			status[st] = []string{}
		}
		status[st] = append(status[st], tid)
	}
	return status, nil
}

// Started returns the number of subtasks started in the TaskGroup
func (instance *taskGroup) Started() (uint, fail.Error) {
	if valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}

	instance.children.lock.RLock()
	defer instance.children.lock.RUnlock()

	return uint(len(instance.children.tasks)), nil
}
