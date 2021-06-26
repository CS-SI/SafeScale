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
	"sync/atomic"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// TaskStatus ...
type TaskStatus int

const (
	UNKNOWN TaskStatus = iota // status is unknown
	READY                     // the task is ready to start
	RUNNING                   // the task is running
	DONE                      // the task has run and is done
	ABORTED                   // the task has been aborted
	TIMEOUT                   // the task ran out of time
)

// TaskParameters ...
type TaskParameters interface{}

// TaskResult ...
type TaskResult interface{}

// TaskAction defines the type of the function that can be started by a Task.
// NOTE: you have to check if task is aborted inside this function using method t.ErrAborted(),
//       to be able to stop the process when task is aborted (no matter what
//       the abort reason is), and permit to end properly. Otherwise this may lead to goroutine leak
//       (there is no good way to stop forcibly a goroutine).
// Example:
// task.Start(func(task concurrency.Task, p TaskParameters) (concurrency.TaskResult, fail.Error) {
// ...
//    for {
//        if task.ErrAborted() {
//            break // or return
//        }
//        ...
//    }
//    return nil
// }, nil)
type TaskAction func(t Task, parameters TaskParameters) (TaskResult, fail.Error)

// TaskGuard ...
type TaskGuard interface {
	TryWait() (bool, TaskResult, fail.Error)
	Wait() (TaskResult, fail.Error)
	WaitFor(time.Duration) (bool, TaskResult, fail.Error)
}

// TaskCore is the interface of core methods to control task and taskgroup
type TaskCore interface {
	Abort() fail.Error
	Abortable() (bool, fail.Error)
	Aborted() bool
	DisarmAbortSignal() func()
	GetID() (string, fail.Error)
	GetSignature() string
	GetStatus() (TaskStatus, fail.Error)
	GetContext() context.Context
	GetLastError() (error, fail.Error)
	GetResult() (TaskResult, fail.Error)
	IsSuccessful() (bool, fail.Error)
	SetID(string) fail.Error

	Run(TaskAction, TaskParameters) (TaskResult, fail.Error)
	Start(fn TaskAction, params TaskParameters, options ...data.ImmutableKeyValue) (Task, fail.Error)
	StartWithTimeout(fn TaskAction, params TaskParameters, timeout time.Duration, options ...data.ImmutableKeyValue) (Task, fail.Error)
}

// Task is the interface of a task running in goroutine, allowing to identity (indirectly) goroutines
type Task interface {
	TaskCore
	TaskGuard
}

// task is a structure allowing to identify (indirectly) goroutines
type task struct {
	lock sync.RWMutex
	id   string

	ctx    context.Context
	cancel context.CancelFunc
	status TaskStatus

	controllerTerminatedCh chan struct{} // Used to signal Wait() (and siblings) the controller of the go routine has terminated
	runTerminatedCh        chan bool     // Used by go routine to signal it has done its processing
	abortCh                chan bool     // Used to signal the routine it has to stop processing

	err    fail.Error
	result TaskResult

	abortDisengaged bool
}

const (
	// keywordInheritParentIDOption is the string to use to make task inherit the ID ofr the parent task
	keywordInheritParentIDOption = "inherit_parent_id"
	keywordAmendID               = "amend_id"
)

var (
	globalTask            atomic.Value
	InheritParentIDOption = data.NewImmutableKeyValue(keywordInheritParentIDOption, true)
)

// AmendID returns a data.ImmutableKeyValue containing string to add to task ID
// to be used as option on NewXXX functions that accept such options
func AmendID(id string) data.ImmutableKeyValue {
	return data.NewImmutableKeyValue(keywordAmendID, id)
}

// RootTask is the "task to rule them all"
func RootTask() (rt Task, xerr fail.Error) {
	defer fail.OnPanic(&xerr)
	anon := globalTask.Load()
	if anon == nil {
		newT, err := newTask(context.Background(), nil)
		if err != nil {
			return nil, err
		}

		newT.id = "0"
		globalTask.Store(newT)
		anon = globalTask.Load()
	}
	return anon.(Task), nil
}

// VoidTask is a new task that do nothing
func VoidTask() (Task, fail.Error) {
	return NewTask()
}

// user-defined type to use as key in context.WithValue()
type taskContextKey = string

const (
	KeyForTaskInContext taskContextKey = "task"
)

// TaskFromContext extracts the task instance from context
func TaskFromContext(ctx context.Context) (Task, fail.Error) {
	if ctx != nil {
		if ctxValue := ctx.Value(KeyForTaskInContext); ctxValue != nil {
			if task, ok := ctxValue.(Task); ok {
				return task, nil
			}
			return nil, fail.InconsistentError("context value for 'task' is not a 'concurrency.Task'")
		}
	}

	return VoidTask()
}

// NewTask creates a new instance of Task
func NewTask() (Task, fail.Error) {
	return newTask(context.Background(), nil)
}

// NewUnbreakableTask is a new task that cannot be aborted by default (but this can be changed with IgnoreAbortSignal(false))
func NewUnbreakableTask() (Task, fail.Error) {
	nt, err := newTask(context.Background(), nil) // nolint
	if err != nil {
		return nil, err
	}

	// To be able to For safety, normally the cancel signal capture routine is not started in this case...
	nt.abortDisengaged = true
	return nt, nil
}

// NewTaskWithParent creates a subtask
// Such a task can be aborted if the parent one can be
func NewTaskWithParent(parentTask Task, options ...data.ImmutableKeyValue) (Task, fail.Error) {
	if parentTask == nil {
		return nil, fail.InvalidParameterError("parentTask", "must not be nil")
	}

	return newTask(context.Background(), parentTask, options...)
}

// NewTaskWithContext creates an intance of Task with context
func NewTaskWithContext(ctx context.Context, options ...data.ImmutableKeyValue) (Task, fail.Error) {
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	return newTask(ctx, nil, options...)
}

// newTask creates a new Task from parentTask or using ctx as parent context
func newTask(ctx context.Context, parentTask Task, options ...data.ImmutableKeyValue) (nt *task, xerr fail.Error) {
	defer fail.OnPanic(&xerr)
	var (
		childContext context.Context
		cancel       context.CancelFunc
	)

	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil!, use context.TODO() or context.Background() instead!")
	}

	if parentTask == nil {
		if ctx == context.TODO() {
			childContext, cancel = context.WithCancel(context.Background())
		} else {
			childContext, cancel = context.WithCancel(ctx)
		}
	} else {
		childContext, cancel = context.WithCancel(parentTask.(*task).ctx)
	}
	t := &task{
		cancel:                 cancel,
		status:                 READY,
		abortCh:                make(chan bool, 1),
		runTerminatedCh:        make(chan bool, 1),
		controllerTerminatedCh: make(chan struct{}, 1),
	}

	generateID := true
	if len(options) > 0 {
		for _, v := range options {
			switch v.Key() {
			case keywordInheritParentIDOption:
				value, ok := v.Value().(bool)
				if ok && value && parentTask != nil {
					generateID = false
					id, xerr := parentTask.GetID()
					if xerr != nil {
						return nil, xerr
					}
					t.id = id
				}
			}
		}
	}

	if generateID {
		u, err := uuid.NewV4()
		if err != nil {
			return nil, fail.Wrap(err, "failed to create a new task")
		}

		t.id = u.String()
	}

	if len(options) > 0 {
		for _, v := range options {
			switch v.Key() {
			case keywordAmendID:
				value, ok := v.Value().(string)
				if ok {
					t.id += "+" + value
				}
			}
		}
	}

	t.ctx = context.WithValue(childContext, KeyForTaskInContext, t)

	return t, nil
}

// IsNull ...
func (t *task) IsNull() bool {
	return t == nil || t.id == ""
}

// GetLastError returns the last error of the Task
func (t *task) GetLastError() (error, fail.Error) { // nolint
	if t.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.err, nil
}

// GetResult returns the result of the ended task
func (t *task) GetResult() (TaskResult, fail.Error) {
	if t.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	t.lock.RLock()
	defer t.lock.RUnlock()

	if t.status != DONE {
		return nil, fail.InvalidRequestError("task is not done, there is no result yet")
	}

	return t.result, nil
}

// GetID returns an unique id for the task
func (t *task) GetID() (string, fail.Error) {
	if t.IsNull() {
		return "", fail.InvalidInstanceError()
	}

	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.id, nil
}

// GetSignature builds the "signature" of the task passed as parameter,
// ie a string representation of the task ID in the format "{task <id>}".
func (t *task) GetSignature() string {
	if t.IsNull() {
		return ""
	}

	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.getSignature()
}

func (t *task) getSignature() string {
	if t.id != "" {
		return `{task ` + t.id + `}`
	}
	return ""
}

// GetStatus returns the current task status
func (t *task) GetStatus() (TaskStatus, fail.Error) {
	if t.IsNull() {
		return 0, fail.InvalidInstanceError()
	}

	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.status, nil
}

// GetContext returns the context associated to the task
func (t *task) GetContext() context.Context {
	if t.IsNull() {
		return context.TODO()
	}

	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.ctx
}

// SetID allows to specify task ID. The uniqueness of the ID through all the tasks
// becomes the responsibility of the developer...
func (t *task) SetID(id string) fail.Error {
	if t.IsNull() {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty!")
	}
	if id == "0" {
		return fail.InvalidParameterError("id", "cannot be '0', reserved for root task")
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	if t.status == ABORTED {
		return fail.AbortedError(nil, "aborted")
	}

	t.id = id
	return nil
}

// Start runs in goroutine the function with parameters
func (t *task) Start(action TaskAction, params TaskParameters, options ...data.ImmutableKeyValue) (Task, fail.Error) {
	if t.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	return t.StartWithTimeout(action, params, 0, options...)
}

// StartWithTimeout runs in goroutine the TaskAction with TaskParameters, and stops after timeout (if > 0)
// If timeout happens, error returned will be '*fail.ErrTimeout'
func (t *task) StartWithTimeout(action TaskAction, params TaskParameters, timeout time.Duration, options ...data.ImmutableKeyValue) (Task, fail.Error) {
	if t.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	if t.status != READY {
		return nil, fail.NewError("cannot start task '%s': not ready", t.id)
	}

	if action == nil {
		t.status = DONE
	} else {
		t.status = RUNNING
		t.runTerminatedCh = make(chan bool, 1)
		t.abortCh = make(chan bool, 1)
		t.controllerTerminatedCh = make(chan struct{}, 1)
		go func() {
			ctrlErr := t.controller(action, params, timeout)
			if ctrlErr != nil {
				t.lock.Lock()
				if t.err != nil {
					_ = t.err.AddConsequence(fail.Wrap(ctrlErr, "unexpected error running the Task controller"))
				} else {
					t.err = fail.Wrap(ctrlErr, "unexpected error running the Task controller")
				}
				t.lock.Unlock()
			}
		}()
	}
	return t, nil
}

// controller controls the start, termination and possibly abortion of the action
func (t *task) controller(action TaskAction, params TaskParameters, timeout time.Duration) fail.Error {
	if t.IsNull() {
		return fail.InvalidInstanceError()
	}

	traceR := newTracer(t, tracing.ShouldTrace("concurrency.task"))

	defer func() {
		t.lock.Lock()
		close(t.controllerTerminatedCh)
		if t.cancel != nil {
			// Make sure cancel() is called at the end of the task
			t.cancel()
		}
		t.lock.Unlock()
	}()

	go t.run(action, params)

	finish := false
	if timeout > 0 {
		for !finish {
			select {
			case <-t.ctx.Done():
				xerr := t.processCancel(traceR)
				if xerr != nil {
					return xerr
				}

			case <-t.runTerminatedCh:
				t.processDone(traceR)
				finish = true // stop to react on signals

			case <-t.abortCh:
				xerr := t.processAbort(traceR)
				if xerr != nil {
					return xerr
				}

			case <-time.After(timeout):
				t.processTimeout(timeout)
			}
		}
	} else {
		for !finish {
			select {
			case <-t.ctx.Done():
				xerr := t.processCancel(traceR)
				if xerr != nil {
					return xerr
				}

			case <-t.runTerminatedCh:
				t.processDone(traceR)
				finish = true // stop to react on signals

			case <-t.abortCh:
				xerr := t.processAbort(traceR)
				if xerr != nil {
					return xerr
				}
			}
		}
	}

	return nil
}

// processCancel operates when cancel has been called
func (t *task) processCancel(traceR *tracer) fail.Error {
	// Context cancel signal received, propagating using abort signal
	t.lock.Lock()
	traceR.trace("receiving signal from context, aborting task '%s'...", t.id)
	if !t.abortDisengaged {
		switch t.status {
		case RUNNING:
			switch t.ctx.Err() {
			case context.DeadlineExceeded:
				t.status = TIMEOUT
				t.err = fail.TimeoutError(nil, 0, "context deadline exceeded")
			case context.Canceled:
				fallthrough
			default:
				t.status = ABORTED
			}
			t.abortCh <- true

		case ABORTED:
			fallthrough
		case TIMEOUT:
			fallthrough
		case DONE:
			// do nothing

		case READY: // abnormal status if controller is executed
			fallthrough
		case UNKNOWN: // by definition, this status is invalid
			fallthrough
		default:
			return fail.InconsistentError("invalid Task state '%d'", t.status)
		}
	}
	t.lock.Unlock()
	return nil
}

// processDone operates when go routine terminates
func (t *task) processDone(traceR *tracer) {
	traceR.trace("receiving done signal from go routine")
	t.lock.Lock()
	defer t.lock.Unlock()
	t.controllerTerminatedCh <- struct{}{}
}

// processAbort operates when Abort has been requested
func (t *task) processAbort(traceR *tracer) fail.Error {
	// Abort signal received
	traceR.trace("receiving abort signal")
	t.lock.Lock()
	if !t.abortDisengaged {
		if t.err != nil {
			switch t.err.(type) {
			case *fail.ErrAborted:
				// do nothing
			case *fail.ErrTimeout:
				// do nothing
			default:
				abortError := fail.AbortedError(nil)
				_ = abortError.AddConsequence(t.err)
				t.err = abortError
			}
		} else {
			t.err = fail.AbortedError(nil)
		}
	} else {
		traceR.trace("abort signal is disengaged, ignored")
	}
	t.lock.Unlock()
	return nil
}

// processTimeout operates when timeout occurs
func (t *task) processTimeout(timeout time.Duration) {
	t.lock.Lock()
	if t.status != ABORTED {
		t.abortCh <- true
		t.err = fail.TimeoutError(t.err, timeout)
		t.status = TIMEOUT
	}
	t.lock.Unlock()
}

// run executes the function 'action'
func (t *task) run(action TaskAction, params TaskParameters) {
	defer func() {
		if err := recover(); err != nil {
			t.lock.Lock()
			defer t.lock.Unlock()

			fmt.Printf("panic happened in Task %s\n", t.id)
			if t.err != nil {
				_ = t.err.AddConsequence(fail.RuntimePanicError("panic happened: %v", err))
			} else {
				t.err = fail.RuntimePanicError("panic happened: %v", err)
			}
			t.result = nil
			t.status = DONE
			t.runTerminatedCh <- false
			close(t.runTerminatedCh)
		}
	}()

	result, xerr := action(t, params)

	t.lock.Lock()
	defer t.lock.Unlock()

	t.err = xerr
	t.result = result
	t.runTerminatedCh <- true
	close(t.runTerminatedCh)
}

// Run starts task, waits its completion then return the error code
func (t *task) Run(action TaskAction, params TaskParameters) (TaskResult, fail.Error) {
	if t.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	_, err := t.Start(action, params)
	if err != nil {
		return nil, err
	}

	return t.Wait()
}

// IsSuccessful tells if the Task has been executed without error
func (instance *task) IsSuccessful() (bool, fail.Error) {
	if instance.IsNull() {
		return false, fail.InvalidInstanceError()
	}


	switch instance.status {
	case DONE:
		instance.lock.RLock()
		defer instance.lock.RUnlock()
		return instance.err == nil, nil

	case READY:
		return false, fail.InconsistentError("cannot test the success of a Task that has not started")

	case ABORTED:
		fallthrough
	case TIMEOUT:
		fallthrough
	case RUNNING:
		return false, fail.InvalidRequestError("cannot test the success of a Task that has not been waited")

	case UNKNOWN:
		fallthrough
	default:
		return false, fail.InvalidRequestError("failed to tell if Task is successful: invalid status")
	}
}

// Wait awaits for the task to end, and returns the error (or nil) of the execution
// Returns:
// - TaskResult, nil: the Task ended normally and provide a Result
// - nil, *fail.ErrAborted: the Task has been aborted; *fail.ErrAborted.Consequences() may contain error(s) happening after the signal has been received by the Task
// - nil, *fail.ErrTimeout: the Task has reached its execution delay
// - TaskResult, <other error>: the Task runs successfully but returned an error; the TaskResult usage is dependant of the TaskAction content

func (instance *task) Wait() (TaskResult, fail.Error) {
	if instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	tid := instance.id
	status := instance.status
	instance.lock.RUnlock()

	switch status {
	case READY: // Waiting a ready task always succeed by design
		return nil, fail.InconsistentError("cannot wait a Task that has not been started")

	case DONE:
		instance.lock.RLock()
		defer instance.lock.RUnlock()

		return instance.result, instance.err

	case TIMEOUT:
		fallthrough
	case ABORTED:
		fallthrough
	case RUNNING:
		<-instance.controllerTerminatedCh

		instance.lock.Lock()
		defer instance.lock.Unlock()

		if instance.status == ABORTED {
			// In case of ABORT, if an error is already there, the TASK has ended, so just return this error with the result
			if instance.err != nil {
				instance.status = DONE
				return instance.result, instance.err
			}
			// In case of ABORT, if there is no error and instance.result is not nil, return an Abort error with result
			if instance.result != nil {
				instance.status = DONE
				return instance.result, fail.AbortedError(nil)
			}
		}

		if instance.status == TIMEOUT {
			instance.status = DONE
			instance.result = nil
			instance.err = fail.TimeoutError(nil, 0)
			return nil, instance.err
		}

		instance.status = DONE
		return instance.result, instance.err

	case UNKNOWN:
		fallthrough
	default:
		return nil, fail.InconsistentError("cannot wait task '%s': unknown status (%d)", tid, status)
	}
}

// TryWait tries to wait on a task
// If task done, returns (true, TaskResult, <error from the task>)
// If task is not done, returns (false, nil, nil) (subsequent calls of TryWait may be necessary)
// if Task is not started, returns (false, nil, *fail.ErrInconsistent)
func (instance *task) TryWait() (bool, TaskResult, fail.Error) {
	if instance.IsNull() {
		return false, nil, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	tid := instance.id
	status := instance.status
	instance.lock.RUnlock()

	switch status {
	case READY: // Waiting a ready task always succeed by design
		return false, nil, fail.InconsistentError("cannot wait a Task that has not been started")

	case DONE:
		instance.lock.RLock()
		defer instance.lock.RUnlock()
		return true, instance.result, instance.err

	case ABORTED:
		fallthrough
	case TIMEOUT:
		fallthrough
	case RUNNING:
		if len(instance.controllerTerminatedCh) == 1 {
			_, err := instance.Wait()
			instance.lock.RLock()
			defer instance.lock.RUnlock()
			return true, instance.result, err
		}
		return false, nil, nil

	case UNKNOWN:
		fallthrough
	default:
		return false, nil, fail.NewError("cannot wait task '%s': unknown status (%d)", tid, status)
	}
}

// WaitFor waits for the task to end, for 'duration' duration.
// Note: if timeout occurred, the task is not aborted. You have to abort it yourself if needed.
// - true, TaskResult, fail.Error: Task terminates, but TaskAction returned an error
// - true, TaskResult, *failErrAborted: Task terminates on Abort
// - false, nil, *fail.ErrTimeout: WaitFor has timed out; Task is aborted in this case (and eventual error after
//                                 abort signal has been received would be attached to the error as consequence)
func (instance *task) WaitFor(duration time.Duration) (_ bool, _ TaskResult, xerr fail.Error) {
	if instance.IsNull() {
		return false, nil, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	tid := instance.id
	status := instance.status
	instance.lock.RUnlock()

	switch status {
	case READY: // Waiting a ready task always succeed by design
		return false, nil, fail.InconsistentError("cannot wait a Task that has not be started")

	case DONE:
		instance.lock.RLock()
		defer instance.lock.RUnlock()
		return true, instance.result, instance.err

	case ABORTED:
		fallthrough
	case TIMEOUT:
		fallthrough
	case RUNNING:
		var (
			result TaskResult
			c chan struct{}
		)
		waiterTask, xerr := NewTaskWithParent(instance, InheritParentIDOption, AmendID("WaitForHelper"))
		if xerr != nil {
			return false, nil, fail.Wrap(xerr, "failed to create helper Task to WaitFor")
		}
		_, xerr = waiterTask.Start(
			func(t Task, _ TaskParameters) (_ TaskResult, innerXErr fail.Error) {
				t.DisarmAbortSignal()

				var done bool
				for ; !t.Aborted() && !done; {
					done, result, innerXErr = instance.TryWait()
					if !done {
						time.Sleep(1*time.Millisecond) // FIXME: hardcoded value :-(
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
				// We want now waiterTask to react to abort signal...
				waiterTask.(*task).lock.Lock()
				waiterTask.(*task).abortDisengaged = false
				waiterTask.(*task).lock.Unlock()

				// signal waiterTask to abort (and do not wait for it, it will terminate)
				xerr := waiterTask.Abort()
				tout := fail.TimeoutError(xerr, duration, fmt.Sprintf("timeout of %s waiting for Task '%s'", duration, tid))

				// Timeout has been reached, send abort signal to Task
				xerr = instance.Abort()
				if xerr != nil {
					_ = tout.AddConsequence(xerr)
				}
				// We do not wait on Task after the Abort, because if the TaskAction is badly coded and never
				// terminate, Wait would not terminate neither... So bad for leaked go routines but this function has to end...

				return false, nil, tout
			case <-c:
				return true, result, xerr
			}
		}

		select { // nolint
		case <-c:
			return true, result, xerr
		}

	case UNKNOWN:
		fallthrough
	default:
		return false, nil, fail.NewError("cannot wait Task '%s': unknown status (%d)", tid, status)
	}
}

// Abort aborts the task execution if running and marks it as ABORTED unless it's already DONE.
// A call of this method does not actually stop the running task if there is one; a subsequent
// call of Wait() may still be needed, it's still the responsibility of the executed code in task to stop
// early on Abort.
// returns an error if abort signal send fails
func (t *task) Abort() (err fail.Error) {
	if t.IsNull() {
		return fail.InvalidInstanceError()
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	if t.abortDisengaged {
		return fail.NotAvailableError("abort signal is disengaged on task %s", t.id)
	}

	switch t.status {
	case RUNNING:
		// Tell controller to stop goroutine
		t.abortCh <- true
		close(t.abortCh)
		t.status = ABORTED

	case ABORTED:
		fallthrough
	case TIMEOUT:
		fallthrough
	case DONE:
		fallthrough
	case READY:
		fallthrough
	case UNKNOWN:
		fallthrough
	default:
	}

	// VPL: why this?
	// if previousErr != nil && previousStatus != TIMEOUT && previousStatus != ABORTED {
	// 	return fail.AbortedError(previousErr)
	// }

	return nil
}

// Aborted tells if the task is aborted (by cancel(), by Abort() or by timeout)
// As a Task is actually a go routine, and there is no way to safely stop a go routine from outside, the code running in
// the Task has to check regularly if Task has been aborted and stop execution (return...) as soon as possible
// (leaving place for cleanup if needed). Without the use of Aborted(), a task may run indefinitely.
func (t *task) Aborted() bool {
	if t.IsNull() {
		return false
	}

	t.lock.RLock()
	defer t.lock.RUnlock()

	// If abort signal is disengaged, return false
	if t.abortDisengaged {
		return false
	}

	return t.status == ABORTED || t.status == TIMEOUT
}

// Abortable tells if task can be aborted
func (t *task) Abortable() (bool, fail.Error) {
	if t.IsNull() {
		return false, fail.InvalidInstanceError()
	}

	t.lock.RLock()
	defer t.lock.RUnlock()

	return !t.abortDisengaged, nil
}

// DisarmAbortSignal can be use to disable the effect of Abort()
// Typically, it is advised to call this inside a defer statement when cleanup things (cleanup has to terminate; if abort signal is not disarmed, any
// call with task as parameter may abort before the end.
// Returns a function to rearm the signal handling
// If on call the abort signal is already disarmed, does nothing and returned function does nothing also.
// If on call the abort signal is not disarmed, disarms it and returned function will rearm it.
// Note: the disarm state is not propagated to subtasks. It's possible to disarm abort signal in a task and want to Abort() explicitely a subtask.
func (t *task) DisarmAbortSignal() func() {
	if t.IsNull() {
		logrus.Errorf("task.DisarmAbortSignal() called from nil; ignored.")
		return func() {}
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	if !t.abortDisengaged {
		// Disengage Abort signal
		t.abortDisengaged = true

		// Return a func that reengage abort signal
		return func() {
			if t.IsNull() {
				return
			}

			t.lock.Lock()
			defer t.lock.Unlock()

			t.abortDisengaged = false
		}
	}

	// If abort signal is already disengaged, does nothing and returns a func that does nothing also
	return func() {}
}
