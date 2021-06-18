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
	AppendToID(string) fail.Error    // appends string to the current Task ID
	DisarmAbortSignal() func()
	GetID() (string, fail.Error)
	GetSignature() string
	GetStatus() (TaskStatus, fail.Error)
	GetContext() context.Context
	GetLastError() (error, fail.Error)
	GetResult() (TaskResult, fail.Error)
	SetID(string) fail.Error

	Run(TaskAction, TaskParameters) (TaskResult, fail.Error)
	RunInSubtask(TaskAction, TaskParameters) (TaskResult, fail.Error)
	Start(TaskAction, TaskParameters, ...data.ImmutableKeyValue) (Task, fail.Error)
	StartWithTimeout(TaskAction, TaskParameters, time.Duration, ...data.ImmutableKeyValue) (Task, fail.Error)
	StartInSubtask(TaskAction, TaskParameters, ...data.ImmutableKeyValue) (Task, fail.Error)
}

// Task is the interface of a task running in goroutine, allowing to identity (indirectly) goroutines
type Task interface {
	TaskCore
	TaskGuard
}

// task is a structure allowing to identify (indirectly) goroutines
type task struct {
	mu sync.Mutex
	id string

	ctx    context.Context
	cancel context.CancelFunc
	status TaskStatus

	finishCh chan struct{} // Used to signal the routine that Wait() the go routine is done
	doneCh   chan bool     // Used by routine to signal it has done its processing
	abortCh  chan bool     // Used to signal the routine it has to stop processing

	err    fail.Error
	result TaskResult

	abortDisengaged bool
}

var globalTask atomic.Value

var (
	InheritParentIDOption = data.NewImmutableKeyValue("inheritID", true)
)

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

const KeyForTaskInContext taskContextKey = "task"

// TaskFromContext extracts the task instance from context
func TaskFromContext(ctx context.Context) (Task, fail.Error) {
	if ctx != nil {
		if ctxValue := ctx.Value(KeyForTaskInContext); ctxValue != nil {
			if task, ok := ctxValue.(*task); ok {
				return task, nil
			}
			return nil, fail.InconsistentError("context value for 'task' is not a 'concurrency.Task'")
		}
	}

	return VoidTask()
}

// NewTask ...
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
func NewTaskWithParent(parentTask Task) (Task, fail.Error) {
	if parentTask == nil {
		return nil, fail.InvalidParameterError("parentTask", "must not be nil")
	}

	return newTask(context.Background(), parentTask)
}

// NewTaskWithContext ...
func NewTaskWithContext(ctx context.Context /*, parentTask Task*/) (Task, fail.Error) {
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	return newTask(ctx, nil /*parentTask*/)
}

// newTask creates a new Task from parentTask or using ctx as parent context
func newTask(ctx context.Context, parentTask Task) (nt *task, xerr fail.Error) {
	defer fail.OnPanic(&xerr)
	var (
		childContext context.Context
		cancel       context.CancelFunc
	)

	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil!, use context.TODO() instead!")
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
	t := task{
		// ctx:      childContext,
		cancel:   cancel,
		status:   READY,
		abortCh:  make(chan bool, 1),
		doneCh:   make(chan bool, 1),
		finishCh: make(chan struct{}, 1),
		//		subtasks: make(map[string]Task),
	}

	u, err := uuid.NewV4()
	if err != nil {
		return nil, fail.Wrap(err, "failed to create a new task")
	}

	t.id = u.String()
	t.ctx = context.WithValue(childContext, KeyForTaskInContext, &t)

	return &t, nil
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

	t.mu.Lock()
	defer t.mu.Unlock()

	return t.err, nil
}

// GetResult returns the result of the ended task
func (t *task) GetResult() (TaskResult, fail.Error) {
	if t.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	t.mu.Lock()
	defer t.mu.Unlock()

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

	t.mu.Lock()
	defer t.mu.Unlock()

	return t.id, nil
}

// GetSignature builds the "signature" of the task passed as parameter,
// ie a string representation of the task ID in the format "{task <id>}".
func (t *task) GetSignature() string {
	if t.IsNull() {
		return ""
	}

	t.mu.Lock()
	defer t.mu.Unlock()

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

	t.mu.Lock()
	defer t.mu.Unlock()

	return t.status, nil
}

// GetContext returns the context associated to the task
func (t *task) GetContext() context.Context {
	if t.IsNull() {
		return context.TODO()
	}

	t.mu.Lock()
	defer t.mu.Unlock()

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

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == ABORTED {
		return fail.AbortedError(nil, "aborted")
	}

	t.id = id
	return nil
}

// AppendToID appends string to current ID
func (t *task) AppendToID(id string) fail.Error {
	if t.IsNull() {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == ABORTED {
		return fail.AbortedError(nil, "aborted")
	}

	t.id += "+"+id
	return nil
}

// Start runs in goroutine the function with parameters
func (t *task) Start(action TaskAction, params TaskParameters, options ...data.ImmutableKeyValue) (Task, fail.Error) {
	if t.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	return t.StartWithTimeout(action, params, 0)
}

// StartWithTimeout runs in goroutine the TaskAction with TaskParameters, and stops after timeout (if > 0)
// If timeout happens, error returned will be '*fail.ErrTimeout'
func (t *task) StartWithTimeout(action TaskAction, params TaskParameters, timeout time.Duration, options ...data.ImmutableKeyValue) (Task, fail.Error) {
	if t.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	tid, err := t.GetID()
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status != READY {
		return nil, fail.NewError("cannot start task '%s': not ready", tid)
	}

	if action == nil {
		t.status = DONE
	} else {
		t.status = RUNNING
		t.doneCh = make(chan bool, 1)
		t.abortCh = make(chan bool, 1)
		t.finishCh = make(chan struct{}, 1)
		go func() {
			_ = t.controller(action, params, timeout)
		}()
	}
	return t, nil
}

// StartInSubtask runs in a subtask goroutine the function with parameters
func (t *task) StartInSubtask(action TaskAction, params TaskParameters, options ...data.ImmutableKeyValue) (Task, fail.Error) {
	if t.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	st, xerr := NewTaskWithParent(t)
	if xerr != nil {
		return nil, xerr
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	return st.Start(action, params)
}

// controller controls the start, termination and possibly abortion of the action
func (t *task) controller(action TaskAction, params TaskParameters, timeout time.Duration) fail.Error {
	if t.IsNull() {
		return fail.InvalidInstanceError()
	}

	traceR := newTracer(t, tracing.ShouldTrace("concurrency.t"))

	go t.run(action, params)

	finish := false
	defer close(t.finishCh)

	if t.cancel != nil {
		defer t.cancel()
	}

	if timeout > 0 {
		for !finish {
			select {
			case <-t.ctx.Done():
				// Context cancel signal received, propagating using abort signal
				traceR.trace("receiving signal from context, aborting task...")
				t.mu.Lock()
				t.status = ABORTED
				switch t.err.(type) {
				case *fail.ErrAborted:
					// continue
				default:
					t.err = fail.AbortedError(t.err)
				}
				t.finishCh <- struct{}{}
				finish = true
				t.mu.Unlock() // Avoid defer in loop
			case <-t.doneCh:
				traceR.trace("receiving done signal from go routine")
				t.mu.Lock()
				t.status = DONE
				finish = true
				t.mu.Unlock() // Avoid defer in loop
			case <-t.abortCh:
				// Abort signal received
				traceR.trace("receiving abort signal")
				t.mu.Lock()
				if !t.abortDisengaged {
					if t.status != TIMEOUT {
						t.status = ABORTED
					}
					switch t.err.(type) {
					case *fail.ErrAborted:
						// do nothing
					default:
						t.err = fail.AbortedError(t.err)
					}
					t.finishCh <- struct{}{}
					finish = true
				} else {
					traceR.trace("abort signal is disengaged, ignored")
				}
				t.mu.Unlock() // Avoid defer in loop
			case <-time.After(timeout):
				t.mu.Lock()
				t.status = TIMEOUT
				t.err = fail.TimeoutError(t.err, timeout)
				t.finishCh <- struct{}{}
				finish = true
				t.mu.Unlock() // Avoid defer in loop
			}
		}
	} else {
		for !finish {
			select {
			case <-t.ctx.Done():
				// Context cancel signal received, propagating using abort signal
				traceR.trace("receiving signal from context, aborting task...")
				t.mu.Lock()
				t.status = ABORTED
				switch t.err.(type) {
				case *fail.ErrAborted:
					// continue
				default:
					t.err = fail.AbortedError(t.err)
				}
				t.finishCh <- struct{}{}
				finish = true
				t.mu.Unlock() // Avoid defer in loop
			case <-t.doneCh:
				traceR.trace("receiving done signal from go routine")
				t.mu.Lock()
				if t.status == RUNNING {
					t.status = DONE
					t.finishCh <- struct{}{}
				}
				finish = true
				t.mu.Unlock() // Avoid defer in loop
			case <-t.abortCh:
				// Abort signal received
				traceR.trace("receiving abort signal")
				t.mu.Lock()
				if !t.abortDisengaged {
					if t.status != TIMEOUT {
						t.status = ABORTED
					}
					switch t.err.(type) {
					case *fail.ErrAborted:
						// continue
					default:
						t.err = fail.AbortedError(t.err)
					}
					t.finishCh <- struct{}{}
					finish = true
				} else {
					traceR.trace("abort signal is disengaged, ignored")
				}
				t.mu.Unlock() // Avoid defer in loop
			}
		}
	}

	return nil
}

// run executes the function 'action'
func (t *task) run(action TaskAction, params TaskParameters) {
	defer func() {
		if err := recover(); err != nil {
			t.mu.Lock()
			defer t.mu.Unlock()

			t.err = fail.RuntimePanicError("panic happened: %v", err)
			t.result = nil
			t.doneCh <- false
			defer close(t.doneCh)
		}
	}()

	result, err := action(t, params)

	t.mu.Lock()
	defer t.mu.Unlock()

	t.err = err
	t.result = result
	t.doneCh <- true
	defer close(t.doneCh)
}

// Run starts task, waits its completion then return the error code
func (t *task) Run(action TaskAction, params TaskParameters) (TaskResult, fail.Error) {
	if t.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	stask, err := t.Start(action, params)
	if err != nil {
		return nil, err
	}

	return stask.Wait()
}

// RunInSubtask starts a subtask, waits its completion then return the error code
func (t *task) RunInSubtask(action TaskAction, params TaskParameters) (TaskResult, fail.Error) {
	if t.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if action == nil {
		return nil, fail.InvalidParameterCannotBeNilError("action")
	}

	st, xerr := NewTaskWithParent(t)
	if xerr != nil {
		return nil, xerr
	}

	return st.Run(action, params)
}

// Wait waits for the task to end, and returns the error (or nil) of the execution
func (t *task) Wait() (TaskResult, fail.Error) {
	if t.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	tid, err := t.GetID()
	if err != nil {
		return nil, err
	}

	status, err := t.GetStatus()
	if err != nil {
		return nil, err
	}

	switch status {
	case READY: // Waiting a ready task always succeed by design
		return nil, fail.InconsistentError("cannot wait a Task that has not be started")
	case DONE:
		return t.result, t.err
	case TIMEOUT:
		return nil, t.err
	case RUNNING, ABORTED:
		// status == ABORTED does not prevent to wait the end of the task
		<-t.finishCh

		t.mu.Lock()
		defer t.mu.Unlock()

		if t.status == ABORTED || t.status == TIMEOUT {
			return nil, t.err
		}

		return t.result, t.err
	default:
		return nil, fail.InconsistentError("cannot wait task '%s': unknown status (%d)", tid, status)
	}
}

// TryWait tries to wait on a task
// If task done, returns (true, TaskResult, <error from the task>)
// If task aborted, returns (false, utils.ErrAborted) (subsequent calls of TryWait may be necessary)
// If task still running, returns (false, nil)
func (t *task) TryWait() (bool, TaskResult, fail.Error) {
	if t.IsNull() {
		return false, nil, fail.InvalidInstanceError()
	}

	tid, err := t.GetID()
	if err != nil {
		return false, nil, err
	}

	status, err := t.GetStatus()
	if err != nil {
		return false, nil, err
	}

	switch status {
	case READY: // Waiting a ready task always succeed by design
		return false, nil, fail.InconsistentError("cannot wait a Task that has not be started")
	case DONE:
		t.mu.Lock()
		defer t.mu.Unlock()
		return true, t.result, t.err
	case ABORTED:
		t.mu.Lock()
		defer t.mu.Unlock()
		return true, nil, t.err
	case RUNNING:
		if len(t.finishCh) == 1 {
			_, err := t.Wait()
			//	t.mu.Lock()
			//	defer t.mu.Unlock()
			return true, t.result, err
		}
		return false, nil, nil
	default:
		return false, nil, fail.NewError("cannot wait task '%s': unkown status (%d)", tid, status)
	}
}

// WaitFor waits for the task to end, for 'duration' duration.
// Note: if timeout occurred, the task is not aborted. You have to abort it yourself if needed.
// If task done, returns (true, <error from the task>)
// If task aborted, returns (true, utils.ErrAborted)
// If duration elapsed (meaning the task is still running after duration), returns (false, utils.ErrTimeout)
func (t *task) WaitFor(duration time.Duration) (bool, TaskResult, fail.Error) {
	if t.IsNull() {
		return false, nil, fail.InvalidInstanceError()
	}

	tid, err := t.GetID()
	if err != nil {
		return false, nil, err
	}

	status, err := t.GetStatus()
	if err != nil {
		return false, nil, err
	}

	switch status {
	case READY: // Waiting a ready task always succeed by design
		return false, nil, fail.InconsistentError("cannot wait a Task that has not be started")
	case DONE:
		return true, t.result, t.err
	case ABORTED:
		return true, nil, t.err
	case RUNNING:
		// continue
	default:
		return false, nil, fail.NewError("cannot wait task '%s': unknown status (%d)", tid, status)
	}

	var result TaskResult
	c := make(chan struct{})
	go func() {
		result, err = t.Wait()
		c <- struct{}{} // done
		close(c)
	}()

	if duration > 0 {
		select {
		case <-time.After(duration):
			toErr := fail.TimeoutError(fmt.Errorf("timeout of %s waiting for task '%s'", duration, tid), duration, nil)
			abErr := t.Abort()
			if abErr != nil {
				_ = toErr.AddConsequence(abErr)
			}
			return false, nil, toErr
		case <-c:
			return true, result, err
		}
	}

	select { // nolint
	case <-c:
		return true, result, err
	}
}

// Abort aborts the task execution if running and marks it as ABORTED unless it's already DONE
// A call of this method does not actually stop the running task if there is one; a subsequent
// call of Wait() may still be needed, it's still the responsibility of the executed code in task to stop
// early on Abort.
// returns an error if abort signal send fails
func (t *task) Abort() (err fail.Error) {
	if t.IsNull() {
		return fail.InvalidInstanceError()
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.abortDisengaged {
		return fail.NotAvailableError("abort signal is disengaged on task %s", t.id)
	}

	// previousErr := t.err
	// previousStatus := t.status

	switch t.status {
	case RUNNING:
		// Tell controller to stop go routine
		t.abortCh <- true
		close(t.abortCh)

		// Tell context to cancel
		defer t.cancel()

		t.status = ABORTED
		t.err = fail.AbortedError(t.err)
		// } else if t.status == DONE {
		// 	t.status = ABORTED
		// 	t.err = fail.AbortedError(t.err)
	case ABORTED, TIMEOUT, DONE:
		// already stopped, do nothing more
	default:
		t.status = ABORTED
		t.err = fail.AbortedError(t.err)
	}

	logrus.Debugf("task %s aborted", t.getSignature())

	// VPL: why this?
	// if previousErr != nil && previousStatus != TIMEOUT && previousStatus != ABORTED {
	// 	return fail.AbortedError(previousErr)
	// }

	return nil
}

// Aborted tells if the task is aborted
func (t *task) Aborted() bool {
	if t.IsNull() {
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// If abort signal is disengaged, return false
	if t.abortDisengaged {
		return false
	}

	return t.status == ABORTED
}

// Abortable tells if task can be aborted
func (t *task) Abortable() (bool, fail.Error) {
	if t.IsNull() {
		return false, fail.InvalidInstanceError()
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	return !t.abortDisengaged, nil
}

// DisarmAbortSignal can be use to disable the effect of Abort()
// Typically, it is advised to call this inside a defer statement when cleanup things (cleanup has to terminate; if abort signal is not disarmed, any
// call with task as parameter may abort before the end.
// Returns a function to rearm the signal handling
// If on call the abort signal is already disarmed, does nothing and returned function does nothing also.
// If on call the abort signal is not disarmed, disarms it and returned function will rearm it.

func (t *task) DisarmAbortSignal() func() {
	if t.IsNull() {
		logrus.Errorf("task.DisarmAbortSignal() called from nil; ignored.")
		return func() {}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.abortDisengaged {
		// Disengage Abort signal
		t.abortDisengaged = true

		// Return a func that reengage abort signal
		return func() {
			if t.IsNull() {
				return
			}

			t.mu.Lock()
			defer t.mu.Unlock()

			t.abortDisengaged = false
		}
	}

	// If abort signal is already disengaged, does nothing and returns a func that does nothing also
	return func() {}
}
