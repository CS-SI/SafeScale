/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// TaskStatus ...
type TaskStatus int

const (
	_ TaskStatus = iota
	// READY the task is ready to start
	READY
	// RUNNING the task is running
	RUNNING
	// DONE the task has run and is done
	DONE
	// ABORTED the task has been aborted
	ABORTED
	// TIMEOUT the task ran out of time
	TIMEOUT
)

// TaskParameters ...
type TaskParameters interface{}

// TaskResult ...
type TaskResult interface{}

// TaskAction defines the type of the function that can be started by a Task.
// NOTE: you have to check if task is aborted inside this function using method Aborted(),
//       to be able to stop the corresponding process when task is aborted (no matter what
//       the abort reason is), and permit to end properly. Otherwise this may lead to goroutine leak.
// Example:
// task.Start(func(t concurrency.Task, p TaskParameters) (concurrency.TaskResult, error) {
//    for {
//        if t.Aborted() {
//            break // or return
//        }
//        ...
//    }
//    return nil
//})
type TaskAction func(t Task, parameters TaskParameters) (TaskResult, error)

// TaskGuard ...
type TaskGuard interface {
	TryWait() (bool, TaskResult, error)
	Wait() (TaskResult, error)
	WaitFor(time.Duration) (bool, TaskResult, error)
}

// TaskCore is the interface of core methods to control task and taskgroup
type TaskCore interface {
	Abort() error
	Aborted() bool
	Abortable() bool
	IgnoreAbortSignal(bool) error
	SetID(string) error
	GetID() (string, error)
	GetSignature() (string, error)
	GetStatus() (TaskStatus, error)
	GetContext() (context.Context, context.CancelFunc, error)
	// Reset() error
	Run(TaskAction, TaskParameters) (TaskResult, error)
	RunInSubtask(TaskAction, TaskParameters) (TaskResult, error)
	Start(TaskAction, TaskParameters) (Task, error)
	StartWithTimeout(TaskAction, TaskParameters, time.Duration) (Task, error)
	StartInSubtask(TaskAction, TaskParameters) (Task, error)

	SafeGetID() string
	SafeGetSignature() string

	Close()
}

// Task is the interface of a task running in goroutine, allowing to identity (indirectly) goroutines
type Task interface {
	TaskCore
	TaskGuard
}

// task is the implementation of Task
type task struct {
	mu     sync.Mutex
	id     string
	sig    string
	status TaskStatus

	context context.Context    // \ context and cancel allows
	cancel  context.CancelFunc // / to cancel a running task

	finishCh chan struct{} // Used to signal the routine that Wait() the go routine is done
	doneCh   chan bool     // Used by routine to signal it has done its processing
	abortCh  chan bool
	closeCh  chan struct{} // Used to signal the routine capturing the cancel signal to stop capture

	err    error
	result TaskResult

	abortDisengaged bool
	subtasks        map[Task]struct{} // list of subtasks created from this task
}

var globalTask atomic.Value

// // TaskFromContext returns the task contained in the context
//func TaskFromContext(ctx context.Context) (Task, error) {
//	if ctx == nil {
//		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
//	}
//	task := ctx.Value(TaskValue{})
//	if task == nil {
//		return nil, scerr.NotFoundError("task")
//	}
//	return task.(Task), nil
//}

// RootTask is the "task to rule them all"
func RootTask() (Task, error) {
	anon := globalTask.Load()
	if anon == nil {
		newT, _ := newTask(nil, nil, nil) // nolint
		newT.id = "0"
		globalTask.Store(newT)
		anon = globalTask.Load()
	}
	return anon.(Task), nil
}

// NewTask creates a new instance of struct task
func NewTask() (Task, error) {
	return newTask(nil, nil, nil) // nolint
}

// NewUnbreakableTask is a new task that cannot be aborted by default (but this can be changed with IgnoreAbortSignal(false))
func NewUnbreakableTask() (Task, error) {
	nt, err := newTask(nil, nil, nil) // nolint
	if err != nil {
		return nil, err
	}
	// To be able to For safety, normally the cancel signal capture routine is not started in this case...
	nt.abortDisengaged = true
	return nt, nil
}

// NewTaskWithParent creates a subtask
// Such a task can be aborted if the parent one can be
func NewTaskWithParent(parentTask Task) (Task, error) {
	// Don't use context.TODO() we don't want to force context if there is no one
	return newTask(nil, nil, parentTask) // nolint
}

// NewTaskWithContext creates a task with a context and cancel function
func NewTaskWithContext(ctx context.Context, cancel context.CancelFunc) (Task, error) {
	return newTask(ctx, cancel, nil)
}

// newTask creates a new Task with optional parent task or with ctx/cancel pair
// 'cancel' contains the context.CancelFunc corresponding to 'ctx'. There is no sense to provide 'cancel' without 'ctx'
// There is also no sense to provide parent task with ctx/cancel
func newTask(ctx context.Context, cancel context.CancelFunc, parentTask Task) (*task, error) {
	if ctx == nil && cancel != nil {
		return nil, scerr.InvalidParameterError("cancel", "must be nil if ctx is nil")
	}
	if parentTask != nil {
		if ctx != nil {
			return nil, scerr.InvalidParameterError("ctx", "must be nil if parentTask is not nil")
		}
		if cancel != nil {
			return nil, scerr.InvalidParameterError("cancel", "must be nil if parentTask is not nil")
		}
	}

	var (
		taskContext  context.Context
		taskCancel   context.CancelFunc
		taskInstance *task
		needContext  bool
	)

	if parentTask != nil {
		taskInstance = parentTask.(*task)
	}
	if taskInstance == nil || (taskInstance.context == nil && taskInstance.cancel == nil) {
		needContext = (ctx == nil)
	} else if taskInstance.context == nil && taskInstance.cancel == nil {
		needContext = true
	}
	if needContext {
		taskContext, taskCancel = context.WithCancel(context.Background())
	} else {
		taskContext = ctx
		taskCancel = cancel
	}

	t := &task{
		context: taskContext,
		cancel:  taskCancel,
		status:  READY,
		// abortCh:  make(chan bool, 1),
		// doneCh:   make(chan bool, 1),
		// finishCh: make(chan struct{}, 1),
	}
	// close(t.abortCh)
	// close(t.doneCh)
	// close(t.finishCh)

	u, err := uuid.NewV4()
	if err != nil {
		return nil, scerr.Wrap(err, "failed to create a new task")
	}

	t.id = u.String()
	t.sig = fmt.Sprintf("{task %s}", t.id)

	// Starts a go routine if cancel is not nil to react to cancel signal
	if t.context != nil && t.cancel != nil {
		t.closeCh = make(chan struct{}, 1)
		go t.taskCancelReceiver()
	}

	return t, nil
}

// taskCancelReceiver captures cancel signal if it arrives and abort the task
func (t *task) taskCancelReceiver() {
	sig := t.SafeGetSignature()
	finish := false
	for !finish {
		select {
		case <-t.closeCh: // Close channel receives something, stop capturing
			finish = true
		case <-t.context.Done(): // Cancel signal received, abort task
			logrus.Debugf("%s: cancel received, aborting task", sig)
			_ = t.Abort()
			finish = true
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// GetID returns an unique id for the task
func (t *task) GetID() (string, error) {
	if t == nil {
		return "", scerr.InvalidInstanceError()
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	return t.id, nil
}

// SafeGetID ...
func (t *task) SafeGetID() string {
	sig, _ := t.GetID()
	return sig
}

// GetSignature builds the "signature" of the task passed as parameter,
// ie a string representation of the task ID in the format "{task <id>}".
func (t *task) GetSignature() (string, error) {
	if t == nil {
		return "", scerr.InvalidInstanceError()
	}

	return t.sig, nil
}

// SafeGetSignature ...
func (t *task) SafeGetSignature() string {
	sig, _ := t.GetSignature()
	return sig
}

// GetStatus returns the current task status
func (t *task) GetStatus() (TaskStatus, error) {
	if t == nil {
		return 0, scerr.InvalidInstanceError()
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status, nil
}

// GetContext returns the context associated to the task
func (t *task) GetContext() (context.Context, context.CancelFunc, error) {
	if t == nil {
		return nil, nil, scerr.InvalidInstanceError()
	}
	return t.context, t.cancel, nil
}

// SetID allows to specify task ID. The unicity of the ID through all the tasks
// becomes the responsibility of the developer...
func (t *task) SetID(id string) error {
	if t == nil {
		return scerr.InvalidInstanceError()
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "cannot be empty!")
	}
	if id == "0" {
		return scerr.InvalidParameterError("id", "cannot be '0', reserved for root task")
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	t.id = id
	t.sig = fmt.Sprintf("{task %s}", t.id)
	return nil
}

// Start runs in goroutine the function with parameters
func (t *task) Start(action TaskAction, params TaskParameters) (Task, error) {
	if t == nil {
		return nil, scerr.InvalidInstanceError()
	}
	return t.StartWithTimeout(action, params, 0)
}

// StartWithTimeout runs in goroutine the TasAction with TaskParameters, and stops after timeout (if > 0)
// If timeout happens, error returned will be ErrTimeout
// This function is useful when you know at the time you use it there will be a timeout to apply.
func (t *task) StartWithTimeout(action TaskAction, params TaskParameters, timeout time.Duration) (Task, error) {
	tid, err := t.GetID()
	if err != nil {
		return nil, err
	}

	status, err := t.GetStatus()
	if err != nil {
		return t, err
	}
	if status != READY {
		return t, scerr.InvalidRequestError("cannot start task '%s': not ready", tid)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if action == nil {
		t.status = DONE
	} else {
		t.status = RUNNING
		t.doneCh = make(chan bool, 1)
		t.abortCh = make(chan bool, 1)
		t.finishCh = make(chan struct{}, 1)
		go t.controller(action, params, timeout)
	}
	return t, nil
}

// StartInSubtask runs in a subtask goroutine the function with parameters
func (t *task) StartInSubtask(action TaskAction, params TaskParameters) (Task, error) {
	if t == nil {
		return nil, scerr.InvalidInstanceError()
	}

	st, err := NewTaskWithParent(t)
	if err != nil {
		return nil, err
	}

	return st.Start(action, params)
}

// controller controls the start, termination and possibly aboprtion of the action
func (t *task) controller(action TaskAction, params TaskParameters, timeout time.Duration) {
	go t.run(action, params)

	sig, _ := t.GetSignature() // If we arrive here, no need to check again for an error impossible to happen
	// tracer := NewTracer(true, t, "")
	finish := false

	if timeout > 0 {
		for !finish {
			select {
			// VPL: cancel signal is captured by its own go routine
			// case <-t.context.Done():
			// 	// Context cancel signal received, propagating using abort signal
			// 	// tracer.Trace("receiving signal from context, aborting task...")
			// 	logrus.Debugf("%s received cancel signal from context", sig)
			// 	t.abortCh <- true
			case <-t.doneCh:
				// When action is done, "rearms" the done channel to allow Wait()/TryWait() to read from it
				// tracer.Trace("receiving done signal from go routine")
				t.mu.Lock()
				t.status = DONE
				t.mu.Unlock()
				finish = true
			case <-t.abortCh:
				// Abort signal received
				// tracer.Trace("receiving abort signal")
				logrus.Debugf("%s received abort signal", sig)
				t.mu.Lock()
				if !t.abortDisengaged && t.status != TIMEOUT {
					t.status = ABORTED
					t.err = scerr.AbortedError("aborted", nil)
				} else {
					logrus.Debugf("%s abort signal is disengaged, ignored", sig)
				}
				t.mu.Unlock()
				// VPL: don't force stop on abort to let the task the chance to clean up and end properly
				// finish = true
			case <-time.After(timeout):
				t.mu.Lock()
				if t.status == RUNNING {
					t.abortCh <- true
					close(t.abortCh)
					t.err = scerr.TimeoutError("task is out of time", timeout, nil)
				}
				t.mu.Unlock()
				finish = true
			}
		}
	} else {
		for !finish {
			select {
			// case <-t.ctx.Done():
			// 	// Context cancel signal received, propagating using abort signal
			// 	// tracer.Trace("receiving signal from context, aborting task...")
			// 	logrus.Debugf("%s received cancel signal from context", sig)
			// 	t.abortCh <- true
			case <-t.doneCh:
				// When action is done, "rearms" the done channel to allow Wait()/TryWait() to read from it
				// tracer.Trace("receiving done signal from go routine")
				t.mu.Lock()
				t.status = DONE
				t.mu.Unlock()
				finish = true
			case <-t.abortCh:
				// Abort signal received
				logrus.Debugf("%s received abort signal", sig)
				// tracer.Trace("receiving abort signal")
				t.mu.Lock()
				if !t.abortDisengaged && t.status != TIMEOUT {
					t.status = ABORTED
					t.err = scerr.AbortedError("aborted", nil)
				} else {
					logrus.Debugf("%s abort signal is disengaged, ignored", sig)
				}
				t.mu.Unlock()
				// VPL: don't force stop on abort to let the goroutine the chance to clean up and end properly
				// finish = true
			}
		}
	}

	logrus.Debugf("%s controller ended properly", sig)
	t.finishCh <- struct{}{}
	close(t.finishCh)
}

// run executes the function 'action'
func (t *task) run(action TaskAction, params TaskParameters) {
	var err error
	defer func() {
		if err := recover(); err != nil {
			t.mu.Lock()
			defer t.mu.Unlock()

			t.err = scerr.RuntimePanicError("panic happened: %v", err)
			t.result = nil
			t.doneCh <- false
			close(t.doneCh)
		}
	}()

	result, err := action(t, params)

	t.mu.Lock()
	defer t.mu.Unlock()

	t.err = err
	t.result = result
	t.doneCh <- true
	close(t.doneCh)
}

// Run starts task, waits its completion then return the error code
func (t *task) Run(action TaskAction, params TaskParameters) (TaskResult, error) {
	if t == nil {
		return nil, scerr.InvalidInstanceError()
	}

	_, err := t.Start(action, params)
	if err != nil {
		return nil, err
	}

	return t.Wait()
}

// RunInSubtask starts a subtask, waits its completion then return the error code
func (t *task) RunInSubtask(action TaskAction, params TaskParameters) (TaskResult, error) {
	if t == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if action == nil {
		return nil, scerr.InvalidParameterError("action", "cannot be nil")
	}

	st, err := NewTaskWithParent(t)
	if err != nil {
		return nil, err
	}
	return st.Run(action, params)
}

// Wait waits for the task to end, and returns the error (or nil) of the execution
func (t *task) Wait() (TaskResult, error) {
	if t == nil {
		return nil, scerr.InvalidInstanceError()
	}

	tid, err := t.GetID()
	if err != nil {
		return nil, err
	}

	status, err := t.GetStatus()
	if err != nil {
		return nil, err
	}

	if status == DONE {
		return t.result, t.err
	}
	if status == ABORTED {
		return nil, t.err
	}
	if status != RUNNING {
		return nil, scerr.InconsistentError("cannot wait task '%s': not running (%d)", tid, status)
	}

	<-t.finishCh

	t.mu.Lock()
	defer t.mu.Unlock()

	close(t.finishCh)
	close(t.abortCh)
	close(t.doneCh)
	return t.result, t.err
}

// TryWait tries to wait on a task
// If task done, returns (true, TaskResult, <error from the task>)
// If task aborted, returns (true, utils.ErrAborted)
// If task still running, returns (false, nil)
func (t *task) TryWait() (bool, TaskResult, error) {
	if t == nil {
		return false, nil, scerr.InvalidInstanceError()
	}

	tid, err := t.GetID()
	if err != nil {
		return false, nil, err
	}

	status, err := t.GetStatus()
	if err != nil {
		return false, nil, err
	}

	if status == DONE {
		return true, t.result, t.err
	}
	if status == ABORTED {
		return true, nil, t.err
	}
	if status != RUNNING {
		return false, nil, scerr.InconsistentError("cannot wait task '%s': not running", tid)
	}
	if len(t.finishCh) == 1 {
		_, err := t.Wait()
		return false, t.result, err
	}
	return false, nil, nil
}

// WaitFor waits for the task to end, for 'duration' duration.
// Note: if timeout occured, the task is not aborted. You have to abort it yourself if needed.
// If task done, returns (true, <error from the task>)
// If task aborted, returns (true, scerr.ErrAborted)
// If duration elapsed (meaning the task is still running after duration), returns (false, scerr.ErrTimeout)
func (t *task) WaitFor(duration time.Duration) (bool, TaskResult, error) {
	if t == nil {
		return false, nil, scerr.InvalidInstanceError()
	}

	tid, err := t.GetID()
	if err != nil {
		return false, nil, err
	}

	status, err := t.GetStatus()
	if err != nil {
		return false, nil, err
	}

	if status == DONE {
		return true, t.result, t.err
	}
	if status == ABORTED {
		return true, nil, t.err
	}
	if status != RUNNING {
		return false, nil, scerr.InconsistentError("cannot wait task '%s': not running", tid)
	}

	for {
		select {
		case <-time.After(duration):
			return false, nil, scerr.TimeoutError(fmt.Sprintf("timeout waiting for task '%s'", tid), duration, nil)
		default:
			ok, result, err := t.TryWait()
			if ok {
				return ok, result, err
			}
			// Waits 1 ms between checks...
			time.Sleep(time.Millisecond)
		}
	}
}

// Deprecated: Reset resets the task for reuse. Deprecated due to data race problems.
func (t *task) Reset() error {
	if t == nil {
		return scerr.InvalidInstanceError()
	}

	tid, err := t.GetID()
	if err != nil {
		return err
	}

	status, err := t.GetStatus()
	if err != nil {
		return err
	}

	if status == RUNNING {
		return scerr.InconsistentError("cannot reset task '%s': task running", tid)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.status = READY
	t.err = nil
	t.result = nil
	return nil
}

// Abort aborts the task execution if running and marks it as ABORTED unless it's already DONE
// A call of this method doesn't actually stop the running task if there is one; a subsequent
// call of Wait() is still needed
func (t *task) Abort() (err error) {
	if t == nil {
		return scerr.InvalidInstanceError()
	}

	status, err := t.GetStatus()
	if err != nil {
		return err
	}
	id, err := t.GetID()
	if err != nil {
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.abortDisengaged {
		return scerr.NotAvailableError("abort signal is disengaged on task %s", id)
	}

	if status == RUNNING {
		// Tell controller to abort go routine
		t.abortCh <- true

		// VPL: sending a signal to abortCh should be sufficient
		// // Tell context to cancel
		// if t.cancel != nil {
		// 	logrus.Debugf("%s: cancelling from Abort()...", sig)
		// 	t.cancel()
		// 	t.cancel = nil
		// }

		t.status = ABORTED
	} else if t.status != DONE {
		t.status = ABORTED
	}
	return nil
}

// Aborted tells if task has been aborted
func (t *task) Aborted() bool {
	status, err := t.GetStatus()
	if err != nil {
		return false
	}
	return status == ABORTED
}

// Abortable tells if task can be aborted
func (t *task) Abortable() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.abortDisengaged
}

// IgnoreAbortSignal can be use to disable the effet of Abort()
func (t *task) IgnoreAbortSignal(ignore bool) error {
	if t == nil {
		return scerr.InvalidInstanceError()
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	t.abortDisengaged = ignore
	return nil
}

// Close cleans up the context
// Must be called to prevent memory leaks
func (t *task) Close() {
	_ = t.Abort()
	for k := range t.subtasks {
		_ = k.Abort()
		_, _ = k.Wait()
	}
	_, _ = t.Wait()
	if t.context != nil && t.cancel != nil {
		t.closeCh <- struct{}{}
		close(t.closeCh)
	}
}
