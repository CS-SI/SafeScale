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

	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

const (
	UNKNOWN TaskStatus = iota // status is unknown
	READY                     // the task is ready to start
	RUNNING                   // the task is running
	DONE                      // the task has run and is done
	ABORTED                   // the task has been aborted
	TIMEOUT                   // the task ran out of time
)

// TaskStatus ...
type TaskStatus int

// TaskParameters ...
type TaskParameters interface{}

// TaskResult ...
type TaskResult interface{}

// TaskAction defines the type of the function that can be started by a Task.
// NOTE: you have to check if task is aborted inside this function using method t.Aborted(),
//       to be able to stop the process when task is aborted (no matter what
//       the abort reason is), and permit to end properly. Otherwise this may lead to goroutine leak
//       (there is no good way to stop forcibly a goroutine).
// Example:
// task.Start(func(t concurrency.Task, p TaskParameters) (concurrency.TaskResult, error) {
// ...
//    for {
//        if t.Aborted() {
//            break // or return
//        }
//        ...
//    }
//    return nil
// }, nil)
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
	Abortable() (bool, error)
	IgnoreAbortSignal(bool) error
	SetID(string) error
	GetID() (string, error)
	GetSignature() (string, error)
	GetStatus() (TaskStatus, error)
	GetContext() (context.Context, error)

	Run(TaskAction, TaskParameters) (TaskResult, error)
	RunInSubtask(TaskAction, TaskParameters) (TaskResult, error)
	Start(TaskAction, TaskParameters) (Task, error)
	StartWithTimeout(TaskAction, TaskParameters, time.Duration) (Task, error)
	StartInSubtask(TaskAction, TaskParameters) (Task, error)
}

// Task is the interface of a task running in goroutine, allowing to identity (indirectly) goroutines
type Task interface {
	TaskCore
	TaskGuard
}

// task is a structure allowing to identify (indirectly) goroutines
type task struct {
	lock sync.Mutex
	id   string

	ctx    context.Context
	cancel context.CancelFunc
	status TaskStatus

	finishCh chan struct{} // Used to signal the routine that Wait() the go routine is done
	doneCh   chan bool     // Used by routine to signal it has done its processing
	abortCh  chan bool     // Used to signal the routine it has to stop processing
	closeCh  chan struct{} // Used to signal the routine capturing the cancel signal to stop capture

	err    error
	result TaskResult

	abortDisengaged bool
	subtasks        map[string]Task // list of subtasks created from this task
}

var globalTask atomic.Value

// RootTask is the "task to rule them all"
func RootTask() (Task, error) {
	anon := globalTask.Load()
	if anon == nil {
		newT, err := newTask(nil, nil) // nolint
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
func VoidTask() (Task, error) {
	return NewTask(nil)
}

// NewTask ...
func NewTask(parentTask Task) (Task, error) {
	return newTask(context.TODO(), parentTask)
}

// NewUnbreakableTask is a new task that cannot be aborted by default (but this can be changed with IgnoreAbortSignal(false))
func NewUnbreakableTask() (Task, error) {
	nt, err := newTask(context.TODO(), nil) // nolint
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
	return newTask(context.TODO(), parentTask)
}

// NewTaskWithContext ...
func NewTaskWithContext(ctx context.Context, parentTask Task) (Task, error) {
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	return newTask(ctx, parentTask)
}

// newTask creates a new Task from parentTask or using ctx as parent context
func newTask(ctx context.Context, parentTask Task) (*task, error) {
	var (
		childContext context.Context
		cancel       context.CancelFunc
	)

	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil!, use context.TODO() instead!")
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
		ctx:      childContext,
		cancel:   cancel,
		status:   READY,
		abortCh:  make(chan bool, 1),
		doneCh:   make(chan bool, 1),
		finishCh: make(chan struct{}, 1),
		subtasks: make(map[string]Task),
	}

	u, err := uuid.NewV4()
	if err != nil {
		return nil, scerr.Wrap(err, "failed to create a new task")
	}

	t.id = u.String()

	return &t, nil
}

// GetID returns an unique id for the task
func (t *task) GetID() (string, error) {
	if t == nil {
		return "", scerr.InvalidInstanceError()
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	return t.id, nil
}

// GetSignature builds the "signature" of the task passed as parameter,
// ie a string representation of the task ID in the format "{task <id>}".
func (t *task) GetSignature() (string, error) {
	if t == nil {
		return "", scerr.InvalidInstanceError()
	}

	theId, _ := t.GetID()

	return fmt.Sprintf("{task %s}", theId), nil
}

// GetStatus returns the current task status
func (t *task) GetStatus() (TaskStatus, error) {
	if t == nil {
		return 0, scerr.InvalidInstanceError()
	}

	t.lock.Lock()
	defer t.lock.Unlock()
	return t.status, nil
}

// GetContext returns the context associated to the task
func (t *task) GetContext() (context.Context, error) {
	if t == nil {
		return nil, scerr.InvalidInstanceError()
	}

	t.lock.Lock()
	defer t.lock.Unlock()
	return t.ctx, nil
}

// SetID allows to specify task ID. The uniqueness of the ID through all the tasks
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
	t.lock.Lock()
	defer t.lock.Unlock()

	t.id = id
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
	if t == nil {
		return nil, scerr.InvalidInstanceError()
	}

	tid, err := t.GetID()
	if err != nil {
		return nil, err
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	if t.status != READY {
		return nil, scerr.NewError("can't start task '%s': not ready", tid)
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
func (t *task) StartInSubtask(action TaskAction, params TaskParameters) (Task, error) {
	if t == nil {
		return nil, scerr.InvalidInstanceError()
	}

	st, err := NewTaskWithParent(t)
	if err != nil {
		return nil, err
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	subtaskId, _ := st.GetID()
	t.subtasks[subtaskId] = st

	return st.Start(action, params)
}

// controller controls the start, termination and possibly abortion of the action
func (t *task) controller(action TaskAction, params TaskParameters, timeout time.Duration) error {
	if t == nil {
		return scerr.InvalidInstanceError()
	}

	go t.run(action, params)

	tracer := NewTracer(t, debug.ShouldTrace("concurrency.task"), "")
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
				// tracer.Trace("receiving signal from context, aborting task...")
				t.lock.Lock()
				defer t.lock.Unlock()
				t.status = ABORTED
				t.err = scerr.AbortedError("cancel signal received", nil)
				finish = true
				t.finishCh <- struct{}{}
			case <-t.doneCh:
				tracer.Trace("receiving done signal from go routine")
				t.mu.Lock()
				if t.status == RUNNING {
					t.status = DONE
					t.finishCh <- struct{}{}
					close(t.finishCh)
				}
				t.mu.Unlock()
				finish = true
				t.finishCh <- struct{}{}
				break
			case <-t.abortCh:
				// Abort signal received
				tracer.Trace("receiving abort signal")
				t.mu.Lock()
				if !t.abortDisengaged {
					if t.status != TIMEOUT {
						t.status = ABORTED
					}
					t.err = scerr.AbortedError("", nil)
					finish = true
					t.finishCh <- struct{}{}
				} else {
					tracer.Trace("abort signal is disengaged, ignored")
				}
			case <-time.After(timeout):
				t.lock.Lock()
				defer t.lock.Unlock()
				t.status = TIMEOUT
				t.err = scerr.TimeoutError(nil, timeout, "task is out of time")
				finish = true
				t.finishCh <- struct{}{}
			}
		}
	} else {
		for !finish {
			select {
			case <-t.ctx.Done():
				// Context cancel signal received, propagating using abort signal
				// tracer.Trace("receiving signal from context, aborting task...")
				t.lock.Lock()
				defer t.lock.Unlock()
				t.status = ABORTED
				t.err = scerr.AbortedError("cancel signal received", nil)
				finish = true
				t.finishCh <- struct{}{}
			case <-t.doneCh:
				tracer.Trace("receiving done signal from go routine")
				t.mu.Lock()
				if t.status == RUNNING {
					t.status = DONE
					t.finishCh <- struct{}{}
					close(t.finishCh)
				}
				t.mu.Unlock()
				finish = true
				t.finishCh <- struct{}{}
				break
			case <-t.abortCh:
				// Abort signal received
				tracer.Trace("receiving abort signal")
				t.mu.Lock()
				if !t.abortDisengaged {
					if t.status != TIMEOUT {
						t.status = ABORTED
					}
					t.err = scerr.AbortedError("", nil)
					finish = true
					t.finishCh <- struct{}{}
				} else {
					tracer.Trace("abort signal is disengaged, ignored")
				}
			}
		}
	}

	// logrus.Debugf("%s controller ended properly", sig)
}

// run executes the function 'action'
func (t *task) run(action TaskAction, params TaskParameters) {
	var err error
	defer func() {
		if err := recover(); err != nil {
			t.lock.Lock()
			defer t.lock.Unlock()

			t.err = scerr.RuntimePanicError(fmt.Sprintf("panic happened: %v", err))
			t.result = nil
			t.doneCh <- false
			defer close(t.doneCh)
		}
	}()

	result, err := action(t, params)

	t.lock.Lock()
	defer t.lock.Unlock()

	t.err = err
	t.result = result
	t.doneCh <- true
	defer close(t.doneCh)
}

// Run starts task, waits its completion then return the error code
func (t *task) Run(action TaskAction, params TaskParameters) (TaskResult, error) {
	if t == nil {
		return nil, scerr.InvalidInstanceError()
	}

	stask, err := t.Start(action, params)
	if err != nil {
		return nil, err
	}

	return stask.Wait()
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
	if status == ABORTED || status == TIMEOUT {
		return nil, t.err
	}
	if status != RUNNING {
		return nil, scerr.InconsistentError(fmt.Sprintf("cannot wait task '%s': not running (%d)", tid, status))
	}

	<-t.finishCh

	t.lock.Lock()
	defer t.lock.Unlock()

	if t.status == ABORTED || t.status == TIMEOUT {
		return nil, t.err
	}
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
		return false, nil, scerr.NewError("cannot wait task '%s': not running", tid)
	}
	if len(t.finishCh) == 1 {
		_, err := t.Wait()
		return true, t.result, err
	}
	return false, nil, nil
}

// WaitFor waits for the task to end, for 'duration' duration.
// Note: if timeout occured, the task is not aborted. You have to abort it yourself if needed.
// If task done, returns (true, <error from the task>)
// If task aborted, returns (true, utils.ErrAborted)
// If duration elapsed (meaning the task is still running after duration), returns (false, utils.ErrTimeout)
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
		return false, nil, scerr.NewError("cannot wait task '%s': not running", tid)
	}

	var result TaskResult

	c := make(chan struct{})
	go func() {
		result, err = t.Wait()
		c <- struct{}{} // done
		close(c)
	}()

	select {
	case <-time.After(duration):
		return false, nil, scerr.TimeoutError(fmt.Errorf("timeout waiting for task '%s'", tid), duration, nil)
	case <-c:
		return true, result, err
	}
}

// Abort aborts the task execution if running and marks it as ABORTED unless it's already DONE
// A call of this method doesn't actually stop the running task if there is one; a subsequent
// call of Wait() is still needed
func (t *task) Abort() (err error) {
	if t == nil {
		return scerr.InvalidInstanceError()
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	if t.abortDisengaged {
		return scerr.NotAvailableError("abort signal is disengaged on task %s", t.id)
	}

	if t.status == RUNNING {
		// Tell controller to stop go routine
		t.abortCh <- true
		close(t.abortCh)

		// Tell context to cancel
		defer t.cancel()

		t.status = ABORTED
	} else if t.status != DONE {
		t.status = ABORTED
	} else if t.status == DONE {
		fmt.Println("It was finished already")
		t.status = ABORTED
	}

	return nil
}

// NewSubtask creates a subtask from current task
func (t *task) newSubtask() (Task, error) {
	if t == nil {
		return nil, scerr.InvalidInstanceError()
	}

	return newTask(context.TODO(), t)
}

// Abortable tells if task can be aborted
func (t *task) Abortable() (bool, error) {
	if t == nil {
		return false, scerr.InvalidInstanceError()
	}

	t.lock.Lock()
	defer t.lock.Unlock()
	return !t.abortDisengaged, nil
}

// IgnoreAbortSignal can be use to disable the effect of Abort()
func (t *task) IgnoreAbortSignal(ignore bool) error {
	if t == nil {
		return scerr.InvalidInstanceError()
	}
	t.lock.Lock()
	defer t.lock.Unlock()

	t.abortDisengaged = ignore
	return nil
}

// Close cleans up the task
// Must be called to prevent memory leaks
func (t *task) Close() {
	_ = t.Abort()
	for k := range t.subtasks {
		_ = k.Abort()
		_, _ = k.Wait()
	}
	t.subtasks = nil
	_, _ = t.Wait()

	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.context != nil {
		t.closeCh <- struct{}{}
		close(t.closeCh)
	}
	// if set, CancelFunc t.cancel has to be called to prevent memory leak
	if t.cancel != nil {
		t.cancel()
	}
}
