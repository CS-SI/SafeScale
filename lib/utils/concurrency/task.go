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

	"github.com/CS-SI/SafeScale/lib/utils/temporal"

	"github.com/CS-SI/SafeScale/lib/utils/fail"

	uuid "github.com/satori/go.uuid"
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

// TaskAction ...
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
	ForceID(string) (Task, error)
	GetID() (string, error)
	GetSignature() string
	GetStatus() TaskStatus
	GetContext() context.Context
	Lock(TaskedLock)
	RLock(TaskedLock)
	Unlock(TaskedLock)
	RUnlock(TaskedLock)
	New() (Task, error)
	// Reset() (Task, error) // VPL: disabled, may lead to DATARACE; need to either fix or definitively remove Reset()
	// GetResult() TaskResult
	Run(TaskAction, TaskParameters) (TaskResult, error)
	Start(TaskAction, TaskParameters) (Task, error)
	StartWithTimeout(TaskAction, TaskParameters, time.Duration) (Task, error)
}

// Task is the interface of a task running in goroutine, allowing to identity (indirectly) goroutines
type Task interface {
	TaskCore
	TaskGuard
}

// task is the implementation of Task
type task struct {
	lock   sync.Mutex
	id     string
	sig    string
	ctx    context.Context
	cancel context.CancelFunc
	status TaskStatus

	finishCh chan struct{} // Used to signal the routine that Wait() the go routine is done
	doneCh   chan bool     // Used by routine to signal it has done its processing
	abortCh  chan struct{}

	err    error
	result TaskResult

	generation uint // For tracing/debug purpose
}

var globalTask atomic.Value

// RootTask is the "task to rule them all"
func RootTask() Task {
	anon := globalTask.Load()
	if anon == nil {
		newT, _ := newTask(context.TODO(), nil)
		newT.id = "0"
		newT.generation = 0
		globalTask.Store(newT)
		anon = globalTask.Load()
	}
	return anon.(Task)
}

// VoidTask is a new task that do nothing
func VoidTask() (Task, error) {
	return NewTask(nil)
}

// NewTask ...
func NewTask(parentTask Task) (Task, error) {
	return newTask(context.TODO(), parentTask)
}

// NewTaskWithContext ...
func NewTaskWithContext(ctx context.Context) (Task, error) {
	return newTask(ctx, nil)
}

// newTask creates a new Task from parentTask or using ctx as parent context
func newTask(ctx context.Context, parentTask Task) (*task, error) {
	var (
		childContext context.Context
		cancel       context.CancelFunc
		generation   uint
	)

	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil, use context.TODO() instead")
	}

	if parentTask == nil {
		if ctx == context.TODO() {
			childContext, cancel = context.WithCancel(context.Background())
		} else {
			childContext, cancel = context.WithCancel(ctx)
		}
	} else {
		pTask := parentTask.(*task)
		childContext, cancel = context.WithCancel(parentTask.(*task).ctx)
		generation = pTask.generation + 1
	}
	t := task{
		ctx:        childContext,
		cancel:     cancel,
		status:     READY,
		generation: generation,
		// abortCh:    make(chan bool, 1),
		// doneCh:     make(chan bool, 1),
		// finishCh:   make(chan struct{}, 1),
	}

	tid, _ := t.GetID() // FIXME: Later
	t.sig = fmt.Sprintf("{task %s}", tid)

	return &t, nil
}

// GetID returns an unique id for the task
func (t *task) GetID() (string, error) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.id == "" {
		u, err := uuid.NewV4()
		if err != nil {
			return "", fmt.Errorf("failed to create a new task: %v", err)
		}
		t.id = u.String()
	}
	return t.id, nil
}

// GetSignature builds the "signature" of the task passed as parameter,
// ie a string representation of the task ID in the format "{task <id>}".
func (t *task) GetSignature() string {
	return t.sig
}

// Status returns the current task status
func (t *task) GetStatus() TaskStatus {
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.status
}

// GetContext returns the context associated to the task
func (t *task) GetContext() context.Context {
	return t.ctx
}

// ForceID allows to specify task ID. The unicity of the ID through all the tasks
// becomes the responsability of the developer...
func (t *task) ForceID(id string) (Task, error) {
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty!")
	}
	if id == "0" {
		return nil, fail.InvalidParameterError("id", "cannot be '0', reserved for root task")
	}
	t.lock.Lock()
	defer t.lock.Unlock()

	t.id = id
	return t, nil
}

// Start runs in goroutine the function with parameters
func (t *task) Start(action TaskAction, params TaskParameters) (Task, error) {
	return t.StartWithTimeout(action, params, 0)
}

// StartWithTimeout runs in goroutine the TasAction with TaskParameters, and stops after timeout (if > 0)
// If timeout happens, error returned will be ErrTimeout
// This function is useful when you know at the time you use it there will be a timeout to apply.
func (t *task) StartWithTimeout(action TaskAction, params TaskParameters, timeout time.Duration) (Task, error) {
	tid, _ := t.GetID() // FIXME: Later

	if t.GetStatus() != READY {
		return nil, fmt.Errorf("cannot start task '%s': not ready", tid)
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	if action == nil {
		t.status = DONE
	} else {
		t.status = RUNNING
		t.doneCh = make(chan bool, 1)
		t.abortCh = make(chan struct{}, 1)
		t.finishCh = make(chan struct{}, 1)
		go t.controller(action, params, timeout)
	}
	return t, nil
}

// controller controls the start, termination and possibly aboprtion of the action
func (t *task) controller(action TaskAction, params TaskParameters, timeout time.Duration) {
	go t.run(action, params)

	// tracer := NewTracer(t, "", true)
	finish := false
	begin := time.Now()

	if timeout > 0 {
		for !finish {
			select {
			case <-t.ctx.Done():
				// Context cancel signal received, propagating using abort signal
				// tracer.Trace("receiving signal from context, aborting task...")
				t.lock.Lock()
				if t.status == RUNNING && t.abortCh != nil {
					t.abortCh <- struct{}{}
				}
				t.lock.Unlock()
			case <-t.doneCh:
				// When action is done, "rearms" the done channel to allow Wait()/TryWait() to read from it
				// tracer.Trace("receiving done signal from go routine")
				t.lock.Lock()
				t.status = DONE
				t.lock.Unlock()
				finish = true
			case <-t.abortCh:
				// Abort signal received
				t.lock.Lock()
				close(t.abortCh)
				t.abortCh = nil
				if t.status != TIMEOUT {
					t.status = ABORTED
					t.err = fail.AbortedError("", nil)
				}
				t.lock.Unlock()
				finish = true
			case <-time.After(timeout):
				t.lock.Lock()
				st := t.status
				t.status = TIMEOUT
				t.err = fail.TimeoutError(
					fmt.Sprintf(
						"task is out of time ( %s > %s)", temporal.FormatDuration(time.Since(begin)),
						temporal.FormatDuration(timeout),
					), timeout, nil,
				)
				if st == RUNNING && t.abortCh != nil {
					t.abortCh <- struct{}{}
				}
				t.lock.Unlock()
			}
		}
	} else {
		for !finish {
			select {
			case <-t.ctx.Done():
				// Context cancel signal received, propagating using abort signal
				// tracer.Trace("receiving signal from context, aborting task...")
				t.lock.Lock()
				if t.status == RUNNING && t.abortCh != nil {
					t.abortCh <- struct{}{}
				}
				t.lock.Unlock()
			case <-t.doneCh:
				t.lock.Lock()
				t.status = DONE
				t.lock.Unlock()
				finish = true
			case <-t.abortCh:
				// Abort signal received
				// tracer.Trace("receiving abort signal")
				t.lock.Lock()
				close(t.abortCh)
				t.abortCh = nil
				if t.status != TIMEOUT {
					t.status = ABORTED
					t.err = fail.AbortedError("", nil)
				}
				t.lock.Unlock()
				finish = true
			}
		}
	}

	t.lock.Lock()
	t.finishCh <- struct{}{}
	close(t.finishCh)
	t.lock.Unlock()
}

// run executes the function 'action'
func (t *task) run(action TaskAction, params TaskParameters) {
	result, err := action(t, params)

	t.lock.Lock()
	defer t.lock.Unlock()

	t.err = err
	t.result = result
	t.doneCh <- true
	close(t.doneCh)
}

// Run starts task, waits its completion then return the error code
func (t *task) Run(action TaskAction, params TaskParameters) (TaskResult, error) {
	_, err := t.Start(action, params)
	if err != nil {
		return nil, err
	}
	return t.Wait()
}

// Wait waits for the task to end, and returns the error (or nil) of the execution
func (t *task) Wait() (TaskResult, error) {
	tid, _ := t.GetID() // FIXME: Later

	status := t.GetStatus()
	if status == DONE {
		return t.result, t.err
	}
	if status == ABORTED {
		return nil, t.err
	}
	if status != RUNNING {
		return nil, fmt.Errorf("cannot wait task '%s': not running (%d)", tid, status)
	}
	<-t.finishCh

	t.lock.Lock()
	defer t.lock.Unlock()
	return t.result, t.err
}

// TryWait tries to wait on a task
// If task done, returns (true, TaskResult, <error from the task>)
// If task aborted, returns (true, utils.ErrAborted)
// If task still running, returns (false, nil)
func (t *task) TryWait() (bool, TaskResult, error) {
	tid, _ := t.GetID() // FIXME: Later

	status := t.GetStatus()
	if status == DONE {
		return true, t.result, t.err
	}
	if status == ABORTED {
		return true, nil, t.err
	}
	if status != RUNNING {
		return false, nil, fmt.Errorf("cannot wait task '%s': not running", tid)
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
// If task aborted, returns (true, fail.ErrAborted)
// If duration elapsed (meaning the task is still running after duration), returns (false, fail.ErrTimeout)
func (t *task) WaitFor(duration time.Duration) (bool, TaskResult, error) {
	tid, _ := t.GetID() // FIXME: Later

	status := t.GetStatus()
	if status == DONE {
		return true, t.result, t.err
	}
	if status == ABORTED {
		return true, nil, t.err
	}
	if status != RUNNING {
		return false, nil, fmt.Errorf("cannot wait task '%s': not running", tid)
	}

	for {
		select {
		case <-time.After(duration):
			return false, nil, fail.TimeoutError(fmt.Sprintf("timeout waiting for task '%s'", tid), duration, nil)
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

// Reset resets the task for reuse
// VPL: DISABLED; need fix or definitive removal
// func (t *task) Reset() (Task, error) {
// 	tid, _ := t.GetID() // FIXME: Later

// 	status := t.GetStatus()
// 	if status == RUNNING {
// 		return nil, fmt.Errorf("cannot reset task '%s': task running", tid)
// 	}

// 	t.lock.Lock()
// 	defer t.lock.Unlock()

// 	t.status = READY
// 	t.err = nil
// 	t.result = nil
// 	return t, nil
// }

// // GetResult returns the result of the task action
// func (t *task) GetResult() TaskResult {
// 	status := t.GetStatus()
// 	if status == READY {
// 		panic("Can't get result of task '%s': task not started!")
// 	}
// 	if status != DONE {
// 		panic("Can't get result of task '%s': task not done!")
// 	}
// 	t.lock.Lock()
// 	defer t.lock.Unlock()
// 	return t.result
// }

// Abort aborts the task execution
func (t *task) Abort() error {
	if t == nil {
		return fail.InvalidInstanceError()
	}

	status := t.GetStatus()
	if status == RUNNING {
		t.lock.Lock()
		defer t.lock.Unlock()

		// Tell context to cancel
		t.cancel()

		t.status = ABORTED
	}
	return nil
}

// Aborted tells if task has been aborted
func (t *task) Aborted() bool {
	st := t.GetStatus()
	return st == ABORTED || st == TIMEOUT
}

// StoreResult stores the result of the run
func (t *task) StoreResult(result TaskParameters) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.result = result
}

// New creates a subtask from current task
func (t *task) New() (Task, error) {
	return newTask(context.TODO(), t)
}

// Lock locks the TaskedLock
func (t *task) Lock(lock TaskedLock) {
	lock.Lock(t)
}

// RLock locks for read the TaskedLock
func (t *task) RLock(lock TaskedLock) {
	lock.RLock(t)
}

// Unlock unlocks the TaskedLock
func (t *task) Unlock(lock TaskedLock) {
	lock.Unlock(t)
}

// RUnlock unlocks a read lock put on the TaskedLock
func (t *task) RUnlock(lock TaskedLock) {
	lock.RUnlock(t)
}
