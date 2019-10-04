/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"sync"
	"sync/atomic"
	"time"

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
)

// TaskParameters ...
type TaskParameters interface{}

// TaskResult ...
type TaskResult interface{}

// TaskAction ...
type TaskAction func(t Task, parameters TaskParameters) (TaskResult, error)

// FIXME Unit test this class

// Task ...
type Task interface {
	Abort()
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
	Reset() (Task, error)
	// GetResult() TaskResult
	Run(TaskAction, TaskParameters) (TaskResult, error)
	Start(TaskAction, TaskParameters) (Task, error)
	// StoreResult(TaskParameters)
	TryWait() (bool, TaskResult, error)
	Wait() (TaskResult, error)
}

// task is a structure allowing to identify (indirectly) goroutines
type task struct {
	lock   sync.Mutex
	id     string
	sig    string
	ctx    context.Context
	cancel context.CancelFunc
	status TaskStatus

	finishCh chan struct{} // Used to signal the routine that Wait() the go routine is done
	doneCh   chan bool     // Used by routine to signal it has done its processing
	abortCh  chan bool

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
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil!, use context.TODO() instead!")
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
		abortCh:    make(chan bool, 1),
		doneCh:     make(chan bool, 1),
		finishCh:   make(chan struct{}, 1),
	}
	close(t.abortCh)
	close(t.doneCh)
	close(t.finishCh)

	tid, _ := t.GetID() // FIXME Later
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
		return nil, scerr.InvalidParameterError("id", "cannot be empty!")
	}
	if id == "0" {
		return nil, scerr.InvalidParameterError("id", "cannot be '0', reserved for root task!")
	}
	t.lock.Lock()
	defer t.lock.Unlock()

	t.id = id
	return t, nil
}

// Start runs in goroutine the function with parameters
func (t *task) Start(action TaskAction, params TaskParameters) (Task, error) {
	tid, _ := t.GetID() // FIXME Later

	t.lock.Lock()
	defer t.lock.Unlock()

	if t.status != READY {
		return nil, fmt.Errorf("Can't start task '%s': not ready!", tid)
	}
	if action == nil {
		t.status = DONE
	} else {
		t.status = RUNNING
		t.doneCh = make(chan bool, 1)
		t.abortCh = make(chan bool, 1)
		t.finishCh = make(chan struct{}, 1)
		go t.controller(action, params)
	}
	return t, nil
}

// controller controls the start, termination and possibly aboprtion of the action
func (t *task) controller(action TaskAction, params TaskParameters) {
	go t.run(action, params)

	// tracer := NewTracer(true, t, "")
	finish := false
	for !finish {
		select {
		case <-t.ctx.Done():
			// Context cancel signal received, propagating using abort signal
			// tracer.Trace("receiving signal from context, aborting task...")
			t.abortCh <- true
		case <-t.doneCh:
			// When action is done, "rearms" the done channel to allow Wait()/TryWait() to read from it
			// tracer.Trace("receiving done signal from go routine")
			t.lock.Lock()
			t.status = DONE
			t.lock.Unlock()
			finish = true
			break
		case <-t.abortCh:
			// Abort signal received
			// tracer.Trace("receiving abort signal")
			t.lock.Lock()
			t.status = ABORTED
			t.err = scerr.AbortedError()
			t.lock.Unlock()
			finish = true
		}
	}

	t.finishCh <- struct{}{}
}

// run executes the function 'action'
func (t *task) run(action TaskAction, params TaskParameters) {
	result, err := action(t, params)

	t.lock.Lock()
	defer t.lock.Unlock()

	t.err = err
	t.result = result
	t.doneCh <- true
}

// Run starts task, waits its completion then return the error code
func (t *task) Run(action TaskAction, params TaskParameters) (TaskResult, error) {
	stask, err := t.Start(action, params)
	if err != nil {
		return nil, err
	}

	return stask.Wait()
}

// Wait waits for the task to end, and returns the error (or nil) of the execution
func (t *task) Wait() (TaskResult, error) {
	tid, _ := t.GetID() // FIXME Later

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
	tid, _ := t.GetID() // FIXME Later

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

// WaitFor waits for the task to end, for 'duration' duration
// If task done, returns (true, <error from the task>)
// If task aborted, returns (true, utils.ErrAborted)
// If duration elapsed (meaning the task is still running after duration), returns (false, utils.ErrTimeout)
func (t *task) WaitFor(duration time.Duration) (bool, TaskResult, error) {
	tid, _ := t.GetID() // FIXME Later

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

// Reset resets the task for reuse
func (t *task) Reset() (Task, error) {
	tid, _ := t.GetID() // FIXME Later

	status := t.GetStatus()
	if status == RUNNING {
		return nil, fmt.Errorf("Can't reset task '%s': task running!", tid)
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	t.status = READY
	t.err = nil
	t.result = nil
	return t, nil
}

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
func (t *task) Abort() {
	status := t.GetStatus()
	if status == RUNNING {
		t.lock.Lock()
		defer t.lock.Unlock()

		// Tell controller to stop go routine
		t.abortCh <- true

		// Tell context to cancel
		t.cancel()

		t.status = ABORTED
	}
}

// Aborted tells if task has been aborted
func (t *task) Aborted() bool {
	return t.status == ABORTED
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
