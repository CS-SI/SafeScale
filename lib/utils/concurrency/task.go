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
	"sync"
	"sync/atomic"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	uuid "github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate stringer -type=TaskStatus

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
//       the abort reason is), and permit ending properly. Otherwise, this may lead to goroutine leak
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

//go:generate minimock -o mocks/mock_taskguard.go -i github.com/CS-SI/SafeScale/v22/lib/utils/concurrency.TaskGuard

// TaskGuard ...
type TaskGuard interface {
	TryWait() (bool, TaskResult, fail.Error)
	Wait() (TaskResult, fail.Error)
	WaitFor(time.Duration) (bool, TaskResult, fail.Error)
}

//go:generate minimock -o mocks/mock_taskcore.go -i github.com/CS-SI/SafeScale/v22/lib/utils/concurrency.TaskCore

// TaskCore is the interface of core methods to control Task and TaskGroup
type TaskCore interface {
	Abort() fail.Error
	AbortWithCause(fail.Error) fail.Error
	Abortable() (bool, fail.Error)
	Aborted() bool
	DisarmAbortSignal() func()
	ID() (string, fail.Error)
	Signature() string
	Status() (TaskStatus, fail.Error)
	Context() context.Context
	LastError() (error, fail.Error)
	Result() (TaskResult, fail.Error)
	SetID(string) fail.Error

	Run(fn TaskAction, params TaskParameters, options ...data.ImmutableKeyValue) (TaskResult, fail.Error)
	Start(fn TaskAction, params TaskParameters, options ...data.ImmutableKeyValue) (Task, fail.Error)
	StartWithTimeout(fn TaskAction, params TaskParameters, timeout time.Duration, options ...data.ImmutableKeyValue) (Task, fail.Error)
}

//go:generate minimock -o mocks/mock_task.go -i github.com/CS-SI/SafeScale/v22/lib/utils/concurrency.Task

// Task is the interface of a task running in goroutine, allowing to identity (indirectly) goroutines
type Task interface {
	TaskCore
	TaskGuard
}

type taskStats struct {
	runBegin           time.Time
	controllerBegin    time.Time
	runDuration        time.Duration
	controllerDuration time.Duration
	events             struct {
		cancel        []time.Time
		timeout       []time.Time
		abort         []time.Time
		runTerminated []time.Time
	}
}

// task is a structure allowing to identify (indirectly) goroutines
type task struct {
	lock sync.RWMutex
	id   string

	ctx    context.Context
	cancel context.CancelFunc
	status TaskStatus

	controllerTerminatedCh chan struct{} // Used to signal Wait() (and siblings) the controller of the go routine has terminated
	runTerminatedCh        chan struct{} // Used by go routine to signal it has done its processing
	abortCh                chan struct{} // Used to signal the routine it has to stop processing

	err    fail.Error
	result TaskResult

	abortDisengaged      bool // used to not react on abort signal
	cancelDisengaged     bool // used to not react on cancel signal (internal use only, not exposed by API)
	runTerminated        bool // used to keep track of run terminated state
	controllerTerminated bool // used to keep track of controller terminated state
	resultObtained       bool // used to know that the result has been returned by the TaskAction

	stats taskStats
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
func RootTask() (rt Task, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	anon := globalTask.Load()
	if anon == nil {
		newT, xerr := newTask(context.Background(), nil)
		if xerr != nil {
			return nil, xerr
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
	KeyForID            taskContextKey = "ID"
)

// TaskFromContext extracts the task instance from context
// returns:
//    - Task, nil: Task found in 'ctx'
//    - nil, *fail.ErrNotAvailable: there is no Task value in 'ctx'
//    - nil, *fail.ErrInconsistent: value stored as Task in "ctx' is not of type Task
//    - nil, *ErrInvalidParameter: 'ctx' is nil
func TaskFromContext(ctx context.Context) (Task, fail.Error) {
	if ctx != nil {
		if ctxValue := ctx.Value(KeyForTaskInContext); ctxValue != nil {
			if task, ok := ctxValue.(Task); ok {
				return task, nil
			}
			return nil, fail.InconsistentError("context value for '%s' is not a 'concurrency.Task'", KeyForTaskInContext)
		}
		return nil, fail.InconsistentError("cannot find a value for '%s' in context", KeyForTaskInContext)
	}

	return nil, fail.InvalidParameterCannotBeNilError("ctx")
}

// TaskFromContextOrVoid extracts the task instance from context.
// If there is no task in the context, returns a VoidTask()
// returns:
//    - Task, nil: Task found in 'ctx' or VoidTask() is returned
func TaskFromContextOrVoid(ctx context.Context) (Task, fail.Error) {
	nctx, err := TaskFromContext(ctx)
	if err != nil {
		return VoidTask()
	}

	return nctx, nil
}

// NewTask creates a new instance of Task
func NewTask() (Task, fail.Error) {
	return newTask(context.Background(), nil)
}

// NewUnbreakableTask is a new task that cannot be aborted by default (but this can be changed with IgnoreAbortSignal(false))
func NewUnbreakableTask() (Task, fail.Error) {
	nt, xerr := newTask(context.Background(), nil) // nolint
	if xerr != nil {
		return nil, xerr
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

// NewTaskWithContext creates an instance of Task with context
func NewTaskWithContext(ctx context.Context, options ...data.ImmutableKeyValue) (Task, fail.Error) {
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	return newTask(ctx, nil, options...)
}

// newTask creates a new Task from parentTask or using ctx as parent context
func newTask(ctx context.Context, parentTask Task, options ...data.ImmutableKeyValue) (nt *task, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	var (
		childContext context.Context
		cancel       context.CancelFunc
	)

	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil!, use context.TODO() or context.Background() instead!")
	}

	if parentTask == nil {
		if ctx == context.TODO() { // nolint
			childContext, cancel = context.WithCancel(context.Background())
		} else {
			childContext, cancel = context.WithCancel(ctx)
		}
	} else {
		childContext, cancel = context.WithCancel(parentTask.(*task).ctx)
	}
	instance := &task{
		cancel:                 cancel,
		status:                 READY,
		abortCh:                make(chan struct{}, 1),
		runTerminatedCh:        make(chan struct{}, 1),
		controllerTerminatedCh: make(chan struct{}, 1),
		result:                 make(chan TaskResult),
	}

	generateID := true
	if len(options) > 0 {
		for _, v := range options {
			switch v.Key() { // nolint
			case keywordInheritParentIDOption:
				value, ok := v.Value().(bool)
				if ok && value && parentTask != nil {
					generateID = false
					id, xerr := parentTask.ID()
					if xerr != nil {
						return nil, xerr
					}
					instance.id = id
				}
			}
		}
	}

	if generateID {
		u, err := uuid.NewV4()
		if err != nil {
			return nil, fail.Wrap(err, "failed to create a new task")
		}

		instance.id = u.String()
	}

	if len(options) > 0 {
		for _, v := range options {
			switch v.Key() { // nolint
			case keywordAmendID:
				value, ok := v.Value().(string)
				if ok {
					instance.id += "+" + value
				}
			}
		}
	}

	instance.ctx = context.WithValue(childContext, KeyForTaskInContext, instance) // nolint

	return instance, nil
}

// IsNull checks if task is not initialized
func (instance *task) IsNull() bool {
	if instance == nil {
		return true
	}
	instance.lock.RLock()
	defer instance.lock.RUnlock()
	return instance.id == ""
}

// LastError returns the last error of the Task
func (instance *task) LastError() (error, fail.Error) { // nolint
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.err, nil
}

// Result returns the result of the ended task
func (instance *task) Result() (TaskResult, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	if instance.status != DONE {
		return nil, fail.InvalidRequestError("task is not done, there is no result yet")
	}

	return instance.result, nil
}

// ID returns an unique id for the task
func (instance *task) ID() (string, fail.Error) {
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.id, nil
}

// Signature builds the "signature" of the task passed as parameter,
// ie a string representation of the task ID in the format "{task <id>}".
func (instance *task) Signature() string {
	if valid.IsNil(instance) {
		return ""
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.signature()
}

// Signature returns a string as signature
func (instance *task) signature() string {
	if instance.id != "" {
		return `{task ` + instance.id + `}`
	}
	return ""
}

// Status returns the current task status
func (instance *task) Status() (TaskStatus, fail.Error) {
	if valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.status, nil
}

// Context returns the context associated to the task, or context.Background() if there is no context
func (instance *task) Context() context.Context {
	if valid.IsNil(instance) {
		return context.TODO() // nolint
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	if instance.ctx != nil {
		return instance.ctx
	}
	return context.Background()
}

// SetID allows specifying task ID. The uniqueness of the ID through all the tasks
// becomes the responsibility of the developer...
func (instance *task) SetID(id string) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty!")
	}
	if id == "0" {
		return fail.InvalidParameterError("id", "cannot be '0', reserved for root task")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	switch instance.status {
	case READY:
		instance.id = id
		return nil

	case ABORTED:
		fallthrough
	case RUNNING:
		fallthrough
	case TIMEOUT:
		return fail.InconsistentError("cannot set ID of a Task in status (%s)", instance.status)

	case DONE:
		return fail.InconsistentError("cannot set ID of a terminated (status %s) Task", instance.status)

	case UNKNOWN:
		fallthrough
	default:
		return fail.InconsistentError("cannot set ID of the Task: invalid status (%s)", instance.status)
	}
}

// Start runs in goroutine the function with parameters
func (instance *task) Start(action TaskAction, params TaskParameters, options ...data.ImmutableKeyValue) (Task, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	return instance.StartWithTimeout(action, params, 0, options...)
}

// StartWithTimeout runs in goroutine the TaskAction with TaskParameters, and stops after timeout (if > 0)
// If timeout happens, error returned will be '*fail.ErrTimeout'
func (instance *task) StartWithTimeout(action TaskAction, params TaskParameters, timeout time.Duration, _ ...data.ImmutableKeyValue) (Task, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	status := instance.status
	instance.lock.RUnlock() // nolint

	switch status {
	case READY:
		if action == nil {
			instance.lock.Lock()
			instance.status = DONE
			instance.lock.Unlock() // nolint
		} else {
			instance.lock.Lock()
			instance.status = RUNNING
			instance.runTerminatedCh = make(chan struct{}, 1)
			instance.abortCh = make(chan struct{}, 1)
			instance.controllerTerminatedCh = make(chan struct{}, 1)
			instance.lock.Unlock() // nolint

			go func() {
				var crash error
				defer func() {
					if crash != nil { // if instance.controller panics
						instance.err = fail.Wrap(crash, "panic running controller method")
					}
				}()
				defer fail.OnPanic(&crash)

				ctrlErr := instance.controller(action, params, timeout)

				instance.lock.Lock()
				defer instance.lock.Unlock()

				if ctrlErr != nil {
					if instance.err != nil {
						_ = instance.err.AddConsequence(fail.Wrap(ctrlErr, "unexpected error running the Task controller"))
					} else {
						instance.err = fail.Wrap(ctrlErr, "unexpected error running the Task controller")
					}
				}
			}()
		}
		return instance, nil

	case ABORTED:
		return nil, fail.InconsistentError("cannot start on Task '%s': reuse is forbidden (already aborted)", instance.id)
	case TIMEOUT:
		return nil, fail.InconsistentError("cannot start on Task '%s': reuse is forbidden (already timeout)", instance.id)
	case RUNNING:
		return nil, fail.InconsistentError("cannot start on Task '%s': reuse is forbidden (already running)", instance.id)
	case DONE:
		return nil, fail.InconsistentError("cannot start on Task '%s': reuse is forbidden (already done)", instance.id)

	case UNKNOWN:
		fallthrough
	default:
		return nil, fail.InconsistentError("cannot start Task '%s': unknown status (%s)", instance.id, instance.status)
	}
}

// controller controls the start, termination and possibly abortion of the action
func (instance *task) controller(action TaskAction, params TaskParameters, timeout time.Duration) (ferr fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	defer fail.OnPanic(&ferr) // better safe than sorry

	traceR := newTracer(instance, tracing.ShouldTrace("concurrency.task"))

	instance.lock.Lock()
	instance.stats.controllerBegin = time.Now()
	instance.lock.Unlock() // nolint

	go func() {
		var failure error
		defer fail.OnPanic(&failure) // this prevents the os.Exit, but we lack communication outside the func -> the task will be unaware

		instance.lock.Lock()
		instance.stats.runBegin = time.Now()
		instance.lock.Unlock() // nolint

		instance.run(action, params)

		instance.lock.Lock()
		instance.stats.runDuration = time.Since(instance.stats.runBegin)
		instance.lock.Unlock() // nolint
	}()

	if timeout > 0 {
		canceled, expired, finished, xerr := instance.reactWithTimeout(timeout, traceR)
		if xerr != nil {
			return xerr
		}

		switch {
		case finished:
			return nil
		case expired:
			return instance.reactAfterExpired(traceR)
		case canceled:
			return instance.reactAfterCanceledWithTimeout(timeout, traceR)
		default:
			return fail.InconsistentError("controller state is inconsistent: neither finished nor expired nor canceled")
		}
	} else {
		canceled, finished, xerr := instance.reactWithoutTimeout(traceR)
		if xerr != nil {
			return xerr
		}

		switch {
		case finished:
			return nil
		case canceled:
			return instance.reactAfterCanceledWithoutTimeout(traceR)
		default:
			return fail.InconsistentError("controller state is inconsistent: neither finished nor canceled")
		}
	}
}

// reactWithTimeout reacts on events with timeout
func (instance *task) reactWithTimeout(timeout time.Duration, traceR *tracer) (canceled, expired, finished bool, ferr fail.Error) {
	for !finished && !canceled {
		select {
		case <-instance.ctx.Done():
			eventTime := time.Now()
			instance.lock.Lock()
			instance.stats.events.cancel = append(instance.stats.events.cancel, eventTime)
			status := instance.status
			terminated := len(instance.runTerminatedCh) > 0
			traceR.trace("received cancel signal after %v\n", time.Since(instance.stats.controllerBegin))
			instance.lock.Unlock() // nolint

			if status != ABORTED && status != TIMEOUT && !terminated {
				xerr := instance.processCancel(traceR)
				if xerr != nil {
					return canceled, expired, finished, xerr
				}
			}
			canceled = true

		case <-instance.abortCh:
			eventTime := time.Now()
			instance.lock.Lock()
			instance.stats.events.abort = append(instance.stats.events.abort, eventTime)
			traceR.trace("received abort signal after %v\n", time.Since(instance.stats.controllerBegin))
			instance.lock.Unlock() // nolint

			var xerr fail.Error
			xerr = instance.processAbort(traceR)
			if xerr != nil {
				return canceled, expired, finished, xerr
			}

		case <-instance.runTerminatedCh:
			eventTime := time.Now()
			instance.lock.Lock()
			instance.stats.events.runTerminated = append(instance.stats.events.runTerminated, eventTime)
			traceR.trace("received run termination signal after %v\n", time.Since(instance.stats.controllerBegin))
			instance.lock.Unlock() // nolint

			instance.processTerminated(traceR)
			finished = true // stop to react on signals

		case <-time.After(timeout):
			eventTime := time.Now()
			instance.lock.Lock()
			instance.stats.events.timeout = append(instance.stats.events.timeout, eventTime)
			traceR.trace("received timeout signal after %v\n", time.Since(instance.stats.controllerBegin))
			instance.lock.Unlock() // nolint

			instance.processTimeout(timeout)
			expired = true // Stop to trigger timeout signal
		}
	}

	return canceled, expired, finished, nil
}

// reactWithoutTimeout reacts on events without timeout
func (instance *task) reactWithoutTimeout(traceR *tracer) (canceled, finished bool, ferr fail.Error) {
	for !finished && !canceled {
		select {
		case <-instance.ctx.Done():
			eventTime := time.Now()
			instance.lock.Lock()
			instance.stats.events.cancel = append(instance.stats.events.cancel, eventTime)
			status := instance.status
			terminated := len(instance.runTerminatedCh) > 0
			traceR.trace("received cancel signal after %v\n", time.Since(instance.stats.controllerBegin))
			instance.lock.Unlock() // nolint

			if status != ABORTED && status != TIMEOUT && !terminated {
				xerr := instance.processCancel(traceR)
				if xerr != nil {
					return canceled, finished, xerr
				}
			}
			canceled = true

		case <-instance.abortCh:
			eventTime := time.Now()
			instance.lock.Lock()
			instance.stats.events.abort = append(instance.stats.events.abort, eventTime)
			traceR.trace("received abort signal after %v\n", time.Since(instance.stats.controllerBegin))
			instance.lock.Unlock() // nolint

			xerr := instance.processAbort(traceR)
			if xerr != nil {
				return canceled, finished, xerr
			}

		case <-instance.runTerminatedCh:
			eventTime := time.Now()
			instance.lock.Lock()
			instance.stats.events.runTerminated = append(instance.stats.events.runTerminated, eventTime)
			traceR.trace("received run termination signal after %v\n", time.Since(instance.stats.controllerBegin))
			instance.lock.Unlock() // nolint

			instance.processTerminated(traceR)
			finished = true // stop to react on signals
		}
	}

	return canceled, finished, nil
}

// reactAfterExpired reacts on events after timeout has occurred
func (instance *task) reactAfterExpired(traceR *tracer) fail.Error {
	var finished bool
	for !finished {
		select {
		case <-instance.abortCh:
			eventTime := time.Now()
			instance.lock.Lock()
			instance.stats.events.abort = append(instance.stats.events.abort, eventTime)
			traceR.trace("received abort signal after %v\n", time.Since(instance.stats.controllerBegin))
			instance.lock.Unlock() // nolint

			xerr := instance.processAbort(traceR)
			if xerr != nil {
				return xerr
			}

		case <-instance.runTerminatedCh:
			eventTime := time.Now()
			instance.lock.Lock()
			instance.stats.events.runTerminated = append(instance.stats.events.runTerminated, eventTime)
			traceR.trace("received run termination signal after %v\n", time.Since(instance.stats.controllerBegin))
			instance.lock.Unlock() // nolint

			instance.processTerminated(traceR)
			finished = true // stop to react on signals
		}
	}
	return nil
}

// reactAfterCanceledWithTimeout reacts on events after task has been canceled but not yet terminated (and timeout may still occur)
func (instance *task) reactAfterCanceledWithTimeout(timeout time.Duration, traceR *tracer) fail.Error {
	var finished bool
	for !finished {
		select {
		case <-instance.abortCh:
			eventTime := time.Now()
			instance.lock.Lock()
			instance.stats.events.abort = append(instance.stats.events.abort, eventTime)
			traceR.trace("received abort signal after %v\n", time.Since(instance.stats.controllerBegin))
			instance.lock.Unlock() // nolint

			xerr := instance.processAbort(traceR)
			if xerr != nil {
				return xerr
			}

		case <-instance.runTerminatedCh:
			eventTime := time.Now()
			instance.lock.Lock()
			instance.stats.events.runTerminated = append(instance.stats.events.runTerminated, eventTime)
			traceR.trace("received run termination signal after %v\n", time.Since(instance.stats.controllerBegin))
			instance.lock.Unlock() // nolint

			instance.processTerminated(traceR)
			finished = true // stop to react on signals

		case <-time.After(timeout):
			eventTime := time.Now()
			instance.lock.Lock()
			instance.stats.events.timeout = append(instance.stats.events.timeout, eventTime)
			traceR.trace("received timeout signal after %v\n", time.Since(instance.stats.controllerBegin))
			instance.lock.Unlock() // nolint

			instance.processTimeout(timeout)
		}
	}

	return nil
}

// reactAfterCanceledWithoutTimeout reacts on events after task has been canceled but not yet terminated and there is no timeout
func (instance *task) reactAfterCanceledWithoutTimeout(traceR *tracer) fail.Error {
	var finished bool
	for !finished {
		select {
		case <-instance.abortCh:
			eventTime := time.Now()
			instance.lock.Lock()
			instance.stats.events.abort = append(instance.stats.events.abort, eventTime)
			traceR.trace("received abort signal after %v\n", time.Since(instance.stats.controllerBegin))
			instance.lock.Unlock() // nolint

			xerr := instance.processAbort(traceR)
			if xerr != nil {
				return xerr
			}

		case <-instance.runTerminatedCh:
			eventTime := time.Now()
			instance.lock.Lock()
			instance.stats.events.runTerminated = append(instance.stats.events.runTerminated, eventTime)
			traceR.trace("received run termination signal after %v\n", time.Since(instance.stats.controllerBegin))
			instance.lock.Unlock() // nolint

			instance.processTerminated(traceR)
			finished = true // stop to react on signals
		}
	}

	return nil
}

// processCancel operates when cancel has been called
func (instance *task) processCancel(traceR *tracer) fail.Error {
	instance.lock.RLock()
	status := instance.status
	doNotAbort := instance.abortDisengaged
	doNotCancel := instance.cancelDisengaged
	ctxErr := instance.ctx.Err()
	instance.lock.RUnlock() // nolint

	traceR.trace("receiving signal from context")
	if !doNotAbort && !doNotCancel {
		switch status {
		case RUNNING:
			switch ctxErr {
			case context.DeadlineExceeded:
				instance.lock.Lock()
				instance.status = TIMEOUT
				instance.lock.Unlock() // nolint

			case context.Canceled:
				fallthrough
			default:
				instance.lock.Lock()
				instance.status = ABORTED
				instance.lock.Unlock() // nolint
			}
			instance.abortCh <- struct{}{} // VPL: do not put this inside a lock

		case ABORTED:
			fallthrough
		case TIMEOUT:
			fallthrough
		case DONE:
			// do nothing
		case READY: // abnormal status if controller is running
			fallthrough
		case UNKNOWN: // by definition, this status is invalid
			fallthrough
		default:
			return fail.InconsistentError("invalid Task state '%s'", status)
		}
	}
	return nil
}

// processTerminated operates when go routine terminates
func (instance *task) processTerminated(_ *tracer) {
	instance.lock.Lock()
	instance.stats.controllerDuration = time.Since(instance.stats.controllerBegin)
	instance.controllerTerminated = true
	// instance.status = DONE
	instance.lock.Unlock() // nolint
	instance.controllerTerminatedCh <- struct{}{}
	close(instance.controllerTerminatedCh) // VPL: this channel MUST BE CLOSED
}

// processAbort operates when Abort has been requested
func (instance *task) processAbort(_ *tracer) fail.Error {
	instance.lock.Lock()
	defer instance.lock.Unlock()

	if instance.err != nil {
		switch instance.err.(type) {
		case *fail.ErrAborted, *fail.ErrTimeout:
			// do nothing
		default:
			abortError := fail.AbortedError(nil)
			_ = abortError.AddConsequence(instance.err)
			instance.err = abortError
		}
	} else if !instance.runTerminated {
		switch instance.status {
		case ABORTED:
			instance.err = fail.AbortedError(nil)
		case TIMEOUT:
			instance.err = fail.TimeoutError(nil, 0)
		}
	}
	if instance.status != TIMEOUT {
		instance.status = ABORTED
	}
	instance.contextCleanup()
	return nil
}

// processTimeout operates when timeout occurs
func (instance *task) processTimeout(timeout time.Duration) {
	instance.lock.RLock()
	status := instance.status
	instance.lock.RUnlock() // nolint

	if status != ABORTED {
		instance.abortCh <- struct{}{} // Note: DO NOT put this inside a lock (blocking write, unbuffered channel...)

		instance.lock.Lock()
		defer instance.lock.Unlock()

		if !instance.runTerminated {
			instance.err = fail.TimeoutError(instance.err, timeout)
		}
		instance.status = TIMEOUT
	}
}

// run executes the function 'action'
func (instance *task) run(action TaskAction, params TaskParameters) {
	defer func() {
		if err := recover(); err != nil {
			instance.runTerminatedCh <- struct{}{} // Note: Do not put this inside a lock (blocking write, unbuffered channel...)
			close(instance.runTerminatedCh)        // Note: This channel MUST BE CLOSED

			instance.lock.Lock()
			defer instance.lock.Unlock()

			instance.runTerminated = true
			instance.cancelDisengaged = true
			if instance.err != nil {
				_ = instance.err.AddConsequence(fail.RuntimePanicError("panic happened: %v", err))
			} else {
				instance.err = fail.RuntimePanicError("panic happened: %v", err)
			}

			instance.result = nil
			instance.resultObtained = true
			instance.status = DONE
		}
	}()

	result, laterErr := action(instance, params) // we process this error later

	instance.runTerminatedCh <- struct{}{} // Note: Do not put this inside a lock
	close(instance.runTerminatedCh)        // Note: this channel MUST BE CLOSED

	instance.lock.Lock()
	defer instance.lock.Unlock()

	instance.cancelDisengaged = true
	instance.runTerminated = true
	instance.result = result
	instance.resultObtained = true

	currentError := instance.err

	xerr := laterErr // time to process the previous error
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAborted:
			if currentError != nil {
				switch cerr := currentError.(type) {
				case *fail.ErrAborted:
					// leave instance.err as it is
					break
				default:
					_ = cerr.AddConsequence(xerr)
				}
			} else {
				currentError = xerr
			}

		default:
			if currentError != nil {
				switch cerr := currentError.(type) { // nolint
				case fail.Error:
					_ = cerr.AddConsequence(xerr)
				}
			} else {
				currentError = xerr
			}
		}
	}

	instance.err = currentError
}

// Run starts task, waits its completion then return the error code
func (instance *task) Run(action TaskAction, params TaskParameters, options ...data.ImmutableKeyValue) (TaskResult, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	_, err := instance.Start(action, params, options...)
	if err != nil {
		return nil, err
	}

	return instance.Wait()
}

// Wait awaits for the task to end, and returns the error (or nil) of the execution
// Returns:
// - TaskResult, nil: the Task ended normally and provide a Result
// - TaskResult, *fail.ErrAborted: the Task has been aborted; *fail.ErrAborted.Consequences() may contain error(s) happening after the signal has been received by the Task
// - TaskResult, *fail.ErrTimeout: the Task has reached its execution timeout
// - TaskResult, <other error>: the Task runs successfully but returned an error
func (instance *task) Wait() (TaskResult, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	traceR := newTracer(instance, tracing.ShouldTrace("concurrency.task"))

	instance.lock.RLock()
	tid := instance.id
	status := instance.status
	instance.lock.RUnlock() // nolint

	for {
		switch status {
		case READY: // Waiting a ready task always succeed by design
			return nil, fail.InconsistentError("cannot wait a Task that has not been started")

		case TIMEOUT:
			instance.lock.RLock()
			runTerminated := instance.runTerminated
			instance.lock.RUnlock() // nolint

			<-instance.controllerTerminatedCh // Note: DO NOT PUT this inside a lock (blocking channel write, unbuffered channel)

			instance.lock.Lock()
			var forgedError fail.Error
			if instance.err != nil {
				switch instance.err.(type) {
				case *fail.ErrAborted:
					forgedError = fail.TimeoutError(nil, 0)
					_ = forgedError.AddConsequence(instance.err)
				case *fail.ErrTimeout:
					forgedError = instance.err
				default:
					if !runTerminated {
						forgedError = fail.TimeoutError(nil, 0)
						_ = forgedError.AddConsequence(instance.err)
					}
				}
			} else if !runTerminated {
				forgedError = fail.TimeoutError(nil, 0)
			}
			instance.err = forgedError
			if runTerminated {
				instance.status, status = DONE, DONE
			}
			instance.lock.Unlock() // Note: Do not defer this, the loop continue

		case ABORTED:
			instance.lock.RLock()
			runTerminated := instance.runTerminated
			instance.lock.RUnlock() // nolint

			<-instance.controllerTerminatedCh // Note: DO NOT PUT this inside a lock (blocking channel write, unbuffered channel)

			instance.lock.Lock()
			// In case of ABORT, if an error is already there, the Task has ended, so just return this error with the result
			if instance.err != nil {
				switch instance.err.(type) {
				case *fail.ErrAborted, *fail.ErrTimeout:
					// leave the abort or timeout error alone
					break
				default:
					if !runTerminated {
						// return abort error with instance.err as consequence (happened after Abort has been acknowledged by TaskAction)
						forgedError := fail.AbortedError(nil)
						_ = forgedError.AddConsequence(instance.err)
						instance.err = forgedError
					}
				}
			}
			if runTerminated {
				instance.status, status = DONE, DONE
			}
			instance.lock.Unlock() // Note: Do not defer this, the loop continue

		case RUNNING:
			instance.lock.Lock()
			runTerminated := instance.runTerminated
			instance.lock.Unlock() // nolint

			<-instance.controllerTerminatedCh

			// Reload status, it may have changed since the controller terminated
			instance.lock.Lock()
			status = instance.status
			if status == RUNNING || runTerminated {
				instance.status, status = DONE, DONE
			}
			instance.lock.Unlock() // nolint

		case DONE:
			instance.lock.Lock()
			traceR.trace("run lasted %v, controller lasted %v\n", instance.stats.runDuration, instance.stats.controllerDuration)
			if instance.resultObtained {
				//goland:noinspection GoDeferInLoop
				defer instance.lock.Unlock() // Note: we can defer here, we will abort the loop

				if instance.ctx.Err() != nil {
					if instance.err == nil {
						instance.err = fail.AbortedError(instance.ctx.Err())
					}
				}
				return instance.result, instance.err
			}

			instance.lock.Unlock() // nolint
			// result not returned by TaskAction yet, continue

		case UNKNOWN:
			fallthrough
		default:
			return nil, fail.InconsistentError("cannot wait task '%s': unknown status (%s)", tid, status)
		}
	}
}

// contextCleanup trigger cancel func if needed
// WARNING! must be called inside instance.lock.RLock!
func (instance *task) contextCleanup() {
	if instance.cancel != nil {
		instance.cancel()
		instance.cancel = nil
	}
}

// TryWait tries to wait on a task
// If task done, returns (true, TaskResult, <error from the task>)
// If task is not done, returns (false, nil, nil) (subsequent calls of TryWait may be necessary)
// if Task is not started, returns (false, nil, *fail.ErrInconsistent)
func (instance *task) TryWait() (bool, TaskResult, fail.Error) {
	if valid.IsNil(instance) {
		return false, nil, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	tid := instance.id
	status := instance.status
	instance.lock.RUnlock() // nolint

	switch status {
	case READY: // Waiting a ready task always succeed by design
		return false, nil, fail.InconsistentError("cannot wait task '%s': has not been started", tid)

	case DONE:
		instance.lock.Lock()
		defer instance.lock.Unlock()

		if instance.resultObtained {
			if instance.ctx.Err() != nil && instance.err == nil {
				instance.err = fail.AbortedError(instance.ctx.Err())
			}
			return true, instance.result, instance.err
		}

		// result has not been returned yet by TaskAction
		return false, nil, nil

	case ABORTED:
		fallthrough
	case TIMEOUT:
		fallthrough
	case RUNNING:
		if len(instance.controllerTerminatedCh) == 1 {
			result, err := instance.Wait()
			return true, result, err
		}
		return false, nil, nil

	case UNKNOWN:
		fallthrough
	default:
		return false, nil, fail.NewError("cannot wait task '%s': unknown status (%s)", tid, status)
	}
}

// WaitFor waits for the task to end, for 'duration' duration.
// Note: if timeout occurred, the task is not aborted. You have to abort then wait for it explicitly if needed.
// - true, TaskResult, fail.Error: Task terminates, but TaskAction returned an error
// - true, TaskResult, *failErrAborted: Task terminates on Abort
// - false, nil, *fail.ErrTimeout: WaitFor has timed out; Task is aborted in this case (and eventual error after
//                                 abort signal has been received would be attached to the error as consequence)
func (instance *task) WaitFor(duration time.Duration) (_ bool, _ TaskResult, ferr fail.Error) {
	if valid.IsNil(instance) {
		return false, nil, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	tid := instance.id
	status := instance.status
	instance.lock.RUnlock() // nolint

	switch status {
	case READY: // Waiting a ready task always succeed by design
		return false, nil, fail.InconsistentError("cannot wait a Task that has not be started")

	case DONE:
		instance.lock.Lock()
		defer instance.lock.Unlock()

		if instance.resultObtained {
			if instance.ctx.Err() != nil && instance.err == nil {
				instance.err = fail.AbortedError(instance.ctx.Err())
			}
			return true, instance.result, instance.err
		}

		return false, nil, fail.InconsistentError("done task has not returned the result")

	case ABORTED:
		fallthrough
	case TIMEOUT:
		fallthrough
	case RUNNING:
		if duration > 0 {
			doneWaitingCh := make(chan struct{}, 1)
			waiterTask, xerr := NewTask()
			if xerr != nil {
				return false, nil, fail.Wrap(xerr, "failed to create helper Task to WaitFor")
			}
			var result TaskResult
			_, xerr = waiterTask.Start(
				func(t Task, _ TaskParameters) (_ TaskResult, innerXErr fail.Error) {
					var done bool
					for !t.Aborted() && !done {
						done, result, innerXErr = instance.TryWait()
						if innerXErr != nil {
							logrus.Warnf("ignoring internal error: %v", innerXErr)
						}
						if !done {
							time.Sleep(100 * time.Microsecond) // FIXME: hardcoded value :-(
						}
					}
					if done {
						doneWaitingCh <- struct{}{}
						return nil, nil
					}
					return nil, fail.AbortedError(nil)
				}, nil,
			)
			if xerr != nil {
				return false, result, xerr
			}

			select {
			case <-doneWaitingCh:
				result, iwerr := instance.Wait()
				return true, result, iwerr

			case <-time.After(duration):
				// signal waiterTask to abort (and do not wait for it, it will terminate)
				waiterTask.(*task).forceAbort()

				tout := fail.TimeoutError(xerr, duration, "timeout of %s waiting for Task '%s'", duration, tid)
				instance.lock.RLock()
				defer instance.lock.RUnlock()

				return false, instance.result, tout
			}
		} else {
			// No duration, do task.Wait()
			result, xerr := instance.Wait()
			return true, result, xerr
		}

	case UNKNOWN:
		fallthrough
	default:
		return false, nil, fail.NewError("cannot wait Task '%s': unknown status (%s)", tid, status)
	}
}

// Abort aborts the task execution if running and marks it as ABORTED unless it's already DONE.
// A call of this method does not actually stop the running task if there is one; a subsequent
// call of Wait() may still be needed, it's still the responsibility of the executed code in task to stop
// early on Abort.
// returns:
// - *fail.ErrInvalidInstanceError: called from nil
// - *fail.ErrNotAvailable: abort signal is disabled
// - *fail.ErrInvalidRequest: trying to abort on a task not started
// - nil: Abort signal sent successfully
//
// Note: a TaskAction, when .Aborted() returns true, _MUST_ return an error to signify its end on Abort (it does not have
// to be a fail.AbortedError(), but cannot be nil).
func (instance *task) Abort() (err fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	status := instance.status
	tid := instance.id
	abortDisarmed := instance.abortDisengaged
	instance.lock.RUnlock() // nolint

	// If abort signal is disengaged, return an error
	if abortDisarmed {
		return fail.NotAvailableError("abort signal is disengaged on task %s", tid)
	}

	// If Task is not started, nothing to Abort, fail.
	if status == READY {
		return fail.InvalidRequestError("abort signal cannot be used, Task is not started")
	}

	// force abort when something is started
	instance.forceAbort()
	instance.lock.Lock()
	defer instance.lock.Unlock()
	instance.err = fail.AbortedError(nil)
	return nil
}

func (instance *task) AbortWithCause(cerr fail.Error) (err fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	status := instance.status
	tid := instance.id
	abortDisarmed := instance.abortDisengaged
	instance.lock.RUnlock() // nolint

	// If abort signal is disengaged, return an error
	if abortDisarmed {
		return fail.NotAvailableError("abort signal is disengaged on task %s", tid)
	}

	// If Task is not started, nothing to Abort, fail.
	if status == READY {
		return fail.InvalidRequestError("abort signal cannot be used, Task is not started")
	}

	// force abort when something is started
	instance.forceAbort()
	instance.lock.Lock()
	instance.err = fail.AbortedError(cerr)
	instance.lock.Unlock() // nolint
	return nil
}

// forceAbort is the weaponized arm of Abort(), that does the job without taking care if abort signal is disarmed
func (instance *task) forceAbort() {
	instance.lock.Lock()
	status := instance.status
	instance.abortDisengaged = false // If we want to force abort, we MUST make sure the signal can be received
	instance.lock.Unlock()           // nolint

	switch status {
	case RUNNING:
		// Tell controller to stop goroutine
		instance.abortCh <- struct{}{} // VPL: Do not put this inside a lock
		instance.lock.Lock()
		instance.status = ABORTED
		instance.lock.Unlock() // nolint

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
}

// Aborted tells if the task is aborted (by cancel(), by Abort() or by timeout)
// As a Task is actually a go routine, and there is no way to safely stop a go routine from outside, the code running in
// the Task has to check regularly if Task has been aborted and stop execution (return...) as soon as possible
// (leaving place for cleanup if needed). Without the use of Aborted(), a task may run indefinitely.
func (instance *task) Aborted() bool {
	if valid.IsNil(instance) {
		return false
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	// If abort signal is disarmed, return false not to react on abort signal despite the internal status of the Task
	if instance.abortDisengaged {
		return false
	}

	switch instance.status {
	case ABORTED:
		fallthrough
	case TIMEOUT:
		return true

	case DONE:
		switch instance.err.(type) {
		case *fail.ErrAborted, *fail.ErrTimeout:
			return true
		default:
			return false
		}

	case READY:
		fallthrough
	case RUNNING:
		fallthrough
	case UNKNOWN:
		fallthrough
	default:
		return false
	}
}

// Abortable tells if task can be aborted
func (instance *task) Abortable() (bool, fail.Error) {
	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return !instance.abortDisengaged, nil
}

// DisarmAbortSignal disables the effect of Abort()
// Typically, it is advised to call this inside a defer statement when cleanup things (cleanup has to terminate; if abort signal is not disarmed, any
// call with task as parameter may abort before the end.
// Returns a function to rearm the signal handling
// If on call the abort signal is already disarmed, does nothing and returned function does nothing also.
// If on call the abort signal is not disarmed, disarms it and returned function will rearm it.
// Note: the disarm state is not propagated to subtasks. It's possible to disarm abort signal in a task and want to Abort() explicitly a subtask.
func (instance *task) DisarmAbortSignal() func() {
	if valid.IsNil(instance) {
		logrus.Errorf("task.DisarmAbortSignal() called from nil; ignored.") // FIXME: return error
		return func() {}
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	if !instance.abortDisengaged {
		// Disengage Abort signal
		instance.abortDisengaged = true

		// Return a func that reengage abort signal
		return func() {
			if valid.IsNil(instance) {
				return
			}

			instance.lock.Lock()
			defer instance.lock.Unlock()

			instance.abortDisengaged = false
		}
	}

	// If abort signal is already disengaged, does nothing and returns a func that does nothing also
	return func() {}
}
