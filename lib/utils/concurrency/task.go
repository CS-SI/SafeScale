package concurrency

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/satori/go.uuid"
)

//go:generate mockgen -destination=../mocks/mock_taskrunner.go -package=mocks github.com/CS-SI/SafeScale/lib/utils/concurrency TaskRunner

// TaskRunner ...
type TaskRunner interface {
	ID() string
	Task() Task
	Done()
	Fail(error)
	StoreResult(interface{})
}

type taskRunner struct {
	task       *task
	resultSent bool
	errorSent  bool
	endSent    bool
}

// ID ...
func (tr *taskRunner) ID() string {
	return tr.task.ID()
}

// Task ...
func (tr *taskRunner) Task() Task {
	return tr.task
}

// Cancel aborts the task execution
func (tr *taskRunner) Cancel() {
	tr.task.cancel()
}

// Done signs the end of the task
func (tr *taskRunner) Done() {
	tr.task.errorCh <- nil
	tr.errorSent = true
	tr.task.doneCh <- true
	tr.endSent = true
}

// Fail is like Done but with error
func (tr *taskRunner) Fail(err error) {
	tr.task.errorCh <- err
	tr.errorSent = true
	tr.task.doneCh <- true
	tr.endSent = true
}

// StoreResult stores the result of the run
func (tr *taskRunner) StoreResult(result interface{}) {
	if tr.resultSent {
		panic("Can't TaskRunner::StoreResult() multiple times!")
	}
	if tr.errorSent || tr.endSent {
		panic("can't TaskRunner::StoreResult() after TaskRunner::Done() or TaskRunner::Fail() have been called!")
	}
	tr.task.resultCh <- result
	tr.resultSent = true
}

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
)

// TaskFunc ...
type TaskFunc func(tr TaskRunner, parameters interface{})

//go:generate mockgen -destination=../mocks/mock_task.go -package=mocks github.com/CS-SI/SafeScale/lib/utils/concurrency Task

// Task ...
type Task interface {
	ID() string
	ForceID(string)
	Context() context.Context
	Start(interface{}) Task
	Wait()
	Run(interface{}) error
	Reset()
	GetStatus() TaskStatus
	GetError() error
	GetResult() interface{}
}

// task is a structure allowing to identify (indirectly) goroutines
type task struct {
	lock     *sync.Mutex
	id       string
	fn       TaskFunc
	ctx      context.Context
	cancel   context.CancelFunc
	status   TaskStatus
	cleanRun bool

	resultCh chan interface{}
	errorCh  chan error
	doneCh   chan bool

	done   bool
	err    error
	result interface{}
}

var globalTask atomic.Value

// RootTask is the task is a "task to rule them all"
func RootTask() Task {
	anon := globalTask.Load()
	if anon == nil {
		fn := func(tr TaskRunner, params interface{}) {
			tr.Done()
			return
		}

		newT := newTask(nil, fn)
		newT.id = "0"
		globalTask.Store(newT)
		anon = globalTask.Load()
	}
	return anon.(Task)
}

// VoidTask is a new task that do nothing
func VoidTask() Task {
	return NewTask(nil, nil)
}

// NewTask ...
func NewTask(parentTask Task, fn TaskFunc) Task {
	return newTask(parentTask, fn)
}

func newTask(parentTask Task, fn TaskFunc) *task {
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)

	if parentTask == nil {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithCancel(parentTask.Context())
	}
	return &task{
		lock:   &sync.Mutex{},
		fn:     fn,
		ctx:    ctx,
		cancel: cancel,
		status: READY,
	}
}

// Context returns the context.Context used by task
func (t *task) Context() context.Context {
	return t.ctx
}

// ID returns an unique id for the task
func (t *task) ID() string {
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.id == "" {
		u, err := uuid.NewV4()
		if err != nil {
			panic(fmt.Sprintf("failed to create a new task: %v", err))
		}
		t.id = u.String()
	}
	return t.id
}

// ForceID allows to specify task ID. The unicity of the ID through all the tasks
// becomes the responsability of the developer...
func (t *task) ForceID(id string) {
	if id == "" {
		panic("Invalid parameter 'id': can't be empty string!")
	}
	if id == "0" {
		panic("Invalid parameter 'id': can't be '0': reserved for root task!")
	}
	t.lock.Lock()
	defer t.lock.Unlock()

	t.id = id
}

// Start runs in goroutine the function with parameters
func (t *task) Start(params interface{}) Task {
	if t.status != READY {
		panic(fmt.Sprintf("Can't start task '%s': not ready!", t.ID()))
	}
	if t.fn == nil {
		t.status = DONE
	}
	t.resultCh = make(chan interface{}, 1)
	t.errorCh = make(chan error, 1)
	t.doneCh = make(chan bool, 1)
	t.status = RUNNING
	go t.wrapper(params)
	return t
}

func (t *task) wrapper(params interface{}) {
	tr := &taskRunner{task: t}
	t.fn(tr, params)
	if !tr.resultSent {
		tr.task.resultCh <- nil
	}
	if !tr.errorSent {
		tr.task.errorCh <- nil
	}
	if !tr.endSent {
		tr.task.doneCh <- true
	}
}

func (t *task) Wait() {
	if t.status != RUNNING {
		panic(fmt.Sprintf("Can't wait task '%s': not running!", t.ID()))
	}
	t.result = <-t.resultCh
	t.err = <-t.errorCh
	<-t.doneCh
	t.status = DONE
}

// Run starts task, waits its completion then return the error code
func (t *task) Run(params interface{}) error {
	t.Start(params)
	t.Wait()
	return t.GetError()
}

func (t *task) TryWait(duration time.Duration) error {
	if t.status != RUNNING {
		panic(fmt.Sprintf("Can't wait task '%s': not running!", t.ID()))
	}
	select {
	case <-t.doneCh:
		t.status = DONE
		return nil
	case <-time.After(duration):
		return utils.TimeoutError(fmt.Sprintf("timeout waiting for task '%s'", t.ID()))
	}
}

func (t *task) Reset() {
	if t.status == RUNNING {
		panic(fmt.Sprintf("Can't reset task '%s': task running!", t.ID()))
	}
	t.status = READY
	t.err = nil
	t.result = nil
}

func (t *task) closeChannels() {
	close(t.doneCh)
	close(t.resultCh)
	close(t.errorCh)
}

// GetStatus tells the status of the task
func (t *task) GetStatus() TaskStatus {
	return t.status
}

// GetError gets the error sent by the done task
func (t *task) GetError() error {
	if t.status == READY {
		panic("Can't get error of task '%s': task not started!")
	}
	if t.status != DONE {
		panic("Can't get error of task '%s': task not done!")
	}
	return t.err
}

func (t *task) GetResult() interface{} {
	if t.status == READY {
		panic("Can't get result of task '%s': task not started!")
	}
	if t.status != DONE {
		panic("Can't get result of task '%s': task not done!")
	}
	return t.result
}
