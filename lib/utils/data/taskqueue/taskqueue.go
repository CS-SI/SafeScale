/*
* Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package taskqueue

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type TaskQueue struct {
	queue      []TaskItem
	size       uint
	handlers   map[string][]chan uint
	processing bool
	mu         *sync.RWMutex
}

type TaskItem struct {
	function func() (interface{}, fail.Error)
	callback chan TaskResult
	timeout  time.Duration
}

type TaskResult struct {
	data interface{}
	err  fail.Error
}

func CreateTaskQueue(size uint) *TaskQueue {
	return &TaskQueue{
		queue:      make([]TaskItem, 0),
		size:       size,
		processing: false,
		mu:         &sync.RWMutex{},
		handlers:   make(map[string][]chan uint),
	}
}

// Push add a task todo in taskqueue
func (e *TaskQueue) Push(f func() (interface{}, fail.Error), timeout time.Duration) (interface{}, fail.Error) {

	task := TaskItem{
		function: f,
		callback: make(chan TaskResult, 1),
		timeout:  timeout,
	}

	go func(e *TaskQueue, task TaskItem) {

		// Queue new task to do
		e.mu.Lock()
		if len(e.queue) >= int(e.size) {
			e.mu.Unlock() // nolint
			task.callback <- TaskResult{
				data: nil,
				err:  fail.OverflowError(fmt.Errorf("task queue overflow (limit at %d)", e.size), e.size, ""),
			}
		} else {
			e.queue = append(e.queue, task)
			if !e.processing {
				e.processing = true
				defer e.processLoop()
			}
			e.mu.Unlock() // nolint
		}

	}(e, task)

	// Avoid useless updates, func scope is significant
	return func(result TaskResult) (interface{}, fail.Error) {
		return result.data, result.err
	}(<-task.callback)

}

// Size returns max size of task queue
func (e *TaskQueue) Size() uint {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.size
}

// Length returns current size of task queue
func (e *TaskQueue) Length() uint {
	// queue updated by slice trunk, Rlock does not lock slice read,
	// but queue replace => makes late update with deprecated data
	e.mu.RLock()
	defer e.mu.RUnlock()

	return uint(len(e.queue))
}

// Drain returns when taskqueue is empty
func (e *TaskQueue) Drain() {
	length := e.Length()
	if length > 0 {
		ch := make(chan uint)
		go func(e *TaskQueue, ch chan uint) {
			e.mu.Lock()
			_, ok := e.handlers["drain"]
			if !ok {
				e.handlers["drain"] = make([]chan uint, 0)
			}
			e.handlers["drain"] = append(e.handlers["drain"], ch)
			e.mu.Unlock() // nolint
		}(e, ch)
		<-ch
	}
}

// unsafeDrain called when queue is empty
func (e *TaskQueue) unsafeDrain() {
	// Drain
	_, ok := e.handlers["drain"]
	if ok && len(e.handlers["drain"]) > 0 {
		for i := range e.handlers["drain"] {
			ch := e.handlers["drain"][i]
			e.handlers["drain"][i] <- 0
			close(ch)
		}
		delete(e.handlers, "drain")
	}
	// End of process
	e.processing = false
}

// Taskqueue processing
func (e *TaskQueue) processLoop() {

	var (
		length int
		task   TaskItem
	)

	// Check if queue has at least one item
	e.mu.Lock()
	length = len(e.queue)
	if length <= 0 {
		e.unsafeDrain()
		e.mu.Unlock() // nolint
		return
	}
	// Get next item to process
	task = e.queue[0]
	if length > 1 {
		e.queue = e.queue[1:]
	} else {
		e.queue = make([]TaskItem, 0)
	}
	e.mu.Unlock() // nolint

	// Run tasks
	task.callback <- func() TaskResult {
		done := make(chan TaskResult)
		go func(done chan TaskResult) {
			defer close(done)
			data, err := task.function()
			result := TaskResult{data: data, err: err}
			done <- result
		}(done)
		select {
		case <-time.After(task.timeout):
			return TaskResult{data: nil, err: fail.TimeoutError(errors.New("task timeout"), task.timeout, "")}
		case result := <-done:
			return result
		}
	}()

	// Loop
	defer e.processLoop()

}
