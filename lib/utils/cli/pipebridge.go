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

package cli

import (
	"bufio"
	"io"
	"os"

	"github.com/CS-SI/SafeScale/v21/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

// Printer ...
type Printer interface {
	Print(interface{})
}

// PipeBridge ...
type PipeBridge interface {
	Printer
	Reader() io.ReadCloser
}

type coreBridge struct {
	pipe io.ReadCloser
}

func (cb coreBridge) Reader() io.ReadCloser {
	return cb.pipe
}

// StdoutBridge is a PipeBridge outputting on stdout
type StdoutBridge struct {
	coreBridge
}

// NewStdoutBridge creates an PipeBridge from a bufio.ReadCloser
func NewStdoutBridge(pipe io.ReadCloser) (*StdoutBridge, fail.Error) {
	if pipe == nil {
		return nil, fail.InvalidParameterCannotBeNilError("pipe")
	}
	sp := StdoutBridge{
		coreBridge: coreBridge{
			pipe: pipe,
		},
	}
	return &sp, nil
}

// Print outputs the string to stdout
func (outp *StdoutBridge) Print(data interface{}) {
	_, err := io.WriteString(os.Stdout, data.(string))
	if err != nil {
		debug.IgnoreError(err)
	}
}

// StderrBridge is a OutputPipe outputting on stderr
type StderrBridge struct {
	coreBridge
}

// NewStderrBridge creates a pipe displaying on stderr
func NewStderrBridge(pipe io.ReadCloser) (*StderrBridge, fail.Error) {
	if pipe == nil {
		return nil, fail.InvalidParameterCannotBeNilError("pipe")
	}
	sp := StderrBridge{
		coreBridge: coreBridge{
			pipe: pipe,
		},
	}
	return &sp, nil
}

// Print outputs the string to stderr
func (errp *StderrBridge) Print(data interface{}) {
	_, err := io.WriteString(os.Stderr, data.(string))
	if err != nil {
		debug.IgnoreError(err)
	}
}

// PipeBridgeController is the controller of the bridges of pipe
type PipeBridgeController struct {
	// taskGroup concurrency.Task
	count        uint
	bridges      []PipeBridge
	displayTask  concurrency.Task
	displayCh    chan outputItem
	readersGroup concurrency.TaskGroup
}

// NewPipeBridgeController creates a new controller of bridges of pipe
func NewPipeBridgeController(bridges ...PipeBridge) (*PipeBridgeController, fail.Error) {
	if bridges == nil {
		return nil, fail.InvalidParameterCannotBeNilError("pipes")
	}

	var validatedBridges []PipeBridge
	for _, v := range bridges {
		if v != nil {
			validatedBridges = append(validatedBridges, v)
		}
	}
	count := uint(len(validatedBridges))
	if count == 0 {
		return nil, fail.InvalidRequestError("no pipe to bridge")
	}

	ob := PipeBridgeController{bridges: validatedBridges, count: count}
	return &ob, nil
}

// Start initiates the capture of pipe outputs and the display of what is captured
func (pbc *PipeBridgeController) Start(task concurrency.Task) fail.Error {
	if pbc == nil {
		return fail.InvalidInstanceError()
	}
	if pbc.bridges == nil {
		return fail.InvalidInstanceContentError("pbc.bridges", "cannot be nil")
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	pipeCount := uint(len(pbc.bridges))
	// if no pipes, do nothing
	if pipeCount == 0 {
		return nil
	}

	// First starts the "displayer" routine...
	var xerr fail.Error
	if pbc.displayTask, xerr = concurrency.NewTaskWithParent(task); xerr != nil {
		return xerr
	}

	pbc.displayCh = make(chan outputItem, pipeCount)
	if _, xerr = pbc.displayTask.Start(taskDisplay, taskDisplayParameters{ch: pbc.displayCh}); xerr != nil {
		return xerr
	}

	// ... then starts the "pipe readers"
	taskGroup, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID("/pipebridges"))
	if xerr != nil {
		return xerr
	}

	for _, v := range pbc.bridges {
		if _, xerr = taskGroup.Start(taskRead, taskReadParameters{bridge: v, ch: pbc.displayCh}); xerr != nil {
			return xerr
		}
	}
	pbc.readersGroup = taskGroup
	return nil
}

type outputItem struct {
	bridge PipeBridge
	data   string
}

// Print displays the message contained by the instance using the pipe displayer
func (oi outputItem) Print() {
	oi.bridge.Print(oi.data)
}

// Structure to store taskRead parameters
type taskReadParameters struct {
	bridge PipeBridge
	ch     chan<- outputItem
}

// taskRead reads data from pipe and sends it to the goroutine in charge of displaying it on the right "file descriptor" (stdout or stderr)
func taskRead(task concurrency.Task, p concurrency.TaskParameters) (_ concurrency.TaskResult, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	if p == nil {
		return nil, fail.InvalidParameterCannotBeNilError("p")
	}

	params, ok := p.(taskReadParameters)
	if !ok {
		return nil, fail.InvalidParameterError("p", "must be a 'taskReadParameters'")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("cli")).WithStopwatch().Entering()
	defer tracer.Exiting()

	// bufio.Scanner.Scan() may panic...
	scanner := bufio.NewScanner(params.bridge.Reader())
	scanner.Split(bufio.ScanLines)

	var err error
	for {
		// If task aborted, stop the loop
		if task.Aborted() {
			err = fail.AbortedError(nil, "aborted")
			break
		}

		if scanner.Scan() {
			item := outputItem{
				bridge: params.bridge,
				data:   scanner.Text() + "\n",
			}
			params.ch <- item
		} else {
			err = scanner.Err()
			break
		}
	}
	if err != nil {
		if err == io.EOF {
			err = nil
		} else {
			switch err.(type) { // nolint
			// case fail.ErrAborted, *os.PathError:
			case *os.PathError:
				err = nil
			}
		}
	}
	return nil, fail.ConvertError(err)
}

// Structure to store taskRead parameters
type taskDisplayParameters struct {
	ch <-chan outputItem
}

func taskDisplay(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	p, ok := params.(taskDisplayParameters)
	if !ok {
		return nil, fail.InvalidParameterError("p", "must be a 'taskDisplayParameters'")
	}
	for item := range p.ch {
		item.Print()
	}
	return nil, nil
}

// Wait waits the end of the goroutines
func (pbc *PipeBridgeController) Wait() fail.Error {
	if pbc == nil {
		return fail.InvalidInstanceError()
	}
	if pbc.displayTask == nil {
		return fail.InvalidInstanceContentError("pbc.displayTask", "cannot be nil")
	}
	if pbc.readersGroup == nil {
		return fail.InvalidInstanceContentError("pbc.readersGroup", "cannot be nil")
	}

	_, xerr := pbc.readersGroup.WaitGroup()
	close(pbc.displayCh)
	if xerr != nil {
		return xerr
	}

	_, xerr = pbc.displayTask.Wait()
	return xerr
}

// Stop the captures and the display.
func (pbc *PipeBridgeController) Stop() fail.Error {
	if pbc == nil {
		return fail.InvalidInstanceError()
	}
	if pbc.count == 0 {
		return nil
	}
	if pbc.readersGroup == nil {
		return fail.InvalidInstanceContentError("pbc.readersGroup", "cannot be nil")
	}

	// Try to wait the end of the task group
	ok, _, xerr := pbc.readersGroup.TryWaitGroup()
	if xerr != nil {
		return xerr
	}
	if !ok {
		// If not done, abort it and wait until the end
		_ = pbc.readersGroup.Abort()
		if xerr = pbc.Wait(); xerr != nil {
			// In case of error, report only if error is not aborted error, as we triggered it
			switch xerr.(type) {
			case *fail.ErrAborted:
				// do nothing
				debug.IgnoreError(xerr)
			default:
				return xerr
			}
		}
	}

	*pbc = PipeBridgeController{}
	return nil
}
