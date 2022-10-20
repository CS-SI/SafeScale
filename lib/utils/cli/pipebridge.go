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
	"context"
	"io"
	"os"

	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"golang.org/x/sync/errgroup"
)

//go:generate minimock -o mocks/mock_printer.go -i github.com/CS-SI/SafeScale/v22/lib/utils/cli.Printer

// Printer ...
type Printer interface {
	Print(interface{})
}

//go:generate minimock -o mocks/mock_pipebridge.go -i github.com/CS-SI/SafeScale/v22/lib/utils/cli.PipeBridge

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
	count        uint
	bridges      []PipeBridge
	displayTask  *errgroup.Group
	displayCh    chan outputItem
	readersGroup *errgroup.Group
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
func (pbc *PipeBridgeController) Start(inctx context.Context) fail.Error {
	if pbc == nil {
		return fail.InvalidInstanceError()
	}
	if pbc.bridges == nil {
		return fail.InvalidInstanceContentError("pbc.bridges", "cannot be nil")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			pipeCount := uint(len(pbc.bridges))
			// if no pipes, do nothing
			if pipeCount == 0 {
				return nil
			}

			// First starts the "displayer" routine...
			displayGroup := new(errgroup.Group)
			pbc.displayTask = displayGroup

			pbc.displayCh = make(chan outputItem, pipeCount)
			displayGroup.Go(
				func() error {
					_, xerr := taskDisplay(ctx, taskDisplayParameters{ch: pbc.displayCh})
					return xerr
				})

			taskGroup := new(errgroup.Group)
			pbc.readersGroup = taskGroup

			// ... then starts the "pipe readers"

			for _, v := range pbc.bridges {
				taskGroup.Go(func() error {
					_, xerr := taskRead(ctx, taskReadParameters{bridge: v, ch: pbc.displayCh})
					return xerr
				})
			}
			return nil
		}()
		chRes <- result{gerr}
	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}

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
func taskRead(inctx context.Context, p concurrency.TaskParameters) (_ concurrency.TaskResult, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rRes concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, gerr := func() (_ concurrency.TaskResult, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if p == nil {
				return nil, fail.InvalidParameterCannotBeNilError("p")
			}

			params, ok := p.(taskReadParameters)
			if !ok {
				return nil, fail.InvalidParameterError("p", "must be a 'taskReadParameters'")
			}

			tracer := debug.NewTracer(ctx, tracing.ShouldTrace("cli")).WithStopwatch().Entering()
			defer tracer.Exiting()

			// bufio.Scanner.Scan() may panic...
			scanner := bufio.NewScanner(params.bridge.Reader())
			scanner.Split(bufio.ScanLines)

			var err error
			for {
				// If task aborted, stop the loop
				select {
				case <-ctx.Done():
					err = fail.AbortedError(ctx.Err())
				default:
				}
				if err != nil {
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

		}()
		chRes <- result{gres, gerr}
	}()
	select {
	case res := <-chRes:
		return res.rRes, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

// Structure to store taskRead parameters
type taskDisplayParameters struct {
	ch <-chan outputItem
}

func taskDisplay(inctx context.Context, params concurrency.TaskParameters) (_ concurrency.TaskResult, ferr fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		tRes concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, gerr := func() (_ concurrency.TaskResult, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			p, ok := params.(taskDisplayParameters)
			if !ok {
				return nil, fail.InvalidParameterError("p", "must be a 'taskDisplayParameters'")
			}
			for item := range p.ch {
				item.Print()
			}
			return nil, nil

		}()
		chRes <- result{gres, gerr}
	}()
	select {
	case res := <-chRes:
		return res.tRes, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
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

	xerr := fail.ConvertError(pbc.readersGroup.Wait())
	close(pbc.displayCh)
	if xerr != nil {
		return xerr
	}

	xerr = fail.ConvertError(pbc.displayTask.Wait())
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
	xerr := fail.ConvertError(pbc.readersGroup.Wait())
	if xerr != nil {
		return xerr
	}

	*pbc = PipeBridgeController{}
	return nil
}
