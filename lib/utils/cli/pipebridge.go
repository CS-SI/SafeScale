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

package cli

import (
	"bufio"
	"context"
	"io"
	"os"

	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
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
func (pbc *PipeBridgeController) Start(ctx context.Context) fail.Error {
	if pbc == nil {
		return fail.InvalidInstanceError()
	}
	if pbc.bridges == nil {
		return fail.InvalidInstanceContentError("pbc.bridges", "cannot be nil")
	}

	select {
	case <-ctx.Done():
		return fail.AbortedError(ctx.Err())
	default:
	}

	pipeCount := uint(len(pbc.bridges))
	// if no pipes, do nothing
	if pipeCount == 0 {
		return nil
	}

	// First starts the "displayer" routine...
	pbc.displayTask = new(errgroup.Group)

	pbc.displayCh = make(chan outputItem, pipeCount)
	pbc.displayTask.Go(func() error {
		_, err := taskDisplay(ctx, taskDisplayParameters{ch: pbc.displayCh})
		return err
	})

	// ... then starts the "pipe readers"
	taskGroup := new(errgroup.Group)

	for _, v := range pbc.bridges {
		v := v
		taskGroup.Go(func() error {
			_, err := taskRead(ctx, taskReadParameters{bridge: v, ch: pbc.displayCh})
			return err
		})
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
func taskRead(ctx context.Context, p taskReadParameters) (_ interface{}, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	select {
	case <-ctx.Done():
		return nil, fail.AbortedError(ctx.Err())
	default:
	}

	// bufio.Scanner.Scan() may panic...
	scanner := bufio.NewScanner(p.bridge.Reader())
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
				bridge: p.bridge,
				data:   scanner.Text() + "\n",
			}
			p.ch <- item
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

func taskDisplay(ctx context.Context, params taskDisplayParameters) (_ interface{}, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	select {
	case <-ctx.Done():
		return nil, fail.AbortedError(ctx.Err())
	default:
	}

	for item := range params.ch {
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
