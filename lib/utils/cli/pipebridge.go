package cli

import (
	"bufio"
	"io"
	"os"

	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
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
		return nil, fail.InvalidParameterError("pipe", "cannot be nil")
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
	_, _ = io.WriteString(os.Stdout, data.(string))
}

// StderrBridge is a OutputPipe outputting on stderr
type StderrBridge struct {
	coreBridge
}

// NewStderrBridge creates a pipe displaying on stderr
func NewStderrBridge(pipe io.ReadCloser) (*StderrBridge, fail.Error) {
	if pipe == nil {
		return nil, fail.InvalidParameterError("pipe", "cannot be nil")
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
	_, _ = io.WriteString(os.Stderr, data.(string))
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
		return nil, fail.InvalidParameterError("pipes", "cannot be nil")
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
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
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
	if _, xerr = pbc.displayTask.Start(taskDisplay, pbc.displayCh); xerr != nil {
		return xerr
	}

	// ... then starts the "pipe readers"
	taskGroup, xerr := concurrency.NewTaskGroup(task)
	if xerr != nil {
		return xerr
	}
	for _, v := range pbc.bridges {
		if _, xerr = taskGroup.Start(taskRead, readParameters{bridge: v, ch: pbc.displayCh}); xerr != nil {
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
type readParameters struct {
	bridge PipeBridge
	ch     chan<- outputItem
}

// taskRead reads data from pipe and sends it to the goroutine in charge of displaying it on the right "file descriptor" (stdout or stderr)
func taskRead(t concurrency.Task, p concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	if p == nil {
		return nil, fail.InvalidParameterError("p", "cannot be nil")
	}

	params, ok := p.(readParameters)
	if !ok {
		return nil, fail.InvalidParameterError("p", "must be a 'readParameters'")
	}

	// var (
	// 	bridge    PipeBridge
	// 	displayCh chan<- outputItem
	// )
	//
	// if bridge, ok = params["bridge"].(PipeBridge); !ok {
	// 	return nil, fail.InvalidParameterError("params['bridge']", "must be a PipeBridge")
	// }
	// if bridge == nil {
	// 	return nil, fail.InvalidParameterError("params['bridge']", "cannot be nil")
	// }
	// if displayCh, ok = params["displayCh"].(chan<- outputItem); !ok {
	// 	return nil, fail.InvalidParameterError("params['displayCh']", "must be a 'chan<- outputItem'")
	// }

	tracer := debug.NewTracer(t, tracing.ShouldTrace("cli")).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	// bufio.Scanner.Scan() may panic...
	var panicErr error
	defer func() {
		if panicErr != nil {
			xerr = fail.ToError(panicErr)
		}
	}()
	defer fail.OnPanic(&panicErr)

	scanner := bufio.NewScanner(params.bridge.Reader())
	scanner.Split(bufio.ScanLines)

	var err error
	for {
		// If task aborted, stop the loop
		if t.Aborted() {
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
			switch err.(type) {
			// case fail.ErrAborted, *os.PathError:
			case *os.PathError:
				err = nil
			}
		}
	}
	return nil, fail.ToError(err)
}

func taskDisplay(t concurrency.Task, p concurrency.TaskParameters) (concurrency.TaskResult, fail.Error) {
	displayCh, ok := p.(<-chan outputItem)
	if !ok {
		return nil, fail.InvalidParameterError("p", "must be a '<-chan outputItem'")
	}

	for item := range displayCh {
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
			default:
				return xerr
			}
		}
	}

	*pbc = PipeBridgeController{}
	return nil
}
