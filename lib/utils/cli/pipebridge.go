package cli

import (
	"bufio"
	"io"
	"os"

	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
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
func NewStdoutBridge(pipe io.ReadCloser) (*StdoutBridge, error) {
	if pipe == nil {
		return nil, scerr.InvalidParameterError("pipe", "cannot be nil")
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
func NewStderrBridge(pipe io.ReadCloser) (*StderrBridge, error) {
	if pipe == nil {
		return nil, scerr.InvalidParameterError("pipe", "cannot be nil")
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
	readersGroup concurrency.Task
}

// NewPipeBridgeController creates a new controller of bridges of pipe
func NewPipeBridgeController(bridges ...PipeBridge) (*PipeBridgeController, error) {
	if bridges == nil {
		return nil, scerr.InvalidParameterError("pipes", "cannot be nil")
	}

	var validatedBridges []PipeBridge
	for _, v := range bridges {
		if v != nil {
			validatedBridges = append(validatedBridges, v)
		}
	}
	count := uint(len(validatedBridges))
	if count == 0 {
		return nil, scerr.InvalidRequestError("no pipe to bridge")
	}

	ob := PipeBridgeController{bridges: validatedBridges, count: count}
	return &ob, nil
}

// Start initiates the capture of pipe outputs and the display of what is captured
func (pbc *PipeBridgeController) Start(task concurrency.Task) error {
	if pbc == nil {
		return scerr.InvalidInstanceError()
	}
	if pbc.bridges == nil {
		return scerr.InvalidInstanceContentError("pbc.bridges", "cannot be nil")
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	pipeCount := uint(len(pbc.bridges))
	// if no pipes, do nothing
	if pipeCount == 0 {
		return nil
	}

	var err error

	// First starts the "displayer" routine...
	pbc.displayTask, err = concurrency.NewTask(task)
	if err != nil {
		return err
	}
	pbc.displayCh = make(chan outputItem, pipeCount)
	_, err = pbc.displayTask.Start(asyncDisplay, pbc.displayCh)
	if err != nil {
		return err
	}

	// ... then starts the "pipe readers"
	taskGroup, err := concurrency.NewTaskGroup(task)
	if err != nil {
		return err
	}
	for _, v := range pbc.bridges {
		_, err = taskGroup.Start(asyncRead, data.Map{
			"bridge":    v,
			"displayCh": pbc.displayCh,
		})
		if err != nil {
			return err
		}
	}
	pbc.readersGroup = taskGroup
	return nil
}

type outputItem struct {
	bridge PipeBridge
	data   string
}

// Display displays the message contained by the instance using the pipe displayer
func (oi outputItem) Print() {
	oi.bridge.Print(oi.data)
}

// asyncRead reads data from pipe and sends it to the goroutine in charge of displaying it on the right "file descriptor" (stdout or stderr)
func asyncRead(t concurrency.Task, p concurrency.TaskParameters) (_ concurrency.TaskResult, err error) {
	if p == nil {
		return nil, scerr.InvalidParameterError("p", "cannot be nil")
	}

	params, ok := p.(data.Map)
	if !ok {
		return nil, scerr.InvalidParameterError("p", "must be a 'data.Map'")
	}

	var (
		bridge    PipeBridge
		displayCh chan outputItem
	)
	if bridge, ok = params["bridge"].(PipeBridge); !ok {
		return nil, scerr.InvalidParameterError("p[bridge]", "must be a PipeBridge")
	}
	if bridge == nil {
		return nil, scerr.InvalidParameterError("p[pipe]", "cannot be nil")
	}
	if displayCh, ok = params["displayCh"].(chan outputItem); !ok {
		return nil, scerr.InvalidParameterError("p[displayCh]", "must be a chan outputItem")
	}

	tracer := concurrency.NewTracer(t, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	// bufio.Scanner.Scan() may panic...
	defer scerr.OnPanic(&err)()

	scanner := bufio.NewScanner(bridge.Reader())
	scanner.Split(bufio.ScanLines)

	for {
		// If task aborted, stop the loop
		if t.Aborted() {
			break
		}
		if scanner.Scan() {
			item := outputItem{
				bridge: bridge,
				data:   scanner.Text() + "\n",
			}
			displayCh <- item
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
			case *scerr.ErrAborted, *os.PathError:
				err = nil
			}
		}
	}
	return nil, err
}

func asyncDisplay(t concurrency.Task, p concurrency.TaskParameters) (concurrency.TaskResult, error) {
	displayCh, ok := p.(chan outputItem)
	if !ok {
		return nil, scerr.InvalidParameterError("p", "must be a chan outputItem")
	}
	for item := range displayCh {
		item.Print()
	}
	return nil, nil
}

// Wait waits the end of the goroutines
func (pbc *PipeBridgeController) Wait() error {
	if pbc == nil {
		return scerr.InvalidInstanceError()
	}
	if pbc.displayTask == nil {
		return scerr.InvalidInstanceContentError("pbc.displayTask", "cannot be nil")
	}
	if pbc.readersGroup == nil {
		return scerr.InvalidInstanceContentError("pbc.readersGroup", "cannot be nil")
	}
	_, err := pbc.readersGroup.Wait()
	close(pbc.displayCh)
	if err != nil {
		return err
	}

	_, err = pbc.displayTask.Wait()
	return err
}

// Stop the captures and the display.
func (pbc *PipeBridgeController) Stop() error {
	if pbc == nil {
		return scerr.InvalidInstanceError()
	}
	if pbc.count == 0 {
		return nil
	}
	if pbc.readersGroup == nil {
		return scerr.InvalidInstanceContentError("pbc.readersGroup", "cannot be nil")
	}

	// Try to wait the end of the task group
	ok, _, err := pbc.readersGroup.TryWait()
	if err != nil {
		return err
	}
	if !ok {
		// If not done, abort it and wait until the end
		pbc.readersGroup.Abort()
		err = pbc.Wait()
		if err != nil {
			// In case of error, report only if error is not aborted error, as we triggered it
			if _, ok = err.(*scerr.ErrAborted); !ok {
				return err
			}
		}
	}

	*pbc = PipeBridgeController{}
	return nil
}
