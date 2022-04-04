//go:build !tunnel
// +build !tunnel

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

package ssh

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v21/lib/utils"
	"github.com/CS-SI/SafeScale/v21/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v21/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v21/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/temporal"
)

// VPL: SSH ControlMaster options: -oControlMaster=auto -oControlPath=/tmp/safescale-%C -oControlPersist=5m
//      To make profit of this multiplexing functionality, we have to change the way we manage ports for tunnels: we have to always
//      use the same port for all access to a same host (not the case currently)
//      May not be used for interactive ssh connection...

// killProcess sends a kill signal to the process passed as parameter and Wait() for it to release resources (and
// prevent zombie...)
func killProcess(proc *os.Process) fail.Error {
	err := proc.Kill()
	if err != nil {
		switch cerr := err.(type) {
		case syscall.Errno:
			switch cerr {
			case syscall.ESRCH:
				// process not found, continue
				debug.IgnoreError(err)
			default:
				logrus.Errorf("proc.Kill() failed: %s", cerr.Error())
				return fail.Wrap(err, "unable to send kill signal to process")
			}
		default:
			switch err.Error() {
			case "os: process already finished":
				debug.IgnoreError(err)
			default:
				logrus.Errorf("proc.Kill() failed: %s", err.Error())
				return fail.Wrap(err, "unable to send kill signal to process")
			}
		}
	}

	_, err = proc.Wait()
	if err != nil {
		switch cerr := err.(type) {
		case *os.SyscallError:
			err = cerr.Err
		default:
		}
		switch err {
		case syscall.ESRCH, syscall.ECHILD:
			// process not found or has no child, continue
			debug.IgnoreError(err)
		default:
			logrus.Error(err.Error())
			return fail.Wrap(err, "unable to wait on SSH tunnel process")
		}
	}

	return nil
}

// Command defines a SSH command
type Command struct {
	hostname     string
	runCmdString string
	cmd          *exec.Cmd
	tunnels      Tunnels
	keyFile      *os.File
}

// Wait waits for the command to exit and waits for any copying to stdin or copying from stdout or stderr to complete.
// The command must have been started by Start.
// The returned error is nil if the command runs, has no problems copying stdin, stdout, and stderr, and exits with a zero exit status.
// If the command fails to run or doesn't complete successfully, the error is of type *ExitError. Other error types may be returned for I/O problems.
// Wait also waits for the I/O loop copying from c.Stdin into the process's standard input to complete.
// Wait does not release resources associated with the cmd; Command.Close() must be called for that.
// !!!WARNING!!!: the error returned is NOT USING fail.Error because we may NEED TO CAST the error to recover return code
func (scmd *Command) Wait() error {
	if scmd == nil {
		return fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}

	return scmd.cmd.Wait()
}

// Kill kills Command process.
func (scmd *Command) Kill() fail.Error {
	if scmd == nil {
		return fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}
	if scmd.cmd.Process == nil {
		return fail.InvalidInstanceContentError("scmd.cmd.Process", "cannot be nil")
	}

	return killProcess(scmd.cmd.Process)
}

// getStdoutPipe returns a pipe that will be connected to the command's standard output when the command starts.
// Wait will close the pipe after seeing the command exit, so most callers does not need to close the pipe themselves; however,
// an implication is that it is incorrect to call Wait before all reads from the pipe have been completed.
// For the same reason, it is incorrect to call Run when using getStdoutPipe.
func (scmd *Command) getStdoutPipe() (io.ReadCloser, fail.Error) {
	if scmd == nil {
		return nil, fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return nil, fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}

	pipe, err := scmd.cmd.StdoutPipe()
	if err != nil {
		return nil, fail.ConvertError(err)
	}
	return pipe, nil
}

// getStderrPipe returns a pipe that will be connected to the Command's standard error when the Command starts.
// Wait will close the pipe after seeing the Command exit, so most callers does not need to close the pipe themselves; however,
// an implication is that it is incorrect to call Wait before all reads from the pipe have completed. For the same reason,
// it is incorrect to use Run when using getStderrPipe.
func (scmd *Command) getStderrPipe() (io.ReadCloser, fail.Error) {
	if scmd == nil {
		return nil, fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return nil, fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}

	pipe, err := scmd.cmd.StderrPipe()
	if err != nil {
		return nil, fail.ConvertError(err)
	}
	return pipe, nil
}

// getStdinPipe returns a pipe that will be connected to the Command's standard input when the command starts.
// The pipe will be closed automatically after Wait sees the Command exit.
// A caller need only call Close to force the pipe to close sooner.
// For example, if the command being run will not exit until standard input is closed, the caller must close the pipe.
func (scmd *Command) getStdinPipe() (io.WriteCloser, fail.Error) {
	if scmd == nil {
		return nil, fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return nil, fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}

	pipe, err := scmd.cmd.StdinPipe()
	if err != nil {
		return nil, fail.ConvertError(err)
	}
	return pipe, nil
}

// Output returns the standard output of command started.
// Any returned error will usually be of type *ExitError.
// If c.Stderr was nil, Output populates ExitError.Stderr.
func (scmd *Command) Output() ([]byte, fail.Error) {
	if scmd == nil {
		return nil, fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return nil, fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}

	content, err := scmd.cmd.Output()
	if err != nil {
		return nil, fail.NewError(err.Error())
	}
	return content, nil
}

// CombinedOutput returns the combined standard of command started
// output and standard error.
func (scmd *Command) CombinedOutput() ([]byte, fail.Error) {
	if scmd == nil {
		return nil, fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return nil, fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}

	content, err := scmd.cmd.CombinedOutput()
	if err != nil {
		return nil, fail.NewError(err.Error())
	}
	return content, nil
}

// Start starts the specified command but does not wait for it to complete.
// The Wait method will wait for completion and return the exit code.
func (scmd *Command) Start() fail.Error {
	if scmd == nil {
		return fail.InvalidInstanceError()
	}
	if scmd.cmd == nil {
		return fail.InvalidInstanceContentError("scmd.cmd", "cannot be nil")
	}

	if err := scmd.cmd.Start(); err != nil {
		return fail.ConvertError(err)
	}
	return nil
}

// RunWithTimeout ...
// returns:
// - retcode int
// - stdout string
// - stderr string
// - xerr fail.Error
//   . *fail.ErrNotAvailable if remote SSH is not available
//   . *fail.ErrTimeout if 'timeout' is reached
// Note: if you want to RunWithTimeout in a loop, you MUST create the scmd inside the loop, otherwise
//       you risk to call twice os/exec.Wait, which may panic
// FIXME: maybe we should move this method inside sshconfig directly with systematically created scmd...
func (scmd *Command) RunWithTimeout(ctx context.Context, outs outputs.Enum, timeout time.Duration) (int, string, string, fail.Error) {
	const invalid = -1
	if scmd == nil {
		return invalid, "", "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return invalid, "", "", fail.InvalidParameterError("ctx", "cannot be nil")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	if task.Aborted() {
		return invalid, "", "", fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("ssh"), "(%s, %v)", outs.String(), timeout).WithStopwatch().Entering()
	tracer.Trace("host='%s', command=\n%s\n", scmd.hostname, scmd.runCmdString)
	defer tracer.Exiting()

	subtask, xerr := concurrency.NewTaskWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID("/ssh/run"))
	if xerr != nil {
		return invalid, "", "", xerr
	}

	if timeout == 0 {
		timeout = 1200 * time.Second // upper bound of 20 min
	} else if timeout > 1200*time.Second {
		timeout = 1200 * time.Second // nothing should take more than 20 min
	}

	if _, xerr = subtask.StartWithTimeout(scmd.taskExecute, taskExecuteParameters{collectOutputs: outs != outputs.DISPLAY}, timeout); xerr != nil {
		return invalid, "", "", xerr
	}

	_, r, xerr := subtask.WaitFor(timeout)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			xerr = fail.Wrap(fail.Cause(xerr), "reached timeout of %s", temporal.FormatDuration(timeout)) // FIXME: Change error message
		default:
			debug.IgnoreError(xerr)
		}

		// FIXME: This kind of resource exhaustion deserves its own handling and its own kind of error
		{
			if strings.Contains(xerr.Error(), "annot allocate memory") {
				return invalid, "", "", fail.AbortedError(xerr, "problem allocating memory, pointless to retry")
			}

			if strings.Contains(xerr.Error(), "esource temporarily unavailable") {
				return invalid, "", "", fail.AbortedError(xerr, "not enough resources, pointless to retry")
			}
		}

		tracer.Trace("run failed: %v", xerr)
		return invalid, "", "", xerr
	}

	if result, ok := r.(data.Map); ok {
		tracer.Trace("run succeeded, retcode=%d", result["retcode"].(int))
		return result["retcode"].(int), result["stdout"].(string), result["stderr"].(string), nil
	}
	return invalid, "", "", fail.InconsistentError("'result' should have been of type 'data.Map'")
}

type taskExecuteParameters struct {
	// stdout, stderr io.ReadCloser
	collectOutputs bool
}

func (scmd *Command) taskExecute(task concurrency.Task, p concurrency.TaskParameters) (concurrency.TaskResult, fail.Error) {
	if scmd == nil {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	params, ok := p.(taskExecuteParameters)
	if !ok {
		return nil, fail.InvalidParameterError("p", "must be a 'taskExecuteParameters'")
	}

	var (
		stdoutBridge, stderrBridge cli.PipeBridge
		pipeBridgeCtrl             *cli.PipeBridgeController
		msgOut, msgErr             []byte
		xerr                       fail.Error
		err                        error
	)

	result := data.Map{
		"retcode": -1,
		"stdout":  "",
		"stderr":  "",
	}

	ctx := task.Context()

	// Prepare command
	scmd.cmd = exec.CommandContext(ctx, "bash", "-c", scmd.runCmdString)
	scmd.cmd.SysProcAttr = getSyscallAttrs()

	// Set up the outputs (std and err)
	stdoutPipe, xerr := scmd.getStdoutPipe()
	if xerr != nil {
		return result, xerr
	}

	stderrPipe, xerr := scmd.getStderrPipe()
	if xerr != nil {
		return result, xerr
	}

	if !params.collectOutputs {
		if stdoutBridge, xerr = cli.NewStdoutBridge(stdoutPipe); xerr != nil {
			return result, xerr
		}

		if stderrBridge, xerr = cli.NewStderrBridge(stderrPipe); xerr != nil {
			return result, xerr
		}

		if pipeBridgeCtrl, xerr = cli.NewPipeBridgeController(stdoutBridge, stderrBridge); xerr != nil {
			return result, xerr
		}

		// Starts pipebridge if needed
		if xerr = pipeBridgeCtrl.Start(task); xerr != nil {
			return result, xerr
		}
	}

	// Launch the command and wait for its completion
	if xerr = scmd.Start(); xerr != nil {
		return result, xerr
	}

	if params.collectOutputs {
		if msgOut, err = ioutil.ReadAll(stdoutPipe); err != nil {
			return result, fail.ConvertError(err)
		}

		if msgErr, err = ioutil.ReadAll(stderrPipe); err != nil {
			return result, fail.ConvertError(err)
		}
	}

	var pbcErr error
	runErr := scmd.Wait()
	_ = stdoutPipe.Close()
	_ = stderrPipe.Close()

	if runErr != nil {
		xerr = fail.ExecutionError(runErr)
		// If error doesn't contain outputs and return code of the process, stop the pipe bridges and return error
		var (
			rc     int
			note   data.Annotation
			stderr string
			ok     bool
		)
		if note, ok = xerr.Annotation("retcode"); !ok {
			if !params.collectOutputs {
				if derr := pipeBridgeCtrl.Stop(); derr != nil {
					_ = xerr.AddConsequence(derr)
				}
			}
			return result, xerr
		} else if rc, ok = note.(int); ok && rc == -1 {
			if !params.collectOutputs {
				if derr := pipeBridgeCtrl.Stop(); derr != nil {
					_ = xerr.AddConsequence(derr)
				}
			}
			return result, xerr
		}

		result["retcode"], ok = note.(int)
		if !ok {
			logrus.Warnf("Unable to recover 'retcode' because 'note' is not an integer: %v", note)
		}

		// Make sure all outputs have been processed
		if !params.collectOutputs {
			if pbcErr = pipeBridgeCtrl.Wait(); pbcErr != nil {
				logrus.Error(pbcErr.Error())
			}

			if note, ok = xerr.Annotation("stderr"); ok {
				result["stderr"], ok = note.(string)
				if !ok {
					logrus.Warnf("Unable to recover 'stederr' because 'note' is not an string: %v", note)
				}
			}
		} else {
			result["stdout"] = string(msgOut)
			result["stderr"] = fmt.Sprint(string(msgErr), stderr)
		}
	} else {
		result["retcode"] = 0
		if params.collectOutputs {
			result["stdout"] = string(msgOut)
			result["stderr"] = string(msgErr)
		} else if pbcErr = pipeBridgeCtrl.Wait(); pbcErr != nil {
			logrus.Error(pbcErr.Error())
		}
	}

	return result, nil
}

// Close is called to clean Command (close tunnel(s), remove temporary files, ...)
func (scmd *Command) Close() fail.Error {
	var err1 error

	if len(scmd.tunnels) > 0 {
		err1 = scmd.tunnels.Close()
	}
	if err1 != nil {
		logrus.Errorf("Command.closeTunnels() failed: %s (%s)", err1.Error(), reflect.TypeOf(err1).String())
		defer func() { // lazy removal
			ierr := utils.LazyRemove(scmd.keyFile.Name())
			if ierr != nil {
				debug.IgnoreError(ierr)
			}
		}()
		return fail.Wrap(err1, "failed to close SSH tunnels")
	}

	err2 := utils.LazyRemove(scmd.keyFile.Name())
	if err2 != nil {
		return fail.Wrap(err2, "failed to close SSH tunnels")
	}
	return nil
}
