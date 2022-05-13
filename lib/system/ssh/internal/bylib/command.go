/*
  //go:build tunnel
  // +build tunnel
*/
/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package bylib

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	libssh "golang.org/x/crypto/ssh"

	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// Command defines a SSH command
type Command struct {
	conn         *Connector
	runCmdString string
	withSudo     bool
	username     string
	cmd          *exec.Cmd
}

// Output runs the command and returns its standard output.
// Any returned error will usually be of type *ExitError.
// If c.Stderr was nil, Output populates ExitError.Stderr.
func (scmd *Command) Output() (_ []byte, ferr fail.Error) {
	if scmd.cmd.Stdout != nil {
		return []byte(""), nil
	}

	// defer func() {
	// 	nerr := scmd.cleanup()
	// 	if nerr != nil {
	// 		logrus.Warnf("Error waiting for newExecuteCommand cleanup: %v", nerr)
	// 		ferr = nerr
	// 	}
	// }()

	content, err := scmd.cmd.Output()
	if err != nil {
		return nil, fail.Wrap(err)
	}

	return content, nil
}

// String ...
func (scmd *Command) String() string {
	if valid.IsNull(scmd) {
		return ""
	}

	return scmd.runCmdString
}

// PublicKeyFromStr ...
func PublicKeyFromStr(keyStr string) libssh.AuthMethod {
	key, err := libssh.ParsePrivateKey([]byte(keyStr))
	if err != nil {
		return nil
	}

	return libssh.PublicKeys(key)
}

// RunWithTimeout ...
func (scmd *Command) RunWithTimeout(ctx context.Context, outs outputs.Enum, timeout time.Duration) (_ int, _ string, _ string, ferr fail.Error) {
	const invalid = -1
	if valid.IsNull(scmd) {
		return invalid, "", "", fail.InvalidInstanceError()
	}
	if valid.IsNull(scmd.conn) {
		return invalid, "", "", fail.InvalidInstanceContentError("scmd.conn", "cannot be null value of 'apissh.Connector'")
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
	tracer.Trace("host='%s', command=\n%s\n", scmd.conn.TargetConfig.Hostname, scmd.runCmdString)
	defer tracer.Exiting()

	session, xerr := scmd.conn.createExecutionSession()
	if xerr != nil {
		return -1, "", "", xerr
	}
	defer scmd.conn.closeExecutionSession(session, &ferr)

	subtask, xerr := concurrency.NewTaskWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID("/ssh/run"))
	if xerr != nil {
		return invalid, "", "", xerr
	}

	if timeout == 0 {
		timeout = 1200 * time.Second // upper bound of 20 min
	} else if timeout > 1200*time.Second {
		timeout = 1200 * time.Second // nothing should take more than 20 min
	}

	params := taskExecuteParameters{
		session:        session,
		collectOutputs: outs != outputs.DISPLAY,
	}
	_, xerr = subtask.StartWithTimeout(scmd.taskExecute, params, timeout)
	if xerr != nil {
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
		if outs == outputs.DISPLAY {
			fmt.Print(result["stdout"].(string))
		}
		tracer.Trace("run succeeded, retcode=%d", result["retcode"].(int))
		return result["retcode"].(int), result["stdout"].(string), result["stderr"].(string), nil
	}
	return invalid, "", "", fail.InconsistentError("'result' should have been of type 'data.Map'")
}

type taskExecuteParameters struct {
	session        *libssh.Session
	collectOutputs bool
	timeout        time.Duration
}

func (scmd *Command) taskExecute(task concurrency.Task, p concurrency.TaskParameters) (concurrency.TaskResult, fail.Error) {
	if valid.IsNull(scmd) {
		return nil, fail.InvalidInstanceError()
	}
	if len(scmd.String()) == 0 {
		return nil, fail.InvalidInstanceContentError("scmd", "contains empty command")
	}
	params, ok := p.(taskExecuteParameters)
	if !ok {
		return nil, fail.InvalidParameterError("p", "must be a 'taskExecuteParameters'")
	}
	if params.session == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params.session")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	result := data.Map{
		"retcode": -1,
		"stdout":  "",
		"stderr":  "",
	}

	var (
		stdoutBridge, stderrBridge cli.PipeBridge
		pipeBridgeCtrl             *cli.PipeBridgeController
		msgOut, msgErr             []byte
		xerr                       fail.Error
	)

	opTimeout := params.timeout
	if opTimeout > 0 && opTimeout < 150*time.Second {
		opTimeout = 150 * time.Second
	}

	// Set up the outputs (std and err)
	stdoutPipe, err := params.session.StdoutPipe()
	if err != nil {
		return result, fail.Wrap(err)
	}

	stderrPipe, err := params.session.StderrPipe()
	if err != nil {
		return result, fail.Wrap(err)
	}

	if !params.collectOutputs {
		stdoutBridge, xerr = cli.NewStdoutBridge(stdoutPipe.(io.ReadCloser))
		if xerr != nil {
			return result, xerr
		}

		stderrBridge, xerr = cli.NewStderrBridge(stderrPipe.(io.ReadCloser))
		if xerr != nil {
			return result, xerr
		}

		pipeBridgeCtrl, xerr = cli.NewPipeBridgeController(stdoutBridge, stderrBridge)
		if xerr != nil {
			return result, xerr
		}

		// Starts pipebridge
		xerr = pipeBridgeCtrl.Start(task)
		if xerr != nil {
			return result, xerr
		}

		// Ensure the pipebridge is properly closed
		defer func() {
			if !params.collectOutputs {
				derr := pipeBridgeCtrl.Stop()
				if derr != nil {
					if xerr != nil {
						_ = xerr.AddConsequence(derr)
					} else {
						xerr = derr
					}
				}
				derr = pipeBridgeCtrl.Wait()
				if derr != nil {
					if xerr != nil {
						_ = xerr.AddConsequence(derr)
					} else {
						xerr = derr
					}
				}
			}
		}()
	}

	err = params.session.Start(scmd.String())
	if err != nil {
		return result, fail.Wrap(err)
	}

	err = params.session.Wait()

	if params.collectOutputs {
		msgOut, err = ioutil.ReadAll(stdoutPipe)
		if err != nil {
			return result, fail.Wrap(err)
		}

		msgErr, err = ioutil.ReadAll(stderrPipe)
		if err != nil {
			return result, fail.Wrap(err)
		}

		result["stdout"] = string(msgOut)
		result["stderr"] = string(msgErr)
	}

	if err != nil {
		var errorCode int
		switch casted := err.(type) {
		case *libssh.ExitError:
			errorCode = casted.ExitStatus()
			logrus.Debugf("Found an exit error of newExecuteCommand '%s': %d", scmd.String(), errorCode)
		case *libssh.ExitMissingError:
			logrus.Warnf("Found exit missing error of newExecuteCommand '%s'", scmd.String())
			errorCode = -1
		case net.Error:
			logrus.Debugf("Found network error running newExecuteCommand '%s'", scmd.String())
			errorCode = 255
		default:
			errorCode = -1
		}

		result["retcode"] = errorCode
		xerr = fail.Wrap(err)
	} else {
		result["retcode"] = 0
		xerr = nil
	}

	return result, xerr
}
