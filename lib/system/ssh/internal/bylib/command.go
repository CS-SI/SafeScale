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
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/internal/bylib/sshtunnel"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// Command defines a SSH command
type Command struct {
	conn         *Connector
	runCmdString string
	withSudo     bool
	username     string
	cmd          *exec.Cmd
}

// String ...
func (scmd *Command) String() string {
	if valid.IsNull(scmd) {
		return ""
	}

	return scmd.runCmdString
}

// // RunWithTimeout ...
// func (scmd *Command) RunWithTimeout(ctx context.Context, outs outputs.Enum, timeout time.Duration) (_ int, _ string, _ string, ferr fail.Error) {
// 	const invalid = -1
// 	if valid.IsNull(scmd) {
// 		return invalid, "", "", fail.InvalidInstanceError()
// 	}
// 	if valid.IsNull(scmd.conn) {
// 		return invalid, "", "", fail.InvalidInstanceContentError("scmd.conn", "cannot be null value of 'apissh.Connector'")
// 	}
// 	if ctx == nil {
// 		return invalid, "", "", fail.InvalidParameterError("ctx", "cannot be nil")
// 	}
//
// 	task, xerr := concurrency.TaskFromContext(ctx)
// 	xerr = debug.InjectPlannedFail(xerr)
// 	if xerr != nil {
// 		return invalid, "", "", xerr
// 	}
//
// 	if task.Aborted() {
// 		return invalid, "", "", fail.AbortedError(nil, "aborted")
// 	}
//
// 	tracer := debug.NewTracer(task, tracing.ShouldTrace("ssh"), "(%s, %v)", outs.String(), timeout).WithStopwatch().Entering()
// 	tracer.Trace("host='%s', command=\n%s\n", scmd.conn.TargetConfig.Hostname, scmd.runCmdString)
// 	defer tracer.Exiting()
//
// 	session, xerr := scmd.conn.createExecutionSession()
// 	if xerr != nil {
// 		return -1, "", "", xerr
// 	}
// 	defer scmd.conn.closeExecutionSession(session, &ferr)
//
// 	subtask, xerr := concurrency.NewTaskWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID("/ssh/run"))
// 	if xerr != nil {
// 		return invalid, "", "", xerr
// 	}
//
// 	if timeout == 0 {
// 		timeout = 1200 * time.Second // upper bound of 20 min
// 	} else if timeout > 1200*time.Second {
// 		timeout = 1200 * time.Second // nothing should take more than 20 min
// 	}
//
// 	params := taskExecuteParameters{
// 		session:        session,
// 		collectOutputs: outs != outputs.DISPLAY,
// 	}
//
// 	_, xerr = subtask.StartWithTimeout(scmd.taskExecute, params, timeout)
// 	if xerr != nil {
// 		return invalid, "", "", xerr
// 	}
//
// 	_, r, xerr := subtask.WaitFor(timeout)
// 	if xerr != nil {
// 		switch xerr.(type) {
// 		case *fail.ErrTimeout:
// 			xerr = fail.Wrap(fail.Cause(xerr), "reached timeout of %s", temporal.FormatDuration(timeout)) // FIXME: Change error message
// 		default:
// 			debug.IgnoreError(xerr)
// 		}
//
// 		// FIXME: This kind of resource exhaustion deserves its own handling and its own kind of error
// 		{
// 			if strings.Contains(xerr.Error(), "annot allocate memory") {
// 				return invalid, "", "", fail.AbortedError(xerr, "problem allocating memory, pointless to retry")
// 			}
//
// 			if strings.Contains(xerr.Error(), "esource temporarily unavailable") {
// 				return invalid, "", "", fail.AbortedError(xerr, "not enough resources, pointless to retry")
// 			}
// 		}
//
// 		tracer.Trace("run failed: %v", xerr)
// 		return invalid, "", "", xerr
// 	}
//
// 	if result, ok := r.(data.Map); ok {
// 		if outs == outputs.DISPLAY {
// 			fmt.Print(result["stdout"].(string))
// 		}
// 		tracer.Trace("run succeeded, retcode=%d", result["retcode"].(int))
// 		return result["retcode"].(int), result["stdout"].(string), result["stderr"].(string), nil
// 	}
// 	return invalid, "", "", fail.InconsistentError("'result' should have been of type 'data.Map'")
// }
//
// type taskExecuteParameters struct {
// 	session        *libssh.Session
// 	collectOutputs bool
// }
//
// func (scmd *Command) taskExecute(task concurrency.Task, p concurrency.TaskParameters) (concurrency.TaskResult, fail.Error) {
// 	if valid.IsNull(scmd) {
// 		return nil, fail.InvalidInstanceError()
// 	}
// 	if len(scmd.String()) == 0 {
// 		return nil, fail.InvalidInstanceContentError("scmd", "contains empty command")
// 	}
// 	params, ok := p.(taskExecuteParameters)
// 	if !ok {
// 		return nil, fail.InvalidParameterError("p", "must be a 'taskExecuteParameters'")
// 	}
// 	if params.session == nil {
// 		return nil, fail.InvalidParameterCannotBeNilError("params.session")
// 	}
//
// 	if task.Aborted() {
// 		return nil, fail.AbortedError(nil, "aborted")
// 	}
//
// 	result := data.Map{
// 		"retcode": -1,
// 		"stdout":  "",
// 		"stderr":  "",
// 	}
//
// 	var (
// 		stdoutBridge, stderrBridge cli.PipeBridge
// 		pipeBridgeCtrl             *cli.PipeBridgeController
// 		msgOut, msgErr             []byte
// 		xerr                       fail.Error
// 	)
//
// 	// Set up the outputs (std and err)
// 	stdoutPipe, err := params.session.StdoutPipe()
// 	if err != nil {
// 		return result, fail.Wrap(err)
// 	}
//
// 	stderrPipe, err := params.session.StderrPipe()
// 	if err != nil {
// 		return result, fail.Wrap(err)
// 	}
//
// 	if !params.collectOutputs {
// 		stdoutBridge, xerr = cli.NewStdoutBridge(stdoutPipe.(io.ReadCloser))
// 		if xerr != nil {
// 			return result, xerr
// 		}
//
// 		stderrBridge, xerr = cli.NewStderrBridge(stderrPipe.(io.ReadCloser))
// 		if xerr != nil {
// 			return result, xerr
// 		}
//
// 		pipeBridgeCtrl, xerr = cli.NewPipeBridgeController(stdoutBridge, stderrBridge)
// 		if xerr != nil {
// 			return result, xerr
// 		}
//
// 		// Starts pipebridge
// 		xerr = pipeBridgeCtrl.Start(task)
// 		if xerr != nil {
// 			return result, xerr
// 		}
//
// 		// Ensure the pipebridge is properly closed
// 		defer func() {
// 			if !params.collectOutputs {
// 				derr := pipeBridgeCtrl.Stop()
// 				if derr != nil {
// 					if xerr != nil {
// 						_ = xerr.AddConsequence(derr)
// 					} else {
// 						xerr = derr
// 					}
// 				}
// 				derr = pipeBridgeCtrl.Wait()
// 				if derr != nil {
// 					if xerr != nil {
// 						_ = xerr.AddConsequence(derr)
// 					} else {
// 						xerr = derr
// 					}
// 				}
// 			}
// 		}()
// 	}
//
// 	// err = params.session.Start(scmd.String())
// 	// if err != nil {
// 	// 	return result, fail.Wrap(err)
// 	// }
// 	//
// 	serr := params.session.Run(scmd.String())
//
// 	var consequences []error
// 	if params.collectOutputs {
// 		var derr error
// 		msgOut, derr = ioutil.ReadAll(stdoutPipe)
// 		if derr != nil {
// 			consequences = append(consequences, derr)
// 		}
//
// 		msgErr, derr = ioutil.ReadAll(stderrPipe)
// 		if derr != nil {
// 			consequences = append(consequences, derr)
// 		}
//
// 		if len(consequences) == 0 {
// 			result["stdout"] = string(msgOut)
// 			result["stderr"] = string(msgErr)
// 		}
// 	}
//
// 	if serr != nil {
// 		var errorCode int
// 		switch cerr := serr.(type) {
// 		case *libssh.ExitError:
// 			errorCode = cerr.ExitStatus()
// 			logrus.Debugf("Found an exit error of command '%s': %d", scmd.String(), errorCode)
// 		case *libssh.ExitMissingError:
// 			logrus.Warnf("Found exit missing error of command '%s'", scmd.String())
// 			errorCode = -1
// 		case net.Error:
// 			logrus.Debugf("Found network error running command '%s'", scmd.String())
// 			errorCode = 255
// 		default:
// 			errorCode = -1
// 		}
//
// 		result["retcode"] = errorCode
// 		xerr = fail.Wrap(serr)
// 		if len(consequences) > 0 {
// 			newErr := fail.NewErrorList(consequences)
// 			_ = xerr.AddConsequence(newErr)
// 		}
// 	} else {
// 		result["retcode"] = 0
// 		// FIXME: what to do when len(consequences) > 0 in this case? log? return error? do nothing (like now)?
// 		xerr = nil
// 	}
//
// 	return result, xerr
// }

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

	if timeout == 0 {
		timeout = 1200 * time.Second // upper bound of 20 min
	} else if timeout > 1200*time.Second {
		timeout = 1200 * time.Second // nothing should take more than 20 min
	}

	type result struct {
		errorcode int
		stdout    string
		stderr    string
		reserr    error
	}

	results := make(chan result)
	enough := time.After(timeout)

	go func() {
		defer close(results)

		if task != nil && task.Aborted() {
			results <- result{-1, "", "", fail.AbortedError(task.Context().Err(), "task aborted by parent")}
			return
		}

		session, xerr := scmd.conn.createExecutionSession()
		if xerr != nil {
			results <- result{-1, "", "", xerr}
			return
		}
		defer func() {
			if session != nil {
				err := session.Close()
				if err != nil {
					if !strings.Contains(err.Error(), "EOF") {
						logrus.Warnf("error closing session: %v", err)
					}
				}
			}
		}()

		if task != nil && task.Aborted() {
			results <- result{-1, "", "", fail.AbortedError(task.Context().Err(), "task aborted by parent")}
			return
		}

		if len(scmd.String()) == 0 {
			results <- result{-1, "", "", fail.AbortedError(nil, "empty ssh command")}
			return
		}

		// Once a Session is created, you can execute a single command on
		// the remote side using the Run method.
		var errorCode int

		var be bytes.Buffer
		var b bytes.Buffer
		session.Stdout = &b
		session.Stderr = &be

		opTimeout := timeout
		if timeout != 0 {
			if 150*time.Second > timeout {
				opTimeout = 150 * time.Second
			}
		}

		breaker := false
		for {
			if breaker {
				break
			}

			beginIter := time.Now()
			if err := sshtunnel.RunCommandInSSHSessionWithTimeout(session, scmd.String(), opTimeout); err != nil {
				logrus.Debugf("Error running command after %s: %s", time.Since(beginIter), err.Error())
				errorCode = -1

				if ee, ok := err.(*ssh.ExitError); ok {
					errorCode = ee.ExitStatus()
					logrus.Debugf("Found an exit error of command '%s': %d", scmd.String(), errorCode)
				}

				if _, ok := err.(*ssh.ExitMissingError); ok {
					logrus.Warnf("Found exit missing error of command '%s'", scmd.String())
					errorCode = -2
				}

				if _, ok := err.(net.Error); ok {
					logrus.Debugf("Found network error running command '%s'", scmd.String())
					errorCode = 255
				}

				results <- result{
					errorcode: errorCode,
					stdout:    "",
					stderr:    "",
					reserr:    err,
				}
				return
			}

			breaker = true
		}

		results <- result{
			errorcode: errorCode,
			stdout:    b.String(),
			stderr:    be.String(),
			reserr:    nil,
		}
	}()

	if timeout != 0 {
		select {
		case res := <-results:
			if outs == outputs.DISPLAY {
				fmt.Print(res.stdout)
			}
			return res.errorcode, res.stdout, res.stderr, nil
		case <-enough:
			return 255, "", "", fail.NewError("received timeout of %s", timeout)
		}
	}

	res := <-results

	if outs == outputs.DISPLAY {
		fmt.Print(res.stdout)
	}

	return res.errorcode, res.stdout, res.stderr, nil
}
