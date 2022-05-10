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
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/internal"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
	libssh "golang.org/x/crypto/ssh"

	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/internal/bylib/sshtunnel"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// Command defines a SSH newCommand
type Command struct {
	conn         *Connector
	runCmdString string
	withSudo     bool
	username     string
	cmd          *exec.Cmd
}

// Output runs the newCommand and returns its standard output.
// Any returned error will usually be of type *ExitError.
// If c.Stderr was nil, Output populates ExitError.Stderr.
func (scmd *Command) Output() (_ []byte, ferr fail.Error) {
	if scmd.cmd.Stdout != nil {
		return []byte(""), nil
	}

	// defer func() {
	// 	nerr := scmd.cleanup()
	// 	if nerr != nil {
	// 		logrus.Warnf("Error waiting for newCommand cleanup: %v", nerr)
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

// // RunWithTimeout ...
// func (sc *SSHCommand) RunWithTimeout(ctx context.Context, outs outputs.Enum, timeout time.Duration) (int, string, string, fail.Error) {
// 	tu, _, err := sc.cfg.createTunneling()
// 	if err != nil {
// 		return 0, "", "", fail.NewError("failure creating tunnel: %w", err)
// 	}
// 	sc.tunnels = tu
// 	defer tu.Close()
//
// 	rv, out, sterr, xerr := sc.NewRunWithTimeout(ctx, outs, timeout)
// 	return rv, out, sterr, xerr
// }

// PublicKeyFromStr ...
func PublicKeyFromStr(keyStr string) libssh.AuthMethod {
	key, err := libssh.ParsePrivateKey([]byte(keyStr))
	if err != nil {
		return nil
	}

	return libssh.PublicKeys(key)
}

// RunWithTimeout ...
func (scmd *Command) RunWithTimeout(ctx context.Context, outs outputs.Enum, timeout time.Duration) (int, string, string, fail.Error) {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, "", "", xerr
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("ssh"), "(%s, %v)", outs.String(), timeout).WithStopwatch().Entering()
	tracer.Trace("newCommand=\n%s\n", scmd.String())
	defer tracer.Exiting()

	if task != nil && task.Aborted() {
		return 0, "", "", fail.AbortedError(task.Context().Err(), "task aborted by parent")
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

		directConfig := &libssh.ClientConfig{
			User: scmd.conn.TargetConfig.User,
			Auth: []libssh.AuthMethod{
				PublicKeyFromStr(scmd.conn.TargetConfig.PrivateKey),
			},
			HostKeyCallback: libssh.InsecureIgnoreHostKey(),
			Timeout:         2 * time.Second,
		}

		logrus.Debugf("Dialing to %s(%s):%d using relay %s:%d", scmd.conn.TargetConfig.Hostname, scmd.conn.TargetConfig.IPAddress, scmd.conn.TargetConfig.Port, "localhost", scmd.conn.tunnels.GetLocalEndpoint().Port())
		// FIXME: think a way to factorize this dial code with connector.createExecutionSession/.dial... currently, these 2 methods do not accept timeout...
		client, err := sshtunnel.DialSSHWithTimeout("tcp", fmt.Sprintf("%s:%d", internal.Loopback, scmd.conn.tunnels.GetLocalEndpoint().Port()), directConfig, 45*time.Second)
		if err != nil {
			if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
				logrus.Debugf(spew.Sdump(err))
			}
			if ne, ok := err.(net.Error); ok {
				if ne.Timeout() || ne.Temporary() {
					results <- result{
						errorcode: 255,
						stdout:    "",
						stderr:    "",
						reserr:    err,
					}
					return
				}
			}

			results <- result{
				errorcode: 255,
				stdout:    "",
				stderr:    "",
				reserr:    err,
			}
			return
		}
		defer func() {
			if client != nil {
				clErr := client.Close()
				if clErr != nil {
					logrus.Warn(clErr)
				}
			}
		}()

		if task != nil && task.Aborted() {
			results <- result{-1, "", "", fail.AbortedError(task.Context().Err(), "task aborted by parent")}
			return
		}

		beginDial := time.Now()
		retries := 0

		var session *libssh.Session
		err = retry.WhileUnsuccessful(func() error { // FIXME: Turn this into goroutine
			// Each ClientConn can support multiple interactive sessions,
			// represented by a Session.

			newsession, internalErr := client.NewSession()
			if internalErr != nil {
				retries++
				logrus.Debugf("problem creating session: %s", internalErr.Error())
				return internalErr
			}
			if session != nil { // race condition mitigation
				return fmt.Errorf("too late")
			}
			logrus.Debugf("creating the session took %s and %d retries", time.Since(beginDial), retries)
			session = newsession
			return nil
		}, time.Second, 150*time.Second)
		if err != nil {
			results <- result{
				errorcode: -1,
				stdout:    "",
				stderr:    "",
				reserr:    err,
			}
			return
		}
		defer func() {
			if session != nil {
				err = session.Close()
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

		if scmd == nil {
			results <- result{-1, "", "", fail.AbortedError(nil, "nil ssh newCommand!!")}
			return
		}

		if len(scmd.String()) == 0 {
			results <- result{-1, "", "", fail.AbortedError(nil, "empty ssh newCommand!!")}
			return
		}

		// Once a Session is created, you can execute a single newCommand on
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
				logrus.Debugf("Running with session timeout here after %s", time.Since(beginIter))
				errorCode = -1

				if ee, ok := err.(*libssh.ExitError); ok {
					errorCode = ee.ExitStatus()
					logrus.Debugf("Found an exit error of newCommand '%s': %d", scmd.String(), errorCode)
				}

				if _, ok := err.(*libssh.ExitMissingError); ok {
					logrus.Warnf("Found exit missing error of newCommand '%s'", scmd.String())
					errorCode = -1
				}

				if _, ok := err.(net.Error); ok {
					logrus.Debugf("Found network error running newCommand '%s'", scmd.String())
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
