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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package controller

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

const (
	defaultHttpPort   string = "58500" // By default, consul http will listen on port 58500
	defaultServerPort string = "58300" // By default, consul private server will listen on port 58300
	// defaultHost string = "0.0.0.0" // By default, consul private server will listen on all interfaces
)

var (
	//go:embed templates/consul.hcl
	consulConfigTemplate string

	currentConsulProc atomic.Value
	cancelAgent       context.CancelFunc
)

// StartAgent creates consul configuration file if needed and starts consul agent in server mode
func StartAgent(ctx context.Context) (startedCh chan bool, doneCh chan Result[commandOutput], _ context.CancelFunc, ferr fail.Error) {
	startedCh = make(chan bool)
	doneCh = make(chan Result[commandOutput])
	defer func() {
		if ferr != nil {
			startedCh <- false
			close(startedCh)
			close(doneCh)
		}
	}()

	var cancelNOP context.CancelFunc = func() {}

	// Make sure settings are coherent
	if global.Settings.Backend.Consul.HttpPort == "" {
		global.Settings.Backend.Consul.HttpPort = defaultHttpPort
	}
	if global.Settings.Backend.Consul.ServerPort == "" {
		global.Settings.Backend.Consul.ServerPort = defaultServerPort
	}
	if global.Settings.Backend.Consul.ServerPort != "" && (global.Settings.Backend.Consul.SerfLanPort == "" || global.Settings.Backend.Consul.SerfWanPort == "") {
		val, err := strconv.Atoi(global.Settings.Backend.Consul.ServerPort)
		if err != nil {
			return nil, nil, cancelNOP, fail.Wrap(err, "invalid value '%s' found for Consul server port", global.Settings.Backend.Consul.ServerPort)
		}

		if global.Settings.Backend.Consul.SerfLanPort == "" {
			global.Settings.Backend.Consul.SerfLanPort = strconv.Itoa(val + 1)
		}
		if global.Settings.Backend.Consul.SerfWanPort == "" {
			global.Settings.Backend.Consul.SerfWanPort = strconv.Itoa(val + 2)
		}
	}

	// creates configuration if not present
	consulRootDir := filepath.Join(global.Settings.Folders.ShareDir, "consul")
	consulEtcDir := filepath.Join(consulRootDir, "etc")
	// consulVarDir := filepath.Join(consulRootDir, "var")
	consulConfigFile := filepath.Join(consulEtcDir, "consul.hcl")
	st, err := os.Stat(consulConfigFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			file, err := os.Create(consulConfigFile)
			if err != nil {
				return nil, nil, cancelNOP, fail.Wrap(err, "failed to create consul configuration file")
			}

			_, err = file.WriteString(consulConfigTemplate)
			if err != nil {
				return nil, nil, cancelNOP, fail.Wrap(err, "failed to write content of consul configuration file")
			}

			err = file.Close()
			if err != nil {
				return nil, nil, cancelNOP, fail.Wrap(err, "failed to close consul configuration file")
			}
		} else {
			return nil, nil, cancelNOP, fail.Wrap(err, "failed to check if consul configuration file exists")
		}
	} else if st.IsDir() {
		return nil, nil, cancelNOP, fail.NotAvailableError("'%s' is a directory; should be a file", consulConfigFile)
	}

	// Make sure to stop already running consul on start
	killRemainingConsul(consulRootDir)

	cliArgs := []string{
		"agent",
		"-config-dir=" + consulEtcDir,
		// "-data-dir=" + filepath.Join(consulVarDir, "data"),
		// "-pid-file=" + filepath.Join(consulVarDir, "consul.pid"),
		"-datacenter=safescale",
		"-http-port=" + global.Settings.Backend.Consul.HttpPort,
	}
	if !global.Settings.Backend.Consul.External {
		cliArgs = append(cliArgs, []string{
			"-server",
			"-bootstrap",
			"-server-port=" + global.Settings.Backend.Consul.ServerPort,
			"-serf-lan-port=" + global.Settings.Backend.Consul.SerfLanPort,
			"-serf-wan-port=" + global.Settings.Backend.Consul.SerfWanPort,
		}...)
	}

	var agentCtx context.Context
	agentCtx, cancelAgent = context.WithCancel(ctx)

	// starts a goroutine to start consul server as long as it's needed, depending on the termination reason
	go func() {
		defer func() {
			close(startedCh)
			close(doneCh)
		}()

		const maxRetries = 5
		for i := 0; i < maxRetries; i++ {
			// Runs consul agent
			cmdDoneCh, xerr := startCommand(agentCtx, cliArgs)
			if xerr != nil {
				// Do not try again when binary cannot be started
				logrus.Error(xerr.Error())
				startedCh <- false
				return
			}

			// Wait 10ms to be sure Consul Agent failed if it has to fail
			time.Sleep(10 * time.Millisecond)

			startedCh <- true

			out := <-cmdDoneCh
			// if out.err != nil {
			// 	doneCh <- out
			// 	return
			// }

			// reacts based on termination reason
			switch out.Output().ExitCode() {
			case 0:
				logrus.Debugf("consul ends with status '%d'", out.Output().ExitCode())
				doneCh <- NewResult[commandOutput](nil, commandOutput{exitcode: 0})
				return

			default:
				stdout := out.Output().Stdout()
				if strings.Contains(stdout, "Failed to start Consul server") {
					if strings.Contains(stdout, "bind: address already in use") {
						xerr := fail.NewError("failed to start consul agent on port localhost:%s: address already in use", global.Settings.Backend.Consul.ServerPort)
						logrus.Errorf(xerr.Error())
						doneCh <- NewResult[commandOutput](xerr, out.Output())
						return
					}
				}

				if i < maxRetries {
					logrus.Errorf("consul ends with unexpected status '%d' after %d retries:\nstdout=%s", out.Output().ExitCode(), i, out.Output().Stdout())
				} else {
					logrus.Errorf("consul ends with unexpected status '%d':\nstdout=%s", out.Output().ExitCode(), out.Output().Stdout())
				}
			}

			if i < maxRetries {
				logrus.Info("Restarting consul")
			}
		}
	}()

	return startedCh, doneCh, cancelAgent, nil
}

// killRemainingConsul will stop previous consul that may have not been correctly stopped
func killRemainingConsul(rootDir string) {
	pidfile := filepath.Join(rootDir, "var/consul.pid")
	_ = pidfile
	// test file exists
	// If exists, read content
	// check it's a consul agent running with the pid
	// if yes, kill it
	// rm pidfile
}

func StopAgent() {
	if cancelAgent != nil {
		cancelAgent()
	}
}

type Result[T any] struct {
	err    error
	output T
}

func NewResult[T any](err error, res T) Result[T] {
	return Result[T]{
		err:    err,
		output: res,
	}
}

func (r Result[T]) Failed() bool {
	return r.err != nil
}

func (r Result[T]) Error() error {
	return r.err
}

func (r Result[T]) Output() T {
	return r.output
}

type commandOutput struct {
	exitcode int
	stdout   string
	stderr   string
}

func (r commandOutput) ExitCode() int {
	return r.exitcode
}

func (r commandOutput) Stdout() string {
	return r.stdout
}

func (r commandOutput) Stderr() string {
	return r.stderr
}

// startCommand starts consul agent
func startCommand(ctx context.Context, args []string) (chan Result[commandOutput], fail.Error) {
	var outbuf, errbuf bytes.Buffer

	cmd := exec.Command(global.Settings.Backend.Consul.ExecPath, args...)
	cmd.Dir = filepath.Dir(filepath.Dir(global.Settings.Backend.Consul.ExecPath))
	cmd.Stdout = &outbuf
	cmd.Stderr = &errbuf
	operatingSystemSpecifics(cmd)
	err := cmd.Start()
	if err != nil {
		return nil, fail.Wrap(err, "failed to start consul")
	}

	currentConsulProc.Store(cmd.Process)

	// Starts a goroutine to react to cancellation
	go func() {
		select {
		case <-ctx.Done():
			err := cmd.Process.Signal(os.Interrupt)
			if err != nil {
				if !strings.Contains(err.Error(), "os: process already finished") {
					logrus.Errorf("Failed to signal consul to stop: %v", err)
				}
			}
			return
		}
	}()

	// starts a goroutine to react to agent termination
	doneCh := make(chan Result[commandOutput])
	go func() {
		defer close(doneCh)

		exitcode, stdout, stderr, xerr := waitCommand(cmd, &outbuf, &errbuf)
		if xerr != nil {
			doneCh <- NewResult[commandOutput](xerr, commandOutput{})
			return
		}

		xerr = nil
		if exitcode != 0 {
			xerr = fail.ExecutionError(nil)
		}
		doneCh <- NewResult[commandOutput](xerr, commandOutput{exitcode: exitcode, stdout: stdout, stderr: stderr})
	}()

	return doneCh, nil
}

// waitCommand waits the end of consul agent
func waitCommand(cmd *exec.Cmd, outbuf, errbuf *bytes.Buffer) (int, string, string, fail.Error) {
	exitCode := -1
	err := cmd.Wait()
	stdout := outbuf.String()
	stderr := errbuf.String()
	if err != nil {
		// try to get the exit code
		exitError, ok := err.(*exec.ExitError)
		if ok {
			ws, ok := exitError.Sys().(syscall.WaitStatus)
			if ok {
				exitCode = ws.ExitStatus()
			}
		}

		if exitCode == -1 {
			// This will happen (in OSX) if `name` is not available in $PATH,
			// in this situation, exit code could not be get, and stderr will be
			// empty string very likely, so we use the default fail code, and format err
			// to string and set to stderr
			logrus.Infof("Could not get exit code of failed consul")
			exitCode = 1
			if stderr == "" {
				stderr = err.Error()
			}
		}
	} else {
		// success, exitCode should be 0 if go is ok
		ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
		if ok {
			exitCode = ws.ExitStatus()
		} else {
			exitCode = 0
		}
	}

	return exitCode, stdout, stderr, nil
}
