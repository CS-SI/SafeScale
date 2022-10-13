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

package consul

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
)

// StartAgent creates consul configuration file if needed and starts consul agent in server mode
func StartAgent(ctx context.Context) (_ chan any, ferr fail.Error) {
	doneCh := make(chan any)
	defer func() {
		if ferr != nil {
			close(doneCh)
		}
	}()

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
			return nil, fail.Wrap(err, "invalid value '%s' found for Consul server port", global.Settings.Backend.Consul.ServerPort)
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
				return doneCh, fail.Wrap(err, "failed to create consul configuration file")
			}

			_, err = file.WriteString(consulConfigTemplate)
			if err != nil {
				return doneCh, fail.Wrap(err, "failed to write content of consul configuration file")
			}

			err = file.Close()
			if err != nil {
				return doneCh, fail.Wrap(err, "failed to close consul configuration file")
			}
		} else {
			return doneCh, fail.Wrap(err, "failed to check if consul configuration file exists")
		}
	} else if st.IsDir() {
		return doneCh, fail.NotAvailableError("'%s' is a directory; should be a file", consulConfigFile)
	}

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

	// starts a goroutine to start consul server as long as it's needed, depending on the porocess end reason
	go func() {
		const maxRetries = 5
		for i := 0; i < maxRetries; i++ {
			// Runs consul agent
			exitcode, stdout, _, xerr := runCommand(ctx, cliArgs)
			if xerr != nil {
				// Do not try again when binary cannot be started
				logrus.Error(xerr.Error())
				return
			}

			// reacts based on end reason
			switch exitcode {
			case 0:
				logrus.Debugf("consul ends with status '%d'", exitcode)
				doneCh <- exitcode
				return
			default:
				if strings.Contains(stdout, "Failed to start Consul server") {
					if strings.Contains(stdout, "bind: address already in use") {
						logrus.Errorf("failed to start consul agent on port localhost:%s: address already in use", global.Settings.Backend.Consul.ServerPort)
						return
					}

				}

				if i < maxRetries {
					logrus.Errorf("consul ends with unexpected status '%d' after %d retries:\nstdout=%s", exitcode, i, stdout)
				} else {
					logrus.Errorf("consul ends with unexpected status '%d':\nstdout=%s", exitcode, stdout)
				}
			}

			if i < maxRetries {
				logrus.Info("Restarting consul")
			}
		}
	}()

	return doneCh, nil
}

// runCommand runs consul agent
func runCommand(ctx context.Context, args []string) (int, string, string, fail.Error) {
	var outbuf, errbuf bytes.Buffer

	cmd := exec.Command(global.Settings.Backend.Consul.ExecPath, args...)
	cmd.Dir = filepath.Dir(filepath.Dir(global.Settings.Backend.Consul.ExecPath))
	cmd.Stdout = &outbuf
	cmd.Stderr = &errbuf
	adaptToOS(cmd)
	err := cmd.Start()
	if err != nil {
		return 1, "", "", fail.Wrap(err, "failed to start consul")
	}

	// Starts a goroutine to react to cancellation
	go func() {
		select {
		case <-ctx.Done():
			err := cmd.Process.Signal(os.Interrupt)
			if err != nil {
				logrus.Errorf("Failed to signal consul to stop: %v", err)
			}
			return
		}
	}()

	exitCode := -1
	err = cmd.Wait()
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
