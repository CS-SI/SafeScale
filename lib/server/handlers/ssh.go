/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package handlers

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstracts"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	networkfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/network"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/retry/enums/verdict"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const protocolSeparator = ":"

//go:generate mockgen -destination=../mocks/mock_sshapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers SSHAPI

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// SSHHandler defines ssh management API
type SSHHandler interface {
	// Connect(name string) error
	Run(hostname, cmd string) (int, string, string, error)
	Copy(from string, to string) (int, string, string, error)
	GetConfig(interface{}) (*system.SSHConfig, error)
}

// FIXME ROBUSTNESS All functions MUST propagate context

// sshHandler SSH service
type sshHandler struct {
	job server.Job
}

// NewSSHHandler ...
func NewSSHHandler(job server.Job) *SSHHandler {
	return &sshHandler{job: job}
}

// GetConfig creates SSHConfig to connect to an host
func (handler *sshHandler) GetConfig(hostParam interface{}) (sshConfig *system.SSHConfig, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	defer scerr.OnPanic(&err)()

	var (
		hostRef string
		host    resources.Host
	)
	switch hostParam := hostParam.(type) {
	case string:
		hostRef = hostParam
		host, err := hostfactory.Load(handler.job.Service(), hostRef)
		if err != nil {
			return nil, err
		}
	case resources.Host:
		host = hostParam
		if host.Name() != "" {
			hostRef = host.Name()
		} else {
			hostRef = host.ID()
		}
	}
	if host == nil {
		return nil, scerr.InvalidParameterError("hostParam", "must be a not-empty string or a *abstracts.Host")
	}

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, fmt.Sprintf("(%s)", hostRef), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	cfg, err := handler.job.Service().GetConfigurationOptions()
	if err != nil {
		return nil, err
	}
	user := abstracts.DefaultUser
	if userIf, ok := cfg.Get("OperatorUsername"); ok {
		user = userIf.(string)
		if user == "" {
			logrus.Warnf("OperatorUsername is empty ! Check your tenants.toml file ! Using 'safescale' user instead.")
			user = abstracts.DefaultUser
		}
	}

	ip, err := host.AccessIP(task)
	if err != nil {
		return nil, err
	}
	sshConfig = &system.SSHConfig{
		Port: 22,
		Host: ip,
		User: user,
	}
	err = host.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		rh, ok := clonable.(*abstracts.Host)
		if !ok {
			return scerr.InconsistentError("")
		}
		sshConfig.PrivateKey = rh.PrivateKey

		return props.Inspect(hostproperty.NetworkV1, func(clonable data.Clonable) error {
			hostNetworkV1, ok := clonable.(*propsv1.HostNetwork)
			if !ok {
				return scerr.InconsistentError("'*propsv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if hostNetworkV1.DefaultNetworkID != "" {
				objn, inErr := networkfactory.Load(task, handler.service, hostNetworkV1.DefaultNetworkID)
				if inErr != nil {
					return inErr
				}
				gw, pgwErr := objn.Gateway(task, true)
				if pgwErr == nil {
					inErr = gw.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
						rh, ok := clonable.(*abstracts.Host)
						if !ok {
							return scerr.InconsistentError("'*abstracts.Host' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}
						ip, rhErr := gw.AccessIP(task)
						if rhErr != nil {
							return rhErr
						}
						GatewayConfig := system.SSHConfig{
							PrivateKey: rh.PrivateKey,
							Port:       22,
							Host:       ip,
							User:       user,
						}
						sshConfig.GatewayConfig = &GatewayConfig
						return nil
					})
					if inErr != nil {
						return inErr
					}
				} else {
					if _, ok := pgwErr.(*scerr.ErrNotFound); !ok {
						return pgwErr
					}
				}
				gw, sgwErr := objn.Gateway(task, false)
				if sgwErr == nil {
					inErr = gw.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
						rh, ok := clonable.(*abstracts.Host)
						if !ok {
							return scerr.InconsistentError("'*abstracts.Host' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}
						ip, rhErr := gw.AccessIP(task)
						if rhErr != nil {
							return rhErr
						}
						GatewayConfig := system.SSHConfig{
							PrivateKey: rh.PrivateKey,
							Port:       22,
							Host:       ip,
							User:       user,
						}
						sshConfig.SecondaryGatewayConfig = &GatewayConfig
						return nil
					})
					if inErr != nil {
						return inErr
					}
				} else {
					if _, ok := sgwErr.(*scerr.ErrNotFound); !ok || sshConfig.GatewayConfig == nil {
						return sgwErr
					}
				}
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	return sshConfig, nil
}

// WaitServerReady waits for remote SSH server to be ready. After timeout, fails
func (handler *sshHandler) WaitServerReady(hostParam interface{}, timeout time.Duration) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if hostParam == nil {
		return scerr.InvalidParameterError("hostParam", "cannot be nil!")
	}

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	sshSvc := NewSSHHandler(handler.job)
	ssh, err := sshSvc.GetConfig(hostParam)
	if err != nil {
		return err
	}
	_, err = ssh.WaitServerReady(task, "ready", timeout)
	return err
}

// Run tries to execute command 'cmd' on the host
func (handler *SSHHandler) Run(hostName, cmd string) (retCode int, stdOut string, stdErr string, err error) { // FIXME Make sure ctx is propagated
	if handler == nil {
		return -1, "", "", scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return -1, "", "", scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if hostRef == "" {
		return -1, "", "", scerr.InvalidParameterError("hostName", "cannot be empty string")
	}
	if cmd == "" {
		return -1, "", "", scerr.InvalidParameterError("cmd", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, fmt.Sprintf("('%s', <command>)", hostRef), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	tracer.Trace(fmt.Sprintf("<command>=[%s]", cmd))

	host, err := hostfactory.Load(task, handler.service, hostRef)
	if err != nil {
		return -1, "", "", err
	}

	// retrieve ssh config to perform some commands
	ssh, err := host.SSHConfig(task)
	if err != nil {
		return -1, "", "", err
	}

	retryErr := retry.WhileUnsuccessfulDelay1SecondWithNotify(
		func() error {
			if handler.job.Aborted() {
				return retry.StopRetryError("operation aborted by user", nil)
			}
			retCode, stdOut, stdErr, err = handler.runWithTimeout(ssh, cmd, temporal.GetHostTimeout())
			return err
		},
		temporal.GetHostTimeout(),
		func(t retry.Try, v verdict.Enum) {
			if v == verdict.Retry {
				logrus.Debugf("Remote SSH service on host '%s' isn't ready, retrying...", hostName)
			}
		},
	)
	return retCode, stdOut, stdErr, retryErr
}

// run executes command on the host
func (handler *sshHandler) runWithTimeout(ssh *system.SSHConfig, cmd string, duration time.Duration) (int, string, string, error) {
	// Create the command
	sshCmd, err := ssh.Command(handler.job.Task(), cmd)
	if err != nil {
		return 0, "", "", err
	}
	return sshCmd.RunWithTimeout(handler.job.Task(), outputs.DISPLAY, duration)
}

func extracthostName(in string) (string, error) {
	parts := strings.Split(in, protocolSeparator)
	if len(parts) == 1 {
		return "", nil
	}
	if len(parts) > 2 {
		return "", fmt.Errorf("too many parts in path")
	}
	hostName := strings.TrimSpace(parts[0])
	for _, protocol := range []string{"file", "http", "https", "ftp"} {
		if strings.ToLower(hostName) == protocol {
			return "", fmt.Errorf("no protocol expected. Only host name")
		}
	}

	return hostName, nil
}

func extractPath(in string) (string, error) {
	parts := strings.Split(in, protocolSeparator)
	if len(parts) == 1 {
		return in, nil
	}
	if len(parts) > 2 {
		return "", fmt.Errorf("too many parts in path")
	}
	_, err := extracthostName(in)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(parts[1]), nil
}

// Copy copy file/directory
func (handler *sshHandler) Copy(from, to string) (retCode int, stdOut string, stdErr string, err error) {
	if handler == nil {
		return -1, "", "", scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return -1, "", "", scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if from == "" {
		return -1, "", "", scerr.InvalidParameterError("from", "cannot be empty string")
	}
	if to == "" {
		return -1, "", "", scerr.InvalidParameterError("to", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, fmt.Sprintf("('%s', '%s')", from, to), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	hostName := ""
	var upload bool
	var localPath, remotePath string
	// Try extract host
	hostFrom, err := extracthostName(from)
	if err != nil {
		return 0, "", "", err
	}
	hostTo, err := extracthostName(to)
	if err != nil {
		return 0, "", "", err
	}

	// Host checks
	if hostFrom != "" && hostTo != "" {
		return 0, "", "", fmt.Errorf("copy between 2 hosts is not supported yet")
	}
	if hostFrom == "" && hostTo == "" {
		return 0, "", "", fmt.Errorf("no host name specified neither in from nor to")
	}

	fromPath, err := extractPath(from)
	if err != nil {
		return 0, "", "", err
	}
	toPath, err := extractPath(to)
	if err != nil {
		return 0, "", "", err
	}

	if hostFrom != "" {
		hostName = hostFrom
		remotePath = fromPath
		localPath = toPath
		upload = false
	} else {
		hostName = hostTo
		remotePath = toPath
		localPath = fromPath
		upload = true
	}

	host, err := hostfactory.Load(task, handler.service, hostName)
	if err != nil {
		return -1, "", "", err
	}

	// retrieve ssh config to perform some commands
	ssh, err := handler.GetConfig(host.ID)
	if err != nil {
		return -1, "", "", err
	}

	cRc, cStcOut, cStdErr, cErr := ssh.Copy(handler.job.Task(), remotePath, localPath, upload)
	return cRc, cStcOut, cStdErr, cErr
}
