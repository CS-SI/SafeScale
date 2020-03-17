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
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	networkfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/network"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/retry/enums/verdict"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const protocolSeparator = ":"

//go:generate mockgen -destination=../mocks/mock_sshapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers SSHHandler

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
func NewSSHHandler(job server.Job) SSHHandler {
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

	task := handler.job.SafeGetTask()
	svc := handler.job.SafeGetService()

	var (
		hostRef string
		host    resources.Host
	)
	switch hostParam := hostParam.(type) {
	case string:
		hostRef = hostParam
		host, err = hostfactory.Load(task, svc, hostRef)
		if err != nil {
			return nil, err
		}
	case resources.Host:
		host = hostParam
		if host.SafeGetName() != "" {
			hostRef = host.SafeGetName()
		} else {
			hostRef = host.SafeGetID()
		}
	default:
		return nil, scerr.InvalidParameterError("hostParam", "must be a not-empty string or a resources.Host*abstract.Host")
	}

	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.ssh"), "(%s)", hostRef).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	cfg, err := svc.GetConfigurationOptions()
	if err != nil {
		return nil, err
	}
	user := abstract.DefaultUser
	if userIf, ok := cfg.Get("OperatorUsername"); ok {
		user = userIf.(string)
		if user == "" {
			logrus.Warnf("OperatorUsername is empty ! Check your tenants.toml file ! Using 'safescale' user instead.")
			user = abstract.DefaultUser
		}
	}

	ip, err := host.GetAccessIP(task)
	if err != nil {
		return nil, err
	}
	sshConfig = &system.SSHConfig{
		Port: 22,
		Host: ip,
		User: user,
	}
	err = host.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		hc, ok := clonable.(*abstract.HostCore)
		if !ok {
			return scerr.InconsistentError("")
		}
		sshConfig.PrivateKey = hc.PrivateKey

		return props.Inspect(hostproperty.NetworkV1, func(clonable data.Clonable) error {
			hostNetworkV1, ok := clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if hostNetworkV1.DefaultNetworkID != "" {
				objn, inErr := networkfactory.Load(task, svc, hostNetworkV1.DefaultNetworkID)
				if inErr != nil {
					return inErr
				}
				gw, pgwErr := objn.GetGateway(task, true)
				if pgwErr == nil {
					inErr = gw.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
						gwhc, ok := clonable.(*abstract.HostCore)
						if !ok {
							return scerr.InconsistentError("'*abstract.Host' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}
						ip, rhErr := gw.GetAccessIP(task)
						if rhErr != nil {
							return rhErr
						}
						GatewayConfig := system.SSHConfig{
							PrivateKey: gwhc.PrivateKey,
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
				} else if _, ok := pgwErr.(scerr.ErrNotFound); !ok {
					return pgwErr
				}
				gw, sgwErr := objn.GetGateway(task, false)
				if sgwErr == nil {
					inErr = gw.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
						gwhc, ok := clonable.(*abstract.HostCore)
						if !ok {
							return scerr.InconsistentError("'*abstract.HostFull' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}
						ip, rhErr := gw.GetAccessIP(task)
						if rhErr != nil {
							return rhErr
						}
						GatewayConfig := system.SSHConfig{
							PrivateKey: gwhc.PrivateKey,
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
				} else if _, ok := sgwErr.(scerr.ErrNotFound); !ok || sshConfig.GatewayConfig == nil {
					return sgwErr
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

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.ssh"), "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ssh, err := handler.GetConfig(hostParam)
	if err != nil {
		return err
	}
	_, err = ssh.WaitServerReady(task, "ready", timeout)
	return err
}

// Run tries to execute command 'cmd' on the host
func (handler *sshHandler) Run(hostRef, cmd string) (retCode int, stdOut string, stdErr string, err error) {
	if handler == nil {
		return -1, "", "", scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return -1, "", "", scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if hostRef == "" {
		return -1, "", "", scerr.InvalidParameterError("hostRef", "cannot be empty string")
	}
	if cmd == "" {
		return -1, "", "", scerr.InvalidParameterError("cmd", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.ssh"), "('%s', <command>)", hostRef).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	tracer.Trace(fmt.Sprintf("<command>=[%s]", cmd))

	host, err := hostfactory.Load(task, handler.job.SafeGetService(), hostRef)
	if err != nil {
		return -1, "", "", err
	}

	// retrieve ssh config to perform some commands
	ssh, err := host.GetSSHConfig(task)
	if err != nil {
		return -1, "", "", err
	}

	retryErr := retry.WhileUnsuccessfulDelay1SecondWithNotify(
		func() error {
			if handler.job.Aborted() {
				return retry.StopRetryError(nil, "operation aborted by user")
			}
			retCode, stdOut, stdErr, err = handler.runWithTimeout(ssh, cmd, temporal.GetHostTimeout())
			return err
		},
		temporal.GetHostTimeout(),
		func(t retry.Try, v verdict.Enum) {
			if v == verdict.Retry {
				logrus.Debugf("Remote SSH service on host '%s' isn't ready, retrying...", host.SafeGetName())
			}
		},
	)
	return retCode, stdOut, stdErr, retryErr
}

// run executes command on the host
func (handler *sshHandler) runWithTimeout(ssh *system.SSHConfig, cmd string, duration time.Duration) (int, string, string, error) {
	// Create the command
	sshCmd, err := ssh.Command(handler.job.SafeGetTask(), cmd)
	if err != nil {
		return 0, "", "", err
	}
	return sshCmd.RunWithTimeout(handler.job.SafeGetTask(), outputs.DISPLAY, duration)
}

func extracthostName(in string) (string, error) {
	parts := strings.Split(in, protocolSeparator)
	if len(parts) == 1 {
		return "", nil
	}
	if len(parts) > 2 {
		return "", scerr.InvalidRequestError("too many parts in path")
	}
	hostName := strings.TrimSpace(parts[0])
	for _, protocol := range []string{"file", "http", "https", "ftp"} {
		if strings.ToLower(hostName) == protocol {
			return "", scerr.SyntaxError("no protocol expected. Only host name")
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
		return "", scerr.InvalidRequestError("too many parts in path")
	}
	_, err := extracthostName(in)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(parts[1]), nil
}

// Copy copies file/directory from/to remote host
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

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.ssh"), "('%s', '%s')", from, to).WithStopwatch().Entering()
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
		return 0, "", "", scerr.NotImplementedError("copy between 2 hosts is not supported yet")
	}
	if hostFrom == "" && hostTo == "" {
		return 0, "", "", scerr.InvalidRequestError("no host name specified neither in from nor to")
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

	host, err := hostfactory.Load(task, handler.job.SafeGetService(), hostName)
	if err != nil {
		return -1, "", "", err
	}

	// retrieve ssh config to perform some commands
	ssh, err := handler.GetConfig(host.SafeGetID())
	if err != nil {
		return -1, "", "", err
	}

	cRc, cStcOut, cStdErr, cErr := ssh.Copy(handler.job.SafeGetTask(), remotePath, localPath, upload)
	return cRc, cStcOut, cStdErr, cErr
}
