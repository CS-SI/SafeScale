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
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	networkfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/network"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/retry/enums/verdict"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const protocolSeparator = ":"

//go:generate mockgen -destination=../mocks/mock_sshapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers SSHHandler

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// SSHHandler defines ssh management API
type SSHHandler interface {
	// Connect(name string) error
	Run(hostname, cmd string) (int, string, string, fail.Error)
	Copy(from string, to string) (int, string, string, fail.Error)
	GetConfig(interface{}) (*system.SSHConfig, fail.Error)
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
func (handler *sshHandler) GetConfig(hostParam interface{}) (sshConfig *system.SSHConfig, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	task := handler.job.GetTask()
	svc := handler.job.GetService()

	_, hostRef, xerr := stacks.ValidateHostParam(hostParam)
	if xerr != nil {
		return nil, xerr
	}

	tracer := concurrency.NewTracer(task, debug.ShouldTrace("handlers.ssh"), "(%s)", hostRef).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &xerr)
	defer fail.OnPanic(&xerr)

	host, xerr := hostfactory.Load(task, svc, hostRef)
	if xerr != nil {
		return nil, xerr
	}

	cfg, xerr := svc.GetConfigurationOptions()
	if xerr != nil {
		return nil, xerr
	}
	var user string
	if anon, ok := cfg.Get("OperatorUsername"); ok {
		user = anon.(string)
		if user == "" {
			logrus.Warnf("OperatorUsername is empty, check your tenants.toml file. Using 'safescale' user instead.")
		}
	}
	if user == "" {
		user = abstract.DefaultUser
	}

	ip, xerr := host.GetAccessIP(task)
	if xerr != nil {
		return nil, xerr
	}
	sshConfig = &system.SSHConfig{
		Port: 22,
		Host: ip,
		User: user,
	}
	xerr = host.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		ahc, ok := clonable.(*abstract.HostCore)
		if !ok {
			return fail.InconsistentError("")
		}
		sshConfig.PrivateKey = ahc.PrivateKey

		return props.Inspect(task, hostproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
			hostNetworkV1, ok := clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if hostNetworkV1.DefaultNetworkID != "" {
				rn, innerXErr := networkfactory.Load(task, svc, hostNetworkV1.DefaultNetworkID)
				if innerXErr != nil {
					return innerXErr
				}

				var gwahc *abstract.HostCore

				gw, pgwErr := rn.GetGateway(task, true)
				if pgwErr != nil {
					if _, ok := pgwErr.(*fail.ErrNotFound); !ok {
						return pgwErr
					}
				} else {
					innerXErr = gw.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
						gwahc, ok = clonable.(*abstract.HostCore)
						if !ok {
							return fail.InconsistentError("'*abstract.Host' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}
						return nil
					})
					if innerXErr != nil {
						return innerXErr
					}

					ip, rhErr := gw.GetAccessIP(task)
					if rhErr != nil {
						return rhErr
					}
					GatewayConfig := system.SSHConfig{
						PrivateKey: gwahc.PrivateKey,
						Port:       22,
						Host:       ip,
						User:       user,
					}
					sshConfig.GatewayConfig = &GatewayConfig
				}

				gw, sgwErr := rn.GetGateway(task, false)
				if sgwErr != nil {
					if _, ok := sgwErr.(*fail.ErrNotFound); !ok || sshConfig.GatewayConfig == nil {
						return sgwErr
					}
				} else {
					innerXErr = gw.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
						gwahc, ok = clonable.(*abstract.HostCore)
						if !ok {
							return fail.InconsistentError("'*abstract.HostFull' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}
						return nil
					})
					if innerXErr != nil {
						return innerXErr
					}
					ip, rhErr := gw.GetAccessIP(task)
					if rhErr != nil {
						return rhErr
					}
					GatewayConfig := system.SSHConfig{
						PrivateKey: gwahc.PrivateKey,
						Port:       22,
						Host:       ip,
						User:       user,
					}
					sshConfig.SecondaryGatewayConfig = &GatewayConfig
				}
			}
			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}

	return sshConfig, nil
}

// WaitServerReady waits for remote SSH server to be ready. After timeout, fails
func (handler *sshHandler) WaitServerReady(hostParam interface{}, timeout time.Duration) (xerr fail.Error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if hostParam == nil {
		return fail.InvalidParameterError("hostParam", "cannot be nil!")
	}

	task := handler.job.GetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("handlers.ssh"), "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &xerr)

	ssh, xerr := handler.GetConfig(hostParam)
	if xerr != nil {
		return xerr
	}
	_, xerr = ssh.WaitServerReady(task, "ready", timeout)
	return xerr
}

// Run tries to execute command 'cmd' on the host
func (handler *sshHandler) Run(hostRef, cmd string) (retCode int, stdOut string, stdErr string, xerr fail.Error) {
	if handler == nil {
		return -1, "", "", fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return -1, "", "", fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if hostRef == "" {
		return -1, "", "", fail.InvalidParameterError("hostRef", "cannot be empty string")
	}
	if cmd == "" {
		return -1, "", "", fail.InvalidParameterError("cmd", "cannot be empty string")
	}

	task := handler.job.GetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("handlers.ssh"), "('%s', <command>)", hostRef).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &xerr)
	tracer.Trace(fmt.Sprintf("<command>=[%s]", cmd))

	host, xerr := hostfactory.Load(task, handler.job.GetService(), hostRef)
	if xerr != nil {
		return -1, "", "", xerr
	}

	// retrieve ssh config to perform some commands
	ssh, xerr := host.GetSSHConfig(task)
	if xerr != nil {
		return -1, "", "", xerr
	}

	retryErr := retry.WhileUnsuccessfulDelay1SecondWithNotify(
		func() error {
			if handler.job.Aborted() {
				return retry.StopRetryError(nil, "operation aborted by user")
			}
			retCode, stdOut, stdErr, xerr = handler.runWithTimeout(ssh, cmd, temporal.GetHostTimeout())
			return xerr
		},
		temporal.GetHostTimeout(),
		func(t retry.Try, v verdict.Enum) {
			if v == verdict.Retry {
				logrus.Debugf("Remote SSH service on host '%s' isn't ready, retrying...", host.GetName())
			}
		},
	)
	return retCode, stdOut, stdErr, retryErr
}

// run executes command on the host
func (handler *sshHandler) runWithTimeout(ssh *system.SSHConfig, cmd string, duration time.Duration) (int, string, string, fail.Error) {
	// Create the command
	sshCmd, xerr := ssh.Command(handler.job.GetTask(), cmd)
	if xerr != nil {
		return 0, "", "", xerr
	}
	return sshCmd.RunWithTimeout(handler.job.GetTask(), outputs.DISPLAY, duration)
}

func extracthostName(in string) (string, fail.Error) {
	parts := strings.Split(in, protocolSeparator)
	if len(parts) == 1 {
		return "", nil
	}
	if len(parts) > 2 {
		return "", fail.InvalidRequestError("too many parts in path")
	}
	hostName := strings.TrimSpace(parts[0])
	for _, protocol := range []string{"file", "http", "https", "ftp"} {
		if strings.ToLower(hostName) == protocol {
			return "", fail.SyntaxError("no protocol expected. Only host name")
		}
	}

	return hostName, nil
}

func extractPath(in string) (string, fail.Error) {
	parts := strings.Split(in, protocolSeparator)
	if len(parts) == 1 {
		return in, nil
	}
	if len(parts) > 2 {
		return "", fail.InvalidRequestError("too many parts in path")
	}
	_, err := extracthostName(in)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(parts[1]), nil
}

// Copy copies file/directory from/to remote host
func (handler *sshHandler) Copy(from, to string) (retCode int, stdOut string, stdErr string, xerr fail.Error) {
	if handler == nil {
		return -1, "", "", fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return -1, "", "", fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if from == "" {
		return -1, "", "", fail.InvalidParameterError("from", "cannot be empty string")
	}
	if to == "" {
		return -1, "", "", fail.InvalidParameterError("to", "cannot be empty string")
	}

	task := handler.job.GetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("handlers.ssh"), "('%s', '%s')", from, to).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &xerr)

	hostName := ""
	var upload bool
	var localPath, remotePath string
	// Try extract host
	hostFrom, xerr := extracthostName(from)
	if xerr != nil {
		return 0, "", "", xerr
	}
	hostTo, xerr := extracthostName(to)
	if xerr != nil {
		return 0, "", "", xerr
	}

	// Host checks
	if hostFrom != "" && hostTo != "" {
		return 0, "", "", fail.NotImplementedError("copy between 2 hosts is not supported yet")
	}
	if hostFrom == "" && hostTo == "" {
		return 0, "", "", fail.InvalidRequestError("no host name specified neither in from nor to")
	}

	fromPath, xerr := extractPath(from)
	if xerr != nil {
		return 0, "", "", xerr
	}
	toPath, xerr := extractPath(to)
	if xerr != nil {
		return 0, "", "", xerr
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

	host, xerr := hostfactory.Load(task, handler.job.GetService(), hostName)
	if xerr != nil {
		return -1, "", "", xerr
	}

	// retrieve ssh config to perform some commands
	ssh, xerr := handler.GetConfig(host.GetID())
	if xerr != nil {
		return -1, "", "", xerr
	}

	cRc, cStcOut, cStdErr, cErr := ssh.Copy(handler.job.GetTask(), remotePath, localPath, upload)
	return cRc, cStcOut, cStdErr, cErr
}
