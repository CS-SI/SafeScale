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

package handlers

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	subnetfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/subnet"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/retry/enums/verdict"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const protocolSeparator = ":"

//go:generate minimock -o ../mocks/mock_sshapi.go -i github.com/CS-SI/SafeScale/lib/server/handlers.SSHHandler

// TODO: At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// SSHHandler defines ssh management API
type SSHHandler interface {
	Run(hostname, cmd string) (int, string, string, fail.Error)
	Copy(from string, to string) (int, string, string, fail.Error)
	GetConfig(stacks.HostParameter) (*system.SSHConfig, fail.Error)
}

// FIXME: ROBUSTNESS All functions MUST propagate context

// sshHandler SSH service
type sshHandler struct {
	job server.Job
}

// NewSSHHandler ...
func NewSSHHandler(job server.Job) SSHHandler {
	return &sshHandler{job: job}
}

// GetConfig creates SSHConfig to connect to an host
func (handler *sshHandler) GetConfig(hostParam stacks.HostParameter) (sshConfig *system.SSHConfig, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	task := handler.job.Task()
	svc := handler.job.Service()

	_, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nil, xerr
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.ssh"), "(%s)", hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
	defer fail.OnPanic(&xerr)

	host, xerr := hostfactory.Load(svc, hostRef)
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

	ip, xerr := host.GetAccessIP()
	if xerr != nil {
		return nil, xerr
	}

	sshConfig = &system.SSHConfig{
		Port:      22,
		IPAddress: ip,
		Hostname:  host.GetName(),
		User:      user,
	}

	isSingle, xerr := host.IsSingle()
	if xerr != nil {
		return nil, xerr
	}

	isGateway, xerr := host.IsGateway()
	if xerr != nil {
		return nil, xerr
	}

	if isSingle || isGateway {
		xerr = host.Inspect(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			ahc, ok := clonable.(*abstract.HostCore)
			if !ok {
				return fail.InconsistentError("")
			}

			sshConfig.PrivateKey = ahc.PrivateKey
			sshConfig.Port = int(ahc.SSHPort)
			return nil
		})
		if xerr != nil {
			return nil, xerr
		}
	} else {
		var rs resources.Subnet
		xerr = host.Inspect(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			ahc, ok := clonable.(*abstract.HostCore)
			if !ok {
				return fail.InconsistentError("")
			}

			sshConfig.PrivateKey = ahc.PrivateKey
			sshConfig.Port = int(ahc.SSHPort)
			return props.Inspect(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				hnV2, ok := clonable.(*propertiesv2.HostNetworking)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				if hnV2.DefaultSubnetID != "" {
					var innerXErr fail.Error
					rs, innerXErr = subnetfactory.Load(svc, "", hnV2.DefaultSubnetID)
					if innerXErr != nil {
						return innerXErr
					}
				}
				return nil
			})
		})
		if xerr != nil {
			return nil, xerr
		}
		if rs == nil {
			return nil, fail.NotFoundError("failed to find default Subnet of Host")
		}

		var (
			gwahc *abstract.HostCore
			ok    bool
		)

		// gets primary gateway information
		gw, xerr := rs.InspectGateway(true)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// Primary gateway not found ? let's try with the secondary one later...
			default:
				return nil, xerr
			}
		} else {
			xerr = gw.Inspect(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				if gwahc, ok = clonable.(*abstract.HostCore); !ok {
					return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				return nil
			})
			if xerr != nil {
				return nil, xerr
			}

			if ip, xerr = gw.GetAccessIP(); xerr != nil {
				return nil, xerr
			}
			GatewayConfig := system.SSHConfig{
				PrivateKey: gwahc.PrivateKey,
				Port:       22,
				IPAddress:  ip,
				Hostname:   gw.GetName(),
				User:       user,
			}
			sshConfig.GatewayConfig = &GatewayConfig
		}

		// gets secondary gateway information
		gw, xerr = rs.InspectGateway(false)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// If secondary gateway is not found, and previously failed to set primary gateway config, bail out
				if sshConfig.GatewayConfig == nil {
					return nil, fail.NotFoundError("failed to find a gateway to reach Host")
				}
			default:
				return nil, xerr
			}
		} else {
			xerr = gw.Inspect(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				gwahc, ok = clonable.(*abstract.HostCore)
				if !ok {
					return fail.InconsistentError("'*abstract.HostFull' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return nil
			})
			if xerr != nil {
				return nil, xerr
			}

			if ip, xerr = gw.GetAccessIP(); xerr != nil {
				return nil, xerr
			}
			GatewayConfig := system.SSHConfig{
				PrivateKey: gwahc.PrivateKey,
				Port:       22,
				IPAddress:  ip,
				Hostname:   gw.GetName(),
				User:       user,
			}
			sshConfig.SecondaryGatewayConfig = &GatewayConfig
		}
	}

	return sshConfig, nil
}

// WaitServerReady waits for remote SSH server to be ready. After timeout, fails
func (handler *sshHandler) WaitServerReady(hostParam stacks.HostParameter, timeout time.Duration) (xerr fail.Error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if hostParam == nil {
		return fail.InvalidParameterError("hostParam", "cannot be nil!")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.ssh"), "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	ssh, xerr := handler.GetConfig(hostParam)
	if xerr != nil {
		return xerr
	}
	_, xerr = ssh.WaitServerReady(task.Context(), "ready", timeout)
	return xerr
}

// Run tries to execute command 'cmd' on the host
func (handler *sshHandler) Run(hostRef, cmd string) (retCode int, stdOut string, stdErr string, xerr fail.Error) {
	const invalid = -1
	if handler == nil {
		return invalid, "", "", fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return invalid, "", "", fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if hostRef == "" {
		return invalid, "", "", fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}
	if cmd == "" {
		return invalid, "", "", fail.InvalidParameterCannotBeEmptyStringError("cmd")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.ssh"), "('%s', <command>)", hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
	tracer.Trace(fmt.Sprintf("<command>=[%s]", cmd))

	host, xerr := hostfactory.Load(handler.job.Service(), hostRef)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	// retrieve ssh config to perform some commands
	ssh, xerr := host.GetSSHConfig()
	if xerr != nil {
		return invalid, "", "", xerr
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
func (handler *sshHandler) runWithTimeout(ssh *system.SSHConfig, cmd string, duration time.Duration) (_ int, _ string, _ string, xerr fail.Error) {
	const invalid = -1

	// Create the command
	sshCmd, xerr := ssh.NewCommand(handler.job.Task().Context(), cmd)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	defer func() {
		derr := sshCmd.Close()
		if derr != nil {
			if xerr == nil {
				xerr = derr
			} else {
				_ = xerr.AddConsequence(fail.Wrap(derr, "failed to close SSH tunnel"))
			}
		}
	}()

	return sshCmd.RunWithTimeout(handler.job.Task().Context(), outputs.DISPLAY, duration)
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
	const invalid = -1

	if handler == nil {
		return invalid, "", "", fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return invalid, "", "", fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if from == "" {
		return invalid, "", "", fail.InvalidParameterCannotBeEmptyStringError("from")
	}
	if to == "" {
		return invalid, "", "", fail.InvalidParameterCannotBeEmptyStringError("to")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.ssh"), "('%s', '%s')", from, to).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	hostName := ""
	var upload bool
	var localPath, remotePath string
	// Try extract host
	hostFrom, xerr := extracthostName(from)
	if xerr != nil {
		return invalid, "", "", xerr
	}
	hostTo, xerr := extracthostName(to)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	// IPAddress checks
	if hostFrom != "" && hostTo != "" {
		return invalid, "", "", fail.NotImplementedError("copy between 2 hosts is not supported yet")
	}
	if hostFrom == "" && hostTo == "" {
		return invalid, "", "", fail.InvalidRequestError("no host name specified neither in from nor to")
	}

	fromPath, xerr := extractPath(from)
	if xerr != nil {
		return invalid, "", "", xerr
	}
	toPath, xerr := extractPath(to)
	if xerr != nil {
		return invalid, "", "", xerr
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

	host, xerr := hostfactory.Load(handler.job.Service(), hostName)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	// retrieve ssh config to perform some commands
	ssh, xerr := handler.GetConfig(host.GetID())
	if xerr != nil {
		return invalid, "", "", xerr
	}

	cRc, cStcOut, cStdErr, cErr := ssh.Copy(handler.job.Task().Context(), remotePath, localPath, upload)
	return cRc, cStcOut, cStdErr, cErr
}
