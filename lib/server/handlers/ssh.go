/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hostproperty"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/metadata"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/retry/enums/verdict"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const protocolSeparator = ":"

//go:generate mockgen -destination=../mocks/mock_sshapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers SSHAPI

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// SSHAPI defines ssh management API
type SSHAPI interface {
	// Connect(name string) error
	Run(ctx context.Context, hostname, cmd string) (int, string, string, error)
	Copy(ctx context.Context, from string, to string) (int, string, string, error)
	GetConfig(context.Context, interface{}) (*system.SSHConfig, error)
}

// SSHHandler SSH service
type SSHHandler struct {
	service iaas.Service
}

// NewSSHHandler ...
func NewSSHHandler(svc iaas.Service) *SSHHandler {
	return &SSHHandler{
		service: svc,
	}
}

// GetConfig creates SSHConfig to connect to an host
func (handler *SSHHandler) GetConfig(ctx context.Context, hostParam interface{}) (sshConfig *system.SSHConfig, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}

	var hostRef string
	host := resources.NewHost()
	switch hostParam := hostParam.(type) {
	case string:
		hostRef = hostParam
		mh, err := metadata.LoadHost(handler.service, hostRef)
		if err != nil {
			return nil, err
		}
		host, err = mh.Get()
		if err != nil {
			return nil, err
		}
	case *resources.Host:
		host = hostParam
		if host.Name != "" {
			hostRef = host.Name
		} else {
			hostRef = host.ID
		}
	}
	if host == nil {
		return nil, scerr.InvalidParameterError("hostParam", "must be a not-empty string or a *resources.Host")
	}

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("(%s)", hostRef), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	cfg, err := handler.service.GetConfigurationOptions()
	if err != nil {
		return nil, err
	}
	user := resources.DefaultUser
	if userIf, ok := cfg.Get("OperatorUsername"); ok {
		user = userIf.(string)
		if user == "" {
			logrus.Warnf("OperatorUsername is empty ! Check your tenants.toml file ! Using 'safescale' user instead.")
			user = resources.DefaultUser
		}
	}

	sshConfig = &system.SSHConfig{
		PrivateKey: host.PrivateKey,
		Port:       22,
		Host:       host.GetAccessIP(),
		User:       user,
	}

	err = host.Properties.LockForRead(hostproperty.NetworkV1).ThenUse(func(v interface{}) error {
		hostNetworkV1 := v.(*propsv1.HostNetwork)
		if hostNetworkV1.DefaultGatewayID != "" {
			hostSvc := NewHostHandler(handler.service)
			gw, err := hostSvc.Inspect(ctx, hostNetworkV1.DefaultGatewayID)
			if err != nil {
				return err
			}
			GatewayConfig := system.SSHConfig{
				PrivateKey: gw.PrivateKey,
				Port:       22,
				Host:       gw.GetAccessIP(),
				User:       user,
			}
			sshConfig.GatewayConfig = &GatewayConfig
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sshConfig.Host = host.GetAccessIP()

	return sshConfig, nil
}

// WaitServerReady waits for remote SSH server to be ready. After timeout, fails
func (handler *SSHHandler) WaitServerReady(ctx context.Context, hostParam interface{}, timeout time.Duration) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	// FIXME: validate parameters

	tracer := concurrency.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	sshSvc := NewSSHHandler(handler.service)
	ssh, err := sshSvc.GetConfig(ctx, hostParam)
	if err != nil {
		return err
	}
	_, waitErr := ssh.WaitServerReady("ready", timeout)
	return waitErr
}

// Run tries to execute command 'cmd' on the host
func (handler *SSHHandler) Run(ctx context.Context, hostName, cmd string) (retCode int, stdOut string, stdErr string, err error) {
	if handler == nil {
		return -1, "", "", scerr.InvalidInstanceError()
	}
	// FIXME: validate parameters

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s', <command>)", hostName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	tracer.Trace(fmt.Sprintf("<command>=[%s]", cmd))

	hostSvc := NewHostHandler(handler.service)
	host, err := hostSvc.ForceInspect(ctx, hostName)
	if err != nil {
		return 0, "", "", err
	}

	// retrieve ssh config to perform some commands
	ssh, err := handler.GetConfig(ctx, host)
	if err != nil {
		return 0, "", "", err
	}

	retryErr := retry.WhileUnsuccessfulDelay1SecondWithNotify(
		func() error {
			retCode, stdOut, stdErr, err = handler.runWithTimeout(ssh, cmd, temporal.GetHostTimeout())
			return err
		},
		temporal.GetHostTimeout(),
		func(t retry.Try, v verdict.Enum) {
			if v == verdict.Retry {
				logrus.Debugf("Remote SSH service on host '%s' isn't ready, retrying...\n", hostName)
			}
		},
	)
	if retryErr != nil {
		return retCode, stdOut, stdErr, retryErr
	}

	return retCode, stdOut, stdErr, err
}

// // run executes command on the host
// func (handler *SSHHandler) run(ssh *system.SSHConfig, cmd string) (int, string, string, error) {
// 	// Create the command
// 	sshCmd, err := ssh.Command(cmd)
// 	if err != nil {
// 		return 0, "", "", err
// 	}
// 	return sshCmd.Run(nil, false) // FIXME It CAN lock, use RunWithTimeout instead
// }

// run executes command on the host
func (handler *SSHHandler) runWithTimeout(ssh *system.SSHConfig, cmd string, duration time.Duration) (int, string, string, error) {
	// Create the command
	sshCmd, err := ssh.Command(cmd)
	if err != nil {
		return 0, "", "", err
	}
	return sshCmd.RunWithTimeout(nil, outputs.DISPLAY, duration)
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
func (handler *SSHHandler) Copy(ctx context.Context, from, to string) (retCode int, stdOut string, stdErr string, err error) {
	if handler == nil {
		return -1, "", "", scerr.InvalidInstanceError()
	}
	// FIXME: validate parameters

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s')", from, to), true).WithStopwatch().GoingIn()
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

	hostSvc := NewHostHandler(handler.service)
	host, err := hostSvc.ForceInspect(ctx, hostName)
	if err != nil {
		return 0, "", "", err
	}

	// retrieve ssh config to perform some commands
	ssh, err := handler.GetConfig(ctx, host.ID)
	if err != nil {
		return 0, "", "", err
	}

	cRc, cStcOut, cStdErr, cErr := ssh.Copy(remotePath, localPath, upload)
	return cRc, cStcOut, cStdErr, cErr
}
