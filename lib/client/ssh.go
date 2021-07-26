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

package client

import (
	"fmt"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/retry/enums/verdict"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// ssh is the part of the safescale client that handles SSH stuff
type ssh struct {
	// session is not used currently
	session *Session
}

// Run executes the command
func (s ssh) Run(hostName, command string, outs outputs.Enum, connectionTimeout, executionTimeout time.Duration) (int, string, string, fail.Error) {
	const invalid = -1
	var (
		retcode        int
		stdout, stderr string
	)

	sshCfg, err := s.getHostSSHConfig(hostName)
	if err != nil {
		return invalid, "", "", err
	}

	if connectionTimeout < DefaultConnectionTimeout {
		connectionTimeout = DefaultConnectionTimeout
	}
	if connectionTimeout > executionTimeout { // FIXME: Think about it
		connectionTimeout = executionTimeout + temporal.GetContextTimeout()
	}

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	// Create the command
	retryErr := retry.WhileUnsuccessfulDelay1SecondWithNotify(
		func() (innerErr error) {
			sshCmd, innerXErr := sshCfg.NewCommand(ctx, command)
			if innerXErr != nil {
				return innerXErr
			}

			defer func(cmd *system.SSHCommand) {
				derr := cmd.Close()
				if derr != nil {
					if innerErr == nil {
						innerErr = derr
					} else {
						innerXErr = fail.ConvertError(innerErr)
						_ = innerXErr.AddConsequence(fail.Wrap(derr, "failed to close SSH tunnel"))
						innerErr = innerXErr
					}
				}
			}(sshCmd)

			retcode, stdout, stderr, innerXErr = sshCmd.RunWithTimeout(ctx, outs, executionTimeout)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotAvailable:
					return innerXErr
					// ready = false
				case *fail.ErrTimeout:
					return innerXErr
				default:
					// stop the loop and propagate the error
					retcode = -1
					return retry.StopRetryError(innerXErr)
				}
			}
			// If retcode == 255, ssh connection failed, retry
			if retcode == 255 /*|| !ready*/ {
				return fail.NotAvailableError("Remote SSH server on Host '%s' is not available, failed to connect", sshCfg.Hostname)
			}
			return nil
		},
		connectionTimeout,
		func(t retry.Try, v verdict.Enum) {
			if v == verdict.Retry {
				logrus.Infof("Remote SSH service on host '%s' isn't ready, retrying...\n", hostName)
			}
		},
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return invalid, "", "", fail.ConvertError(retryErr.Cause())
		default:
			return invalid, "", "", retryErr
		}
	}
	return retcode, stdout, stderr, nil
}

func (s ssh) getHostSSHConfig(hostname string) (*system.SSHConfig, fail.Error) {
	host := &host{session: s.session}
	cfg, err := host.SSHConfig(hostname)
	if err != nil {
		return nil, fail.ConvertError(err)
	}
	return cfg, nil
}

const protocolSeparator = ":"

func extracthostName(in string) (string, fail.Error) {
	parts := strings.Split(in, protocolSeparator)
	if len(parts) == 1 {
		return "", nil
	}
	if len(parts) > 2 {
		return "", fail.OverflowError(nil, 2, "too many parts in path")
	}
	hostName := strings.TrimSpace(parts[0])
	for _, proto := range []string{"file", "http", "https", "ftp"} {
		if strings.ToLower(hostName) == proto {
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
		return "", fail.OverflowError(nil, 2, "too many parts in path")
	}
	_, xerr := extracthostName(in)
	if xerr != nil {
		return "", xerr
	}

	return strings.TrimSpace(parts[1]), nil
}

// Copy ...
func (s ssh) Copy(from, to string, connectionTimeout, executionTimeout time.Duration) (int, string, string, fail.Error) {
	const invalid = -1
	if from == "" {
		return invalid, "", "", fail.InvalidParameterCannotBeEmptyStringError("from")
	}
	if to == "" {
		return invalid, "", "", fail.InvalidParameterCannotBeEmptyStringError("to")
	}

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
		return invalid, "", "", fail.NotImplementedError("no host name specified neither in from nor to")
	}

	fromPath, rerr := extractPath(from)
	if rerr != nil {
		return invalid, "", "", rerr
	}
	toPath, rerr := extractPath(to)
	if rerr != nil {
		return invalid, "", "", rerr
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

	sshCfg, xerr := s.getHostSSHConfig(hostName)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	if executionTimeout < temporal.GetHostTimeout() {
		executionTimeout = temporal.GetHostTimeout()
	}
	if connectionTimeout < DefaultConnectionTimeout {
		connectionTimeout = DefaultConnectionTimeout
	}
	if connectionTimeout > executionTimeout {
		connectionTimeout = executionTimeout
	}

	task, xerr := s.session.GetTask()
	if xerr != nil {
		return invalid, "", "", xerr
	}
	ctx := task.Context()

	var (
		retcode        int
		stdout, stderr string
	)
	retryErr := retry.WhileUnsuccessful(
		func() error {
			retcode, stdout, stderr, xerr = sshCfg.CopyWithTimeout(ctx, remotePath, localPath, upload, executionTimeout)
			// If an error occurred, stop the loop and propagates this error
			if xerr != nil {
				retcode = -1
				return nil
			}
			// If retcode == 255, ssh connection failed, retry
			if retcode == 255 {
				xerr = fail.NewError("failure copying '%s' to '%s': failed to connect to '%s'", toPath, hostTo, hostTo)
				return xerr
			}
			return nil
		},
		temporal.GetMinDelay(),
		connectionTimeout,
	)
	if retryErr != nil {
		switch cErr := retryErr.(type) { // nolint
		case *retry.ErrTimeout:
			return invalid, "", "", cErr
		}
	}
	return retcode, stdout, stderr, retryErr
}

// getSSHConfigFromName ...
func (s ssh) getSSHConfigFromName(name string, _ time.Duration) (*system.SSHConfig, fail.Error) {
	s.session.Connect()
	defer s.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewHostServiceClient(s.session.connection)
	sshConfig, err := service.SSH(ctx, &protocol.Reference{Name: name})
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	return converters.SSHConfigFromProtocolToSystem(sshConfig), nil
}

// Connect ...
func (s ssh) Connect(hostname, username, shell string, timeout time.Duration) error {
	sshCfg, xerr := s.getSSHConfigFromName(hostname, timeout)
	if xerr != nil {
		return xerr
	}

	return retry.WhileUnsuccessfulWhereRetcode255Delay5SecondsWithNotify(
		func() error {
			return sshCfg.Enter(username, shell)
		},
		temporal.GetConnectSSHTimeout(),
		func(t retry.Try, v verdict.Enum) {
			if v == verdict.Retry {
				logrus.Infof("Remote SSH service on host '%s' isn't ready, retrying...", hostname)
			}
		},
	)
}

func (s ssh) CreateTunnel(name string, localPort int, remotePort int, timeout time.Duration) error {
	sshCfg, xerr := s.getSSHConfigFromName(name, timeout)
	if xerr != nil {
		return xerr
	}

	if sshCfg.GatewayConfig == nil {
		sshCfg.GatewayConfig = &system.SSHConfig{
			User:          sshCfg.User,
			IPAddress:     sshCfg.IPAddress,
			Hostname:      sshCfg.Hostname,
			PrivateKey:    sshCfg.PrivateKey,
			Port:          sshCfg.Port,
			GatewayConfig: nil,
		}
	}
	sshCfg.IPAddress = "127.0.0.1"
	sshCfg.Port = remotePort
	sshCfg.LocalPort = localPort

	return retry.WhileUnsuccessfulWhereRetcode255Delay5SecondsWithNotify(
		func() error {
			_, _, innerErr := sshCfg.CreateTunneling()
			return innerErr
		},
		temporal.GetConnectSSHTimeout(),
		func(t retry.Try, v verdict.Enum) {
			if v == verdict.Retry {
				logrus.Infof("Remote SSH service on host '%s' isn't ready, retrying...\n", name)
			}
		},
	)
}

func (s ssh) CloseTunnels(name string, localPort string, remotePort string, timeout time.Duration) error {
	sshCfg, xerr := s.getSSHConfigFromName(name, timeout)
	if xerr != nil {
		return xerr
	}

	if sshCfg.GatewayConfig == nil {
		sshCfg.GatewayConfig = &system.SSHConfig{
			User:          sshCfg.User,
			IPAddress:     sshCfg.IPAddress,
			Hostname:      sshCfg.Hostname,
			PrivateKey:    sshCfg.PrivateKey,
			Port:          sshCfg.Port,
			GatewayConfig: nil,
		}
		sshCfg.IPAddress = "127.0.0.1"
	}

	cmdString := fmt.Sprintf("ssh .* %s:%s:%s %s@%s .*", localPort, sshCfg.IPAddress, remotePort, sshCfg.GatewayConfig.User, sshCfg.GatewayConfig.IPAddress)

	bytes, err := exec.Command("pgrep", "-f", cmdString).Output()
	if err == nil {
		portStrs := strings.Split(strings.Trim(string(bytes), "\n"), "\n")
		for _, portStr := range portStrs {
			_, err = strconv.Atoi(portStr)
			if err != nil {
				logrus.Errorf("atoi failed on pid: %s", reflect.TypeOf(err).String())
				return fail.Wrap(err, "unable to close tunnel")
			}
			err = exec.Command("kill", "-9", portStr).Run()
			if err != nil {
				logrus.Errorf("kill -9 failed: %s\n", reflect.TypeOf(err).String())
				return fail.Wrap(err, "unable to close tunnel")
			}
		}
	}

	return nil
}

// WaitReady waits the SSH service of remote host is ready, for 'timeout' duration
func (s ssh) WaitReady( /*ctx context.Context, */ hostName string, timeout time.Duration) error {
	task, xerr := s.session.GetTask()
	if xerr != nil {
		return xerr
	}
	ctx := task.Context()

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	if timeout < temporal.GetHostTimeout() {
		timeout = temporal.GetHostTimeout()
	}
	sshCfg, err := s.getHostSSHConfig(hostName)
	if err != nil {
		return err
	}

	_, xerr = sshCfg.WaitServerReady(ctx, "ready", timeout)
	return xerr
}
