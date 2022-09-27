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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmdline

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/common"
	"github.com/sirupsen/logrus"

	sshfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/ssh"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh"
	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry/enums/verdict"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// ssh is the part of the safescale client that handles SSH stuff
type sshConsumer struct {
	session *Session
}

// Run executes the command
func (s sshConsumer) Run(hostName, command string, outs outputs.Enum, connectionTimeout, executionTimeout time.Duration) (int, string, string, fail.Error) {
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

	ctx, xerr := common.ContextForGRPC(true)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	sshConn, xerr := sshfactory.NewConnector(sshCfg)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	// Create the command
	retryErr := retry.WhileUnsuccessfulWithNotify(
		func() (innerErr error) {
			var sshCmd sshapi.Command
			var innerXErr fail.Error
			defer func() {
				if sshCmd != nil {
					_ = sshCmd.Close()
				}
			}()

			sshCmd, innerXErr = sshConn.NewCommand(ctx, command)
			if innerXErr != nil {
				return innerXErr
			}
			retcode, stdout, stderr, innerXErr = sshCmd.RunWithTimeout(
				ctx, outs, executionTimeout,
			)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotAvailable:
					return innerXErr
				case *fail.ErrTimeout:
					return innerXErr
				default:
					// stop the loop and propagate the error
					retcode = -1
					return retry.StopRetryError(innerXErr)
				}
			}

			if retcode == 255 { // ssh connection drop
				hn, _ := sshCfg.GetHostname()
				return fail.NotAvailableError("Remote SSH currentServer on Host '%s' is not available, failed to connect", hn)
			}

			return nil
		},
		temporal.MinDelay(),
		connectionTimeout,
		func(t retry.Try, v verdict.Enum) {
			if v == verdict.Retry {
				if t.Err != nil {
					logrus.Debugf("Remote SSH service on host '%s' isn't ready (%s), retrying...\n", hostName, t.Err.Error())
				} else {
					logrus.Debugf("Remote SSH service on host '%s' isn't ready, retrying...", hostName)
				}
			}
		},
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return invalid, "", "", fail.Wrap(fail.Cause(retryErr))
		case *retry.ErrTimeout:
			return invalid, "", "", fail.Wrap(retryErr)
		default:
			return invalid, "", "", retryErr
		}
	}
	return retcode, stdout, stderr, nil
}

func (s sshConsumer) getHostSSHConfig(hostname string) (sshapi.Config, fail.Error) {
	hostConsumer := s.session.Host
	cfg, err := hostConsumer.SSHConfig(hostname)
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

func getMD5Hash(text string) string {
	hasher := md5.New()
	_, err := hasher.Write([]byte(text))
	if err != nil {
		return ""
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

// Copy ...
func (s sshConsumer) Copy(from, to string, connectionTimeout, executionTimeout time.Duration) (int, string, string, fail.Error) {
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

	// Host checks
	if hostFrom != "" && hostTo != "" {
		return invalid, "", "", fail.NotImplementedError("copy between 2 hosts is not supported yet") // FIXME: Technical debt
	}
	if hostFrom == "" && hostTo == "" {
		return invalid, "", "", fail.NotImplementedError("no host name specified neither in from nor to") // FIXME: Technical debt
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

	sshConn, xerr := sshfactory.NewConnector(sshCfg)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	if executionTimeout < temporal.HostOperationTimeout() && executionTimeout != 0 {
		executionTimeout = temporal.HostOperationTimeout()
	}
	if connectionTimeout < DefaultConnectionTimeout {
		connectionTimeout = DefaultConnectionTimeout
	}

	task, xerr := s.session.GetTask()
	if xerr != nil {
		return invalid, "", "", xerr
	}
	ctx := task.Context()

	var (
		stdout, stderr string
	)

	extendedTimeout := connectionTimeout + 2*executionTimeout
	if executionTimeout == 0 {
		extendedTimeout = connectionTimeout + 2*temporal.HostOperationTimeout()
	}

	retcode := -1
	retryErr := retry.WhileUnsuccessful(
		func() error {
			iretcode, istdout, istderr, xerr := sshConn.CopyWithTimeout(
				ctx, remotePath, localPath, upload, executionTimeout,
			)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				if strings.Contains(xerr.Error(), "permission denied") {
					return retry.StopRetryError(xerr, "permission denied trying to copy '%s' to '%s'", localPath, remotePath)
				}

				return xerr
			}

			logrus.Debugf("Checking MD5 of remote file...")
			if iretcode == 1 {
				deleteRemoteFile := func() fail.Error {
					crcCtx, cancelCrc := context.WithTimeout(ctx, executionTimeout)
					defer cancelCrc()

					if upload {
						var crcCmd sshapi.Command
						var finnerXerr fail.Error
						defer func() {
							if crcCmd != nil {
								_ = crcCmd.Close()
							}
						}()

						crcCmd, finnerXerr = sshConn.NewCommand(crcCtx, fmt.Sprintf("sudo rm %s", remotePath))
						if finnerXerr != nil {
							return finnerXerr
						}

						fretcode, fstdout, fstderr, finnerXerr := crcCmd.RunWithTimeout(
							crcCtx, outputs.COLLECT, executionTimeout,
						)
						finnerXerr = debug.InjectPlannedFail(finnerXerr)
						if finnerXerr != nil {
							finnerXerr.Annotate("retcode", fretcode)
							finnerXerr.Annotate("stdout", fstdout)
							finnerXerr.Annotate("stderr", fstderr)
							return finnerXerr
						}
						if fretcode != 0 {
							finnerXerr = fail.NewError("failed to remove file")
							finnerXerr.Annotate("retcode", fretcode)
							finnerXerr.Annotate("stdout", fstdout)
							finnerXerr.Annotate("stderr", fstderr)
							return finnerXerr
						}
					}

					return nil
				}

				if strings.Contains(istdout, "Permission denied") || strings.Contains(istderr, "Permission denied") {
					if upload {
						derr := deleteRemoteFile()
						if derr != nil {
							logrus.Debugf("there was an error trying to delete the file: %s", derr)
						}
						return fmt.Errorf("permission denied")
					}
					return retry.StopRetryError(fmt.Errorf("permission denied"))
				}

				if strings.Contains(istdout, "No such file or directory") || strings.Contains(istderr, "No such file or directory") {
					return retry.StopRetryError(fmt.Errorf("permission denied"))
				}
			}

			if iretcode != 0 {
				xerr = fail.NewError("failure copying '%s' to '%s': scp error code %d", toPath, hostTo, iretcode)
				xerr.Annotate("stdout", istdout)
				xerr.Annotate("stderr", istderr)
				xerr.Annotate("retcode", iretcode)

				return xerr
			}

			{
				crcCheck := func() fail.Error {
					md5hash := ""
					if localPath != "" {
						content, err := ioutil.ReadFile(localPath)
						if err != nil {
							return fail.WarningError(err, "unable ro read file %s", localPath)
						}
						md5hash = getMD5Hash(string(content))
						if md5hash == "" {
							return fail.WarningError(fmt.Errorf("failure getting MD5 hash"))
						}
					}

					crcCtx, cancelCrc := context.WithTimeout(ctx, executionTimeout)
					defer cancelCrc()

					var crcCmd sshapi.Command
					var finnerXerr fail.Error
					defer func() {
						if crcCmd != nil {
							_ = crcCmd.Close()
						}
					}()

					crcCmd, finnerXerr = sshConn.NewCommand(crcCtx, fmt.Sprintf("/usr/bin/md5sum %s", remotePath))
					if finnerXerr != nil {
						return fail.WarningError(finnerXerr, "failure creating md5 command")
					}
					fretcode, fstdout, fstderr, finnerXerr := crcCmd.RunWithTimeout(
						crcCtx, outputs.COLLECT, executionTimeout,
					)
					finnerXerr = debug.InjectPlannedFail(finnerXerr)
					if finnerXerr != nil {
						finnerXerr.Annotate("retcode", fretcode)
						finnerXerr.Annotate("stdout", fstdout)
						finnerXerr.Annotate("stderr", fstderr)
						return fail.WarningError(finnerXerr, "failure running remote md5 command")
					}
					if fretcode != 0 {
						finnerXerr = fail.NewError("failed to check md5")
						finnerXerr.Annotate("retcode", fretcode)
						finnerXerr.Annotate("stdout", fstdout)
						finnerXerr.Annotate("stderr", fstderr)
						return fail.WarningError(finnerXerr, "unexpected error code running remote md5 command")
					}
					if !strings.Contains(fstdout, md5hash) {
						logrus.Warnf(
							"WRONG MD5, Tried 'md5sum %s' We got '%s' and '%s', the original was '%s'", remotePath,
							fstdout, fstderr, md5hash,
						)
						return fail.NewError("wrong md5 of '%s'", remotePath)
					}
					return nil
				}

				if xerr = crcCheck(); xerr != nil {
					if _, ok := xerr.(*fail.ErrWarning); !ok || valid.IsNil(xerr) {
						return xerr
					}
					logrus.Warnf(xerr.Error())
				}
			}

			retcode = iretcode
			stdout = istdout
			stderr = istderr

			return nil
		},
		temporal.MinDelay(),
		extendedTimeout,
	)
	if retryErr != nil {
		switch cErr := retryErr.(type) { // nolint
		case *retry.ErrStopRetry:
			return invalid, "", "", fail.Wrap(fail.Cause(retryErr))
		case *retry.ErrTimeout:
			return invalid, "", "", cErr
		}
	}
	return retcode, stdout, stderr, retryErr
}

// getSSHConfigFromName ...
func (s sshConsumer) getSSHConfigFromName(name string, _ time.Duration) (sshapi.Config, fail.Error) {
	s.session.Connect()
	defer s.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
	if xerr != nil {
		return nil, xerr
	}

	req := &protocol.Reference{
		Organization: s.session.currentOrganization,
		Project:      s.session.currentProject,
		TenantId:     s.session.currentTenant,
		Name:         name,
	}
	service := protocol.NewHostServiceClient(s.session.connection)
	sshConfig, err := service.SSH(ctx, req)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	return converters.SSHConfigFromProtocolToSystem(sshConfig), nil
}

// Connect is the "safescale ssh connect"
func (s sshConsumer) Connect(hostname, username, shell string, timeout time.Duration) error {
	sshCfg, xerr := s.getSSHConfigFromName(hostname, timeout) // timeout is ignored here
	if xerr != nil {
		return xerr
	}

	return retry.WhileUnsuccessfulWithAggregator(
		func() error {
			sshConn, xerr := sshfactory.NewConnector(sshCfg)
			if xerr != nil {
				return xerr
			}

			return sshConn.Enter(context.Background(), username, shell)
		},
		temporal.DefaultDelay(),
		temporal.SSHConnectionTimeout(),
		retry.OrArbiter, // if sshCfg.Ender succeeds, we don't care about the timeout
		func(t retry.Try, v verdict.Enum) {
			if v == verdict.Retry {
				if t.Err != nil {
					logrus.Debugf("Remote SSH service on host '%s' isn't ready (%s), retrying...", hostname, t.Err.Error())
				} else {
					logrus.Debugf("Remote SSH service on host '%s' isn't ready, retrying...", hostname)
				}
			}
		},
	)
}

func (s sshConsumer) CreateTunnel(name string, localPort int, remotePort int, timeout time.Duration) error {
	sshCfg, xerr := s.getSSHConfigFromName(name, timeout)
	if xerr != nil {
		return xerr
	}

	ncfg, xerr := ssh.NewConfigFrom(sshCfg)
	if xerr != nil {
		return xerr
	}

	if ncfg.GatewayConfig == nil {
		ncfg.GatewayConfig = ssh.NewConfig(ncfg.Hostname, ncfg.IPAddress, ncfg.Port, ncfg.User, ncfg.PrivateKey, 0, "", nil, nil)
	}
	ncfg.Port = remotePort
	ncfg.LocalPort = localPort

	return retry.WhileUnsuccessfulWithNotify(
		func() error {
			sshConn, xerr := sshfactory.NewConnector(ncfg, sshfactory.ConnectorWithCli())
			if xerr != nil {
				return xerr
			}

			innerErr := sshConn.CreatePersistentTunneling()
			return innerErr
		},
		temporal.DefaultDelay(),
		temporal.SSHConnectionTimeout(),
		func(t retry.Try, v verdict.Enum) {
			if v == verdict.Retry {
				if t.Err != nil {
					logrus.Debugf("Remote SSH service on host '%s' isn't ready (%s), retrying...\n", name, t.Err.Error())
				} else {
					logrus.Debugf("Remote SSH service on host '%s' isn't ready, retrying...", name)
				}
			}
		},
	)
}

// CloseTunnels closes a tunnel created in the machine 'name'
func (s sshConsumer) CloseTunnels(name string, localPort uint16, remotePort uint16, timeout time.Duration) error {
	acfg, xerr := s.getSSHConfigFromName(name, timeout)
	if xerr != nil {
		return xerr
	}

	ncfg, _ := ssh.NewConfigFrom(acfg)
	if ncfg.GatewayConfig == nil {
		ncfg.GatewayConfig = ssh.NewConfig(ncfg.Hostname, ncfg.IPAddress, ncfg.Port, ncfg.User, ncfg.PrivateKey, 0, "", nil, nil)
		ncfg.IPAddress = ssh.Loopback
	}

	ngu, _ := ncfg.GatewayConfig.GetUser()
	ngi, _ := ncfg.GatewayConfig.GetIPAddress()
	cmdString := fmt.Sprintf("ssh .* %d:%s:%d %s@%s .*", localPort, ncfg.IPAddress, remotePort, ngu, ngi)

	bytes, err := exec.Command("pgrep", "-f", cmdString).Output()
	if err != nil {
		_, code, problem := utils.ExtractRetCode(err)
		if problem != nil {
			return fail.Wrap(err, "unable to close tunnel, running pgrep")
		}
		if code == 1 { // no process found
			debug.IgnoreError(err)
			return nil
		}
		if code == 127 { // pgrep not installed
			debug.IgnoreError(fmt.Errorf("pgrep not installed"))
			return nil
		}
		return fail.Wrap(err, "unable to close tunnel, unexpected errorcode running pgrep: %d", code)
	}

	portStrs := strings.Split(strings.Trim(string(bytes), "\n"), "\n")
	for _, portStr := range portStrs {
		_, err = strconv.Atoi(portStr)
		if err != nil {
			return fail.Wrap(err, "unable to close tunnel: %s", fmt.Sprintf("atoi failed on pid: %s", reflect.TypeOf(err).String()))
		}
		err = exec.Command("kill", "-9", portStr).Run()
		if err != nil {
			return fail.Wrap(err, "unable to close tunnel: %s", fmt.Sprintf("kill -9 failed: %s\n", reflect.TypeOf(err).String()))
		}
	}

	return nil
}
