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
    "github.com/CS-SI/SafeScale/lib/utils/concurrency"
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
    // if s == nil {
    //     return -1, "", "", fail.InvalidInstanceError()
    // }

    task, xerr := s.session.GetTask()
    if xerr != nil {
        return -1, "", "", xerr
    }

    var (
        retcode        int
        stdout, stderr string
    )

    sshCfg, err := s.getHostSSHConfig(hostName)
    if err != nil {
        return -1, "", "", err
    }

    if executionTimeout < temporal.GetHostTimeout() {
        executionTimeout = temporal.GetHostTimeout()
    }
    if connectionTimeout < DefaultConnectionTimeout {
        connectionTimeout = DefaultConnectionTimeout
    }
    if connectionTimeout > executionTimeout {
        connectionTimeout = executionTimeout + temporal.GetContextTimeout()
    }

    // _, cancel, err := utils.GetTimeoutContext(executionTimeout)
    // if err != nil {
    // 	return -1, "", "", err
    // }
    // defer cancel()

    // Create the command
    sshCmd, xerr := sshCfg.Command(task, command)
    if xerr != nil {
        return -1, "", "", xerr
    }

    retryErr := retry.WhileUnsuccessfulDelay1SecondWithNotify(
        func() error {
            var innerErr fail.Error
            retcode, stdout, stderr, innerErr = sshCmd.RunWithTimeout(task, outs, executionTimeout)

            // If an error occurred and is not a timeout one, stop the loop and propagates this error
            if innerErr != nil {
                if _, ok := innerErr.(*fail.ErrTimeout); ok {
                    return innerErr
                }
                retcode = -1
                return retry.StopRetryError(innerErr)
            }
            // If retcode == 255, ssh connection failed, retry
            if retcode == 255 {
                return fail.NewError("failed to connect")
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
        if realErr, ok := retryErr.(*retry.ErrStopRetry); ok {
            return -1, "", "", fail.ToError(realErr.Cause())
        }
        return -1, "", "", retryErr
    }
    return retcode, stdout, stderr, nil
}

func (s ssh) getHostSSHConfig(hostname string) (*system.SSHConfig, fail.Error) {
    host := &host{session: s.session}
    cfg, err := host.SSHConfig(hostname)
    if err != nil {
        return nil, fail.ToError(err)
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
    // if s == nil {
    //     return -1, "", "", fail.InvalidInstanceError()
    // }
    if from == "" {
        return -1, "", "", fail.InvalidParameterError("from", "cannot be nil")
    }
    if to == "" {
        return -1, "", "", fail.InvalidParameterError("to", "cannot be nil")
    }

    task, xerr := s.session.GetTask()
    if xerr != nil {
        return -1, "", "", xerr
    }

    hostName := ""
    var upload bool
    var localPath, remotePath string
    // Try extract host
    hostFrom, xerr := extracthostName(from)
    if xerr != nil {
        return -1, "", "", xerr
    }
    hostTo, xerr := extracthostName(to)
    if xerr != nil {
        return -1, "", "", xerr
    }

    // Host checks
    if hostFrom != "" && hostTo != "" {
        return -1, "", "", fail.NotImplementedError("copy between 2 hosts is not supported yet")
    }
    if hostFrom == "" && hostTo == "" {
        return -1, "", "", fail.NotImplementedError("no host name specified neither in from nor to")
    }

    fromPath, rerr := extractPath(from)
    if rerr != nil {
        return -1, "", "", rerr
    }
    toPath, rerr := extractPath(to)
    if rerr != nil {
        return -1, "", "", rerr
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
        return -1, "", "", xerr
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

    // _, cancel, err := utils.GetTimeoutContext(executionTimeout)
    // if err != nil {
    // 	return -1, "", "", err
    // }
    // defer cancel()

    var (
        retcode        int
        stdout, stderr string
    )
    retryErr := retry.WhileUnsuccessful(
        func() error {
            retcode, stdout, stderr, xerr = sshCfg.CopyWithTimeout(task, remotePath, localPath, upload, executionTimeout)
            // If an error occurred, stop the loop and propagates this error
            if xerr != nil {
                retcode = -1
                return nil
            }
            // If retcode == 255, ssh connection failed, retry
            if retcode == 255 {
                xerr = fail.NewError("failed to connect")
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
            return -1, "", "", cErr
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
        return nil, fail.ToError(err)
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
            Host:          sshCfg.Host,
            PrivateKey:    sshCfg.PrivateKey,
            Port:          sshCfg.Port,
            GatewayConfig: nil,
        }
    }
    sshCfg.Host = "127.0.0.1"
    sshCfg.Port = remotePort
    sshCfg.LocalPort = localPort

    return retry.WhileUnsuccessfulWhereRetcode255Delay5SecondsWithNotify(
        func() error {
            tunnels, _, err := sshCfg.CreateTunneling()
            if err != nil {
                for _, t := range tunnels {
                    nerr := t.Close()
                    if nerr != nil {
                        logrus.Errorf("error closing ssh tunnel: %v", nerr)
                    }
                }
                return fail.Wrap(err, "unable to create command")
            }
            return nil
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
            Host:          sshCfg.Host,
            PrivateKey:    sshCfg.PrivateKey,
            Port:          sshCfg.Port,
            GatewayConfig: nil,
        }
        sshCfg.Host = "127.0.0.1"
    }

    cmdString := fmt.Sprintf("ssh .* %s:%s:%s %s@%s .*", localPort, sshCfg.Host, remotePort, sshCfg.GatewayConfig.User, sshCfg.GatewayConfig.Host)

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
func (s ssh) WaitReady(task concurrency.Task, hostName string, timeout time.Duration) error {
    if timeout < temporal.GetHostTimeout() {
        timeout = temporal.GetHostTimeout()
    }
    sshCfg, err := s.getHostSSHConfig(hostName)
    if err != nil {
        return err
    }

    _, xerr := sshCfg.WaitServerReady(task, "ready", timeout)
    return xerr
}
