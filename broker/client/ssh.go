/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
	"log"
	"strings"
	"time"

	pb "github.com/CS-SI/SafeScale/broker"
	conv "github.com/CS-SI/SafeScale/broker/utils"
	utils "github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/system"
	"github.com/CS-SI/SafeScale/utils/retry"
	"github.com/CS-SI/SafeScale/utils/retry/Verdict"
)

// ssh is the part of the broker client that handles SSH stuff
type ssh struct {
	// session is not used currently
	session *Session
}

// func systemSSH(bsc *broker.SshConfig, err error) (*system.SSHConfig, error) {
// 	if err != nil {
// 		return nil, err
// 	}
// 	if bsc == nil {
// 		return nil, nil
// 	}

// 	g, _ := systemSSH(bsc.Gateway, nil)
// 	return &system.SSHConfig{
// 		GatewayConfig: g,
// 		Host:          bsc.Host,
// 		Port:          int(bsc.Port),
// 		PrivateKey:    bsc.PrivateKey,
// 		User:          bsc.User,
// 	}, nil
// }

// Run ...
func (s *ssh) Run(hostName, command string, connectionTimeout, executionTimeout time.Duration) (int, string, string, error) {
	var (
		retcode        int
		stdout, stderr string
	)

	sshCfg, err := s.getHostSSHConfig(hostName)
	if err != nil {
		return 0, "", "", err
	}

	if executionTimeout < utils.TimeoutCtxHost {
		executionTimeout = utils.TimeoutCtxHost
	}
	if connectionTimeout < DefaultConnectionTimeout {
		connectionTimeout = DefaultConnectionTimeout
	}
	if connectionTimeout > executionTimeout {
		connectionTimeout = executionTimeout + 1*time.Minute
	}

	_, cancel := utils.GetContext(executionTimeout)
	defer cancel()

	retryErr := retry.WhileUnsuccessfulDelay1SecondWithNotify(
		func() error {
			// Create the command
			var sshCmd *system.SSHCommand
			sshCmd, err := sshCfg.Command(command)
			if err != nil {
				return err
			}
			retcode, stdout, stderr, err = sshCmd.Run()
			// If an error occured, stop the loop and propagates this error
			if err != nil {
				retcode = -1
				return nil
			}
			// If retcode == 255, ssh connection failed, retry
			if retcode == 255 {
				return fmt.Errorf("failed to connect")
			}
			return nil
		},
		connectionTimeout,
		func(t retry.Try, v Verdict.Enum) {
			if v == Verdict.Retry {
				log.Printf("Remote SSH service on host '%s' isn't ready, retrying...\n", hostName)
			}
		},
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			return -1, "", "", fmt.Errorf("failed to connect after %v", connectionTimeout)
		}
	}
	return retcode, stdout, stderr, err
}

func (s *ssh) getHostSSHConfig(hostname string) (*system.SSHConfig, error) {
	host := &host{session: s.session}
	cfg, err := host.SSHConfig(hostname)
	if err != nil {
		return nil, err
	}
	return conv.ToSystemSshConfig(cfg), nil
}

const protocolSeparator = ":"

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

// Copy ...
func (s *ssh) Copy(from, to string, connectionTimeout, executionTimeout time.Duration) (int, string, string, error) {
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
		return -1, "", "", fmt.Errorf("copy between 2 hosts is not supported yet")
	}
	if hostFrom == "" && hostTo == "" {
		return -1, "", "", fmt.Errorf("no host name specified neither in from nor to")
	}

	fromPath, err := extractPath(from)
	if err != nil {
		return -1, "", "", err
	}
	toPath, err := extractPath(to)
	if err != nil {
		return -1, "", "", err
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

	sshCfg, err := s.getHostSSHConfig(hostName)
	if err != nil {
		return 0, "", "", err
	}

	if executionTimeout < utils.TimeoutCtxHost {
		executionTimeout = utils.TimeoutCtxHost
	}
	if connectionTimeout < DefaultConnectionTimeout {
		connectionTimeout = DefaultConnectionTimeout
	}
	if connectionTimeout > executionTimeout {
		connectionTimeout = executionTimeout
	}

	_, cancel := utils.GetContext(executionTimeout)
	defer cancel()

	var (
		retcode        int
		stdout, stderr string
	)
	retryErr := retry.WhileUnsuccessful(
		func() error {
			retcode, stdout, stderr, err = sshCfg.Copy(remotePath, localPath, upload)
			// If an error occured, stop the loop and propagates this error
			if err != nil {
				retcode = -1
				return nil
			}
			// If retcode == 255, ssh connection failed, retry
			if retcode == 255 {
				err = fmt.Errorf("failed to connect")
				return err
			}
			return nil
		},
		1*time.Second,
		connectionTimeout,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			return -1, "", "", fmt.Errorf("failed to connect after %v", err.Error())
		}
	}
	return retcode, stdout, stderr, err
}

// Connect ...
func (s *ssh) Connect(name string, timeout time.Duration) error {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxHost {
		timeout = utils.TimeoutCtxHost
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()

	service := pb.NewHostServiceClient(conn)
	sshConfig, err := service.SSH(ctx, &pb.Reference{Name: name})
	if err != nil {
		return err
	}
	sshCfg := conv.ToSystemSshConfig(sshConfig)

	return retry.WhileUnsuccessful255Delay5SecondsWithNotify(
		func() error {
			return sshCfg.Enter()
		},
		2*time.Minute,
		func(t retry.Try, v Verdict.Enum) {
			if v == Verdict.Retry {
				log.Printf("Remote SSH service on host '%s' isn't ready, retrying...\n", name)
			}
		},
	)
}

// WaitReady waits the SSH service of remote host is ready, for 'timeout' duration
func (s *ssh) WaitReady(hostName string, timeout time.Duration) error {
	if timeout < utils.TimeoutCtxHost {
		timeout = utils.TimeoutCtxHost
	}
	sshCfg, err := s.getHostSSHConfig(hostName)
	if err != nil {
		return err
	}

	return sshCfg.WaitServerReady(timeout)
}
