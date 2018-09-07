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
	"strings"
	"time"

	pb "github.com/CS-SI/SafeScale/broker"
	conv "github.com/CS-SI/SafeScale/broker/utils"
	utils "github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/utils/retry"
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
func (s *ssh) Run(hostName, command string, timeout time.Duration) (int, string, string, error) {
	if timeout < utils.TimeoutCtxHost {
		timeout = utils.TimeoutCtxHost
	}

	host := &host{session: s.session}
	cfg, err := host.SSHConfig(hostName)
	if err != nil {
		return 0, "", "", err
	}
	ssh := conv.ToAPISshConfig(cfg)

	var stdOut, stdErr string
	var retCode int

	err = retry.WhileUnsuccessfulDelay1SecondWithNotify(
		func() error {
			// Create the command
			sshCmd, err := ssh.Command(command)
			if err != nil {
				return err
			}
			retCode, stdOut, stdErr, err = sshCmd.Run()
			return err
		},
		2*time.Minute,
		retry.NotifyByLog)

	return retCode, stdOut, stdErr, err
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
func (s *ssh) Copy(from, to string, timeout time.Duration) error {
	host := &host{session: s.session}

	hostName := ""
	var upload bool
	var localPath, remotePath string
	// Try extract host
	hostFrom, err := extracthostName(from)
	if err != nil {
		return err
	}
	hostTo, err := extracthostName(to)
	if err != nil {
		return err
	}

	// Host checks
	if hostFrom != "" && hostTo != "" {
		return fmt.Errorf("copy between 2 hosts is not supported yet")
	}
	if hostFrom == "" && hostTo == "" {
		return fmt.Errorf("no host name specified neither in from nor to")
	}

	fromPath, err := extractPath(from)
	if err != nil {
		return err
	}
	toPath, err := extractPath(to)
	if err != nil {
		return err
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

	cfg, err := host.SSHConfig(hostName)
	if err != nil {
		return err
	}
	ssh := conv.ToAPISshConfig(cfg)

	if err != nil {
		return err
	}
	_, _, _, err = ssh.Copy(remotePath, localPath, upload)
	return err
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
	sshCfg := conv.ToAPISshConfig(sshConfig)

	return retry.WhileUnsuccessful255Delay5SecondsWithNotify(
		func() error {
			//cmd := exec.Command("/tmp/exit255.sh")
			//return cmd.Run()
			return sshCfg.Enter()
		},
		2*time.Minute,
		retry.NotifyByLog)
}
