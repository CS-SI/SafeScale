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

package services

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/utils/retry/Verdict"

	"github.com/CS-SI/SafeScale/utils/retry"

	"github.com/CS-SI/SafeScale/system"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
)

const protocolSeparator = ":"

// SSHAPI defines ssh management API
type SSHAPI interface {
	Connect(name string) error
	Run(cmd string) (string, string, int, error)
	Copy(from string, to string)
}

// NewSSHService creates a SSH service
func NewSSHService(api api.ClientAPI) *SSHService {
	return &SSHService{
		provider:    providers.FromClient(api),
		hostService: NewHostService(api),
	}
}

// SSHService SSH service
type SSHService struct {
	provider    *providers.Service
	hostService HostAPI
}

// Run tries to execute command 'cmd' on the host
func (svc *SSHService) Run(hostName, cmd string) (int, string, string, error) {
	var stdOut, stdErr string
	var retCode int
	var err error

	host, err := svc.hostService.Get(hostName)
	if err != nil {
		return 0, "", "", fmt.Errorf("no host found with name or id '%s'", hostName)
	}

	// retrieve ssh config to perform some commands
	ssh, err := svc.provider.GetSSHConfig(host.ID)

	if err != nil {
		return 0, "", "", err
	}

	err = retry.WhileUnsuccessfulDelay1SecondWithNotify(
		func() error {
			retCode, stdOut, stdErr, err = svc.run(ssh, cmd)
			return err
		},
		2*time.Minute,
		func(t retry.Try, v Verdict.Enum) {
			if v == Verdict.Retry {
				log.Printf("Remote SSH service on host '%s' isn't readybroker ssh co, retrying...\n", hostName)
			}
		},
	)

	return retCode, stdOut, stdErr, err
}

// run executes command on the host
func (svc *SSHService) run(ssh *system.SSHConfig, cmd string) (int, string, string, error) {
	// Create the command
	sshCmd, err := ssh.Command(cmd)
	if err != nil {
		return 0, "", "", err
	}
	return sshCmd.Run()
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
func (svc *SSHService) Copy(from, to string) (int, string, string, error) {
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

	host, err := svc.hostService.Get(hostName)
	if err != nil {
		return 0, "", "", fmt.Errorf("no host found with name or id '%s'", hostName)
	}

	// retrieve ssh config to perform some commands
	ssh, err := svc.provider.GetSSHConfig(host.ID)
	if err != nil {
		return 0, "", "", err
	}

	return ssh.Copy(remotePath, localPath, upload)
}
