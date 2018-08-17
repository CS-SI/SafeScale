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

// Run ...
func (s *ssh) Run(hostName, command string, timeout time.Duration) (int, string, string, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxHost {
		timeout = utils.TimeoutCtxHost
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewSshServiceClient(conn)
	resp, err := service.Run(ctx, &pb.SshCommand{
		Host:    &pb.Reference{Name: hostName},
		Command: command,
	})
	if err != nil {
		return -1, "", "", err
	}
	return int(resp.GetStatus()), resp.GetOutputStd(), resp.GetOutputErr(), nil
}

// Copy ...
func (s *ssh) Copy(from, to string, timeout time.Duration) error {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxHost {
		timeout = utils.TimeoutCtxHost
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewSshServiceClient(conn)
	command := pb.SshCopyCommand{
		Source:      from,
		Destination: to,
	}
	_, err := service.Copy(ctx, &command)
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

	return retry.WhileUnsuccessfulDelay5SecondsWithNotify(
		func() error {
			return sshCfg.Enter()
		},
		2*time.Minute,
		retry.NotifyByLog)
}
