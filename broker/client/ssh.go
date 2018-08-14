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
)

// ssh is the part of the broker client that handles SSH stuff
type ssh struct{}

// Run ...
func (s *ssh) Run(command pb.SshCommand, timeout time.Duration) (*pb.SshResponse, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout <= 0 {
		timeout = utils.TimeoutCtxHost
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewSshServiceClient(conn)
	return service.Run(ctx, &command)
}

// Copy ...
func (s *ssh) Copy(command pb.SshCopyCommand, timeout time.Duration) error {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout <= 0 {
		timeout = utils.TimeoutCtxHost
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewSshServiceClient(conn)
	_, err := service.Copy(ctx, &command)
	return err
}

// Connect ...
func (s *ssh) Connect(name string, timeout time.Duration) error {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout <= 0 {
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
	return sshCfg.Enter()
}
