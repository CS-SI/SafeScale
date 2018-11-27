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

package listeners

import (
	"context"
	"fmt"

	"github.com/CS-SI/SafeScale/system"
	log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/server/services"
)

// broker ssh connect host2
// broker ssh run host2 -c "uname -a"
// broker ssh copy /file/test.txt host1://tmp
// broker ssh copy host1:/file/test.txt /tmp

// SSHServiceListener SSH service server grpc
type SSHServiceListener struct{}

// Run executes an ssh command an an host
func (s *SSHServiceListener) Run(ctx context.Context, in *pb.SshCommand) (*pb.SshResponse, error) {
	log.Printf("Ssh run called '%s', '%s'", in.Host, in.Command)
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot execute ssh command : No tenant set")
	}

	service := services.NewSSHService(currentTenant.Service)
	retcode, stdout, stderr, err := service.Run(in.GetHost().GetName(), in.GetCommand())

	return &pb.SshResponse{
		Status:    int32(retcode),
		OutputStd: stdout,
		OutputErr: stderr,
	}, err
}

// Copy copy file from/to an host
func (s *SSHServiceListener) Copy(ctx context.Context, in *pb.SshCopyCommand) (*pb.SshResponse, error) {
	log.Printf("Ssh copy called '%s', '%s'", in.Source, in.Destination)
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot copy ssh : No tenant set")
	}

	service := services.NewSSHService(currentTenant.Service)
	retcode, stdout, stderr, err := service.Copy(in.GetSource(), in.GetDestination())
	if err != nil {
		return nil, err
	}
	if retcode != 0 {
		return nil, fmt.Errorf("Cannot copy ssh : copy failed: retcode=%d (=%s): %s", retcode, system.SCPErrorString(retcode), stderr)
	}
	if err != nil {
		return nil, err
	}

	return &pb.SshResponse{
		Status:    int32(retcode),
		OutputStd: stdout,
		OutputErr: stderr,
	}, err
}
