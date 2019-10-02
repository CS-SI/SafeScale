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

package listeners

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// SSHHandler exists to ease integration tests
var SSHHandler = handlers.NewSSHHandler

// safescale ssh connect host2
// safescale ssh run host2 -c "uname -a"
// safescale ssh copy /file/test.txt host1://tmp
// safescale ssh copy host1:/file/test.txt /tmp

// SSHListener SSH service server grpc
type SSHListener struct{}

// Run executes an ssh command an an host
func (s *SSHListener) Run(ctx context.Context, in *pb.SshCommand) (sr *pb.SshResponse, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "can't be nil")
	}
	host := in.GetHost().GetName()
	command := in.GetCommand()

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s', <command>)", host), true).WithStopwatch().GoingIn()
	tracer.Trace(fmt.Sprintf("<command>=[%s]", command))
	defer tracer.OnExitTrace()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)

	log.Infof("Listeners: ssh run '%s' -c '%s'", in.Host, in.Command)

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "SSH Run "+in.GetCommand()+" on host "+in.GetHost().GetName()); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		// log.Info("Can't execute ssh command: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "can't execute ssh command: no tenant set")
	}

	handler := SSHHandler(tenant.Service)
	retcode, stdout, stderr, err := handler.Run(ctx, host, command)
	if err != nil {
		err = status.Errorf(codes.Internal, err.Error())
	}
	return &pb.SshResponse{
		Status:    int32(retcode),
		OutputStd: stdout,
		OutputErr: stderr,
	}, err
}

// Copy copy file from/to an host
func (s *SSHListener) Copy(ctx context.Context, in *pb.SshCopyCommand) (sr *pb.SshResponse, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "can't be nil")
	}
	source := in.Source
	dest := in.Destination

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s')", source, dest), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)

	log.Infof("Listeners: ssh copy %s %s", source, dest)

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "SSH Copy "+source+" to "+dest); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		// log.Info("Can't copy by ssh command: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "can't copy by ssh: no tenant set")
	}

	handler := SSHHandler(tenant.Service)
	retcode, stdout, stderr, err := handler.Copy(ctx, source, dest)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	if retcode != 0 {
		return nil, fmt.Errorf("can't copy by ssh: copy failed: retcode=%d (=%s): %s", retcode, system.SCPErrorString(retcode), stderr)
	}

	return &pb.SshResponse{
		Status:    int32(retcode),
		OutputStd: stdout,
		OutputErr: stderr,
	}, nil
}
