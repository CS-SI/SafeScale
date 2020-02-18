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

package listeners

import (
	"context"
	"fmt"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// safescale ssh connect host2
// safescale ssh run host2 -c "uname -a"
// safescale ssh copy /file/test.txt host1://tmp
// safescale ssh copy host1:/file/test.txt /tmp

// SSHListener SSH service server grpc
type SSHListener struct{}

// Run executes an ssh command an an host
func (s *SSHListener) Run(ctx context.Context, in *protocol.SshCommand) (sr *protocol.SshResponse, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot run by ssh").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	hostRef := in.GetHost().Name()
	if hostRef == "" {
		hostRef = in.GetHost().ID()
	}
	if hostRef == "" {
		return nil, scerr.InvalidParameterError("in.Host", "host reference is missing")
	}

	command := in.GetCommand()

	job, err := PrepareJob(ctx, "", "ssh run")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.Task(), fmt.Sprintf("('%s', <command>)", hostRef), true).WithStopwatch().GoingIn()
	tracer.Trace(fmt.Sprintf("<command>=[%s]", command))
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	host, err := hostfactory.Load(job.Task(), job.Service(), hostRef)
	if err != nil {
		return nil, err
	}

	retcode, stdout, stderr, err := host.Run(job.Task(), command)
	if err != nil {
		return nil, err
	}

	return &protocol.SshResponse{
		Status:    int32(retcode),
		OutputStd: stdout,
		OutputErr: stderr,
	}, nil
}

// Copy copy file from/to an host
func (s *SSHListener) Copy(ctx context.Context, in *protocol.SshCopyCommand) (sr *protocol.SshResponse, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot copy by ssh").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, "", "ssh copy")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	source := in.Source
	dest := in.Destination
	tracer := concurrency.NewTracer(job.Task(), fmt.Sprintf("('%s', '%s')", source, dest), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	var (
		pull                bool
		hostRef             string
		hostPath, localPath string
		retcode             int
		stdout, stderr      string
	)

	// If source contains remote host, we pull
	parts := strings.Split(source, ":")
	if len(parts) > 1 {
		pull = true
		hostRef = parts[0]
		hostPath = strings.Join(parts[1:], ":")
	} else {
		localPath = source
	}

	// if destination contains remote host, we push (= !pull)
	parts = strings.Split(dest, ":")
	if len(parts) > 1 {
		if pull {
			return nil, scerr.InvalidRequestError("file copy from one remote host to another one is not supported")
		}
		hostRef = parts[0]
		hostPath = strings.Join(parts[1:], ":")
	} else {
		if !pull {
			return nil, scerr.InvalidRequestError("failed to find a remote host in the request")
		}
		localPath = destination
	}

	host, err := hostfactory.Load(job.Task(), job.Service(), hostRef)
	if err != nil {
		return nil, err
	}
	if pull {
		retcode, stdout, stderr, err = host.Pull(hostPath, localPath)
	} else {
		retcode, stdout, stderr, err = host.Push(localPath, hostPath, in.Owner, in.Mode)
	}
	if err != nil {
		return nil, err
	}
	if retcode != 0 {
		return nil, scerr.NewError(fmt.Sprintf("copy failed: retcode=%d (=%s): %s", retcode, system.SCPErrorString(retcode), stderr), nil, nil)
	}

	return &protocol.SshResponse{
		Status:    int32(retcode),
		OutputStd: stdout,
		OutputErr: stderr,
	}, nil
}
