/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// safescale ssh connect host2
// safescale ssh run host2 -c "uname -a"
// safescale ssh copy /file/test.txt host1://tmp
// safescale ssh copy host1:/file/test.txt /tmp

// SSHListener SSH service server grpc
type SSHListener struct{}

// Run executes an ssh command an an host
func (s *SSHListener) Run(ctx context.Context, in *protocol.SshCommand) (sr *protocol.SshResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot run by ssh")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	hostRef := in.GetHost().GetName()
	if hostRef == "" {
		hostRef = in.GetHost().GetId()
	}
	if hostRef == "" {
		return nil, fail.InvalidParameterError("in.Host", "host reference is missing")
	}

	command := in.GetCommand()

	job, xerr := PrepareJob(ctx, in.GetHost().GetTenantId(), fmt.Sprintf("/ssh/run/host/%s", hostRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	task := job.Task()
	tracer := debug.NewTracer(task, true, "('%s', <command>)", hostRef).WithStopwatch().Entering()
	tracer.Trace(fmt.Sprintf("<command>=[%s]", command))
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rh, xerr := hostfactory.Load(job.Service(), hostRef)
	if xerr != nil {
		return nil, xerr
	}

	retcode, stdout, stderr, xerr := rh.Run(task.Context(), command, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if xerr != nil {
		return nil, xerr
	}

	return &protocol.SshResponse{
		Status:    int32(retcode),
		OutputStd: stdout,
		OutputErr: stderr,
	}, nil
}

// Copy copy file from/to an host
func (s *SSHListener) Copy(ctx context.Context, in *protocol.SshCopyCommand) (sr *protocol.SshResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot copy by ssh")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	var (
		pull                bool
		hostRef             string
		hostPath, localPath string
		retcode             int
		stdout, stderr      string
	)

	source := in.Source
	dest := in.Destination

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
			return nil, fail.InvalidRequestError("file copy from one remote host to another one is not supported")
		}
		hostRef = parts[0]
		hostPath = strings.Join(parts[1:], ":")
	} else {
		if !pull {
			return nil, fail.InvalidRequestError("failed to find a remote host in the request")
		}
		localPath = dest
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/ssh/copy/host/%s", hostRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()
	task := job.Task()

	tracer := debug.NewTracer(task, true, "('%s', '%s')", source, dest).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rh, xerr := hostfactory.Load(job.Service(), hostRef)
	if xerr != nil {
		return nil, xerr
	}
	if pull {
		retcode, stdout, stderr, xerr = rh.Pull(task.Context(), hostPath, localPath, temporal.GetLongOperationTimeout())
	} else {
		retcode, stdout, stderr, xerr = rh.Push(task.Context(), localPath, hostPath, in.Owner, in.Mode, temporal.GetLongOperationTimeout())
	}
	if xerr != nil {
		return nil, xerr
	}
	if retcode != 0 {
		return nil, fail.NewError("copy failed: retcode=%d (=%s): %s", retcode, system.SCPErrorString(retcode), stderr)
	}

	return &protocol.SshResponse{
		Status:    int32(retcode),
		OutputStd: stdout,
		OutputErr: stderr,
	}, nil
}
