/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/v22/lib/backend/handlers"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// safescale ssh connect host2
// safescale ssh run host2 -c "uname -a"
// safescale ssh copy /file/test.txt host1://tmp
// safescale ssh copy host1:/file/test.txt /tmp

// SSHListener SSH service server grpc
type SSHListener struct {
	protocol.UnimplementedSshServiceServer
}

// Run executes an ssh command on a host
func (s *SSHListener) Run(inctx context.Context, in *protocol.SshCommand) (sr *protocol.SshResponse, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &ferr)
	defer fail.OnExitWrapError(inctx, &ferr, "cannot run by ssh")
	defer fail.OnPanic(&ferr)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	hostRef := in.GetHost().GetName()
	if hostRef == "" {
		hostRef = in.GetHost().GetId()
		if hostRef == "" {
			return nil, fail.InvalidParameterError("in.Host", "host reference is missing")
		}
	}

	command := in.GetCommand()

	job, xerr := PrepareJob(inctx, in.GetHost().GetTenantId(), fmt.Sprintf("/ssh/run/host/%s", hostRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	handler := handlers.NewSSHHandler(job)
	retcode, stdout, stderr, xerr := handler.Run(hostRef, command)
	if xerr != nil {
		return nil, xerr
	}

	out := &protocol.SshResponse{
		Status:    int32(retcode),
		OutputStd: stdout,
		OutputErr: stderr,
	}
	return out, nil
}

// Copy copies file from/to a host
func (s *SSHListener) Copy(inctx context.Context, in *protocol.SshCopyCommand) (sr *protocol.SshResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot copy by ssh")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	var hostRef string

	job, xerr := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/ssh/%s", hostRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	handler := handlers.NewSSHHandler(job)
	retcode, stdout, stderr, xerr := handler.Copy(in.GetSource(), in.GetDestination())
	if xerr != nil {
		return nil, xerr
	}
	if retcode != 0 {
		return nil, fail.NewError("copy failed: retcode=%d: %s", retcode, stderr)
	}

	out := &protocol.SshResponse{
		Status:    int32(retcode),
		OutputStd: stdout,
		OutputErr: stderr,
	}
	return out, nil
}
