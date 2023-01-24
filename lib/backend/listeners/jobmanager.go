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
	"reflect"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/CS-SI/SafeScale/v22/lib/backend/common/job"
	"github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/common/scope"
	terraformerapi "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer/api"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type scopeFromProtocol interface {
	GetOrganization() string
	GetProject() string
	GetTenantId() string
}

// prepareJob creates a new job and associated service
// FIXME: include job and svc in context?
func prepareJob(ctx context.Context, in scopeFromProtocol, description string) (_ jobapi.Job, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	scopeHolder, xerr := scope.Load(in.GetOrganization(), in.GetProject(), in.GetTenantId())
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			scopeHolder, xerr = scope.New(in.GetOrganization(), in.GetProject(), in.GetTenantId(), description)
			if xerr != nil {
				return nil, xerr
			}
		default:
			return nil, xerr
		}
	}

	newctx, cancel := context.WithCancel(ctx)
	j, xerr := job.New(newctx, cancel, scopeHolder)
	if xerr != nil {
		return nil, xerr
	}

	if j.Service().Capabilities().UseTerraformer {
		castedScope, ok := scopeHolder.(terraformerapi.ScopeLimitedToTerraformerUse)
		if !ok {
			return nil, fail.InconsistentError("failed to cast: expecting 'terraformerapi.ScopeLimitedToTerraformerUse', received '%s'", reflect.TypeOf(scopeHolder).String())
		}

		if !castedScope.IsLoaded() {
			xerr = castedScope.LoadAbstracts(j.Context())
			if xerr != nil {
				return nil, xerr
			}
		}
	}
	return j, nil
}

// JobManagerListener service server gRPC
type JobManagerListener struct {
	protocol.UnimplementedJobServiceServer
}

// Stop specified process
func (s *JobManagerListener) Stop(ctx context.Context, in *protocol.JobDefinition) (empty *emptypb.Empty, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(ctx, &ferr)
	defer fail.OnExitWrapError(ctx, &ferr, "cannot stop job")
	defer fail.OnPanic(&ferr)

	empty = &emptypb.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}

	uuid := in.Uuid
	if in.Uuid == "" {
		return empty, fail.InvalidRequestError("cannot stop job: job id not set")
	}

	tracer := debug.NewTracer(ctx, true, "('%s')", uuid).Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage())

	tracer.Trace("Receiving stop order for job identified by '%s'...", uuid)

	xerr := job.AbortByID(uuid)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// If uuid is not found, it's done
			tracer.Trace("Job '%s' already terminated.", uuid)
		default:
			return empty, xerr
		}
	}
	return empty, nil
}

// List running process
func (s *JobManagerListener) List(inctx context.Context, _ *emptypb.Empty) (jl *protocol.JobList, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot list jobs")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	tracer := debug.NewTracer(inctx, true, "").Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(inctx, &err, tracer.TraceMessage())

	// handler := JobManagerHandler(tenant.Service)
	jobMap := job.List()
	var pbProcessList []*protocol.JobDefinition
	for uuid, info := range jobMap {
		// status, _ := task.Status()
		// if status == concurrency.ABORTED {
		// 	return nil, fail.AbortedError(nil)
		// }
		pbProcessList = append(pbProcessList, &protocol.JobDefinition{Uuid: uuid, Info: info})
	}
	return &protocol.JobList{List: pbProcessList}, nil
}
