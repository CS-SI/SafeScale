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

	"github.com/CS-SI/SafeScale/lib/server/resources/operations"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/asaskevich/govalidator"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
)

// PrepareJob creates a new job
func PrepareJob(ctx context.Context, tenantID string, jobDescription string) (_ server.Job, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	var tenant *operations.Tenant
	if tenantID != "" {
		service, xerr := iaas.UseService(tenantID, "")
		if xerr != nil {
			return nil, xerr
		}

		tenant = &operations.Tenant{Name: tenantID, Service: service}
	} else {
		tenant = operations.CurrentTenant()
		if tenant == nil {
			return nil, fail.NotFoundError("no tenant set")
		}
	}
	newctx, cancel := context.WithCancel(ctx)
	job, xerr := server.NewJob(newctx, cancel, tenant.Service, jobDescription)
	if xerr != nil {
		return nil, xerr
	}

	return job, nil
}

// PrepareJobWithoutService creates a new job without service instanciation (for example to be used with metadata upgrade)
func PrepareJobWithoutService(ctx context.Context, jobDescription string) (_ server.Job, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	newctx, cancel := context.WithCancel(ctx)

	job, xerr := server.NewJob(newctx, cancel, nil, jobDescription)
	if xerr != nil {
		return nil, xerr
	}

	return job, nil
}

// JobManagerListener service server gRPC
type JobManagerListener struct{}

// Stop specified process
func (s *JobManagerListener) Stop(ctx context.Context, in *protocol.JobDefinition) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot stop job")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	uuid := in.Uuid
	if in.Uuid == "" {
		return empty, fail.InvalidRequestError("cannot stop job: job id not set")
	}

	// ctx, cancelFunc := context.WithCancel(ctx)
	task, xerr := concurrency.NewTaskWithContext(ctx)
	if xerr != nil {
		return nil, xerr
	}

	tracer := debug.NewTracer(task, true, "('%s')", uuid).Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	tracer.Trace("Receiving stop order for job identified by '%s'...", uuid)

	return empty, server.AbortJobByID(uuid)
}

// List running process
func (s *JobManagerListener) List(ctx context.Context, in *googleprotobuf.Empty) (jl *protocol.JobList, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list jobs")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	task, xerr := concurrency.NewTaskWithContext(ctx)
	if xerr != nil {
		return nil, xerr
	}

	tracer := debug.NewTracer(task, true, "").Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	// handler := JobManagerHandler(tenant.GetService)
	jobMap := server.ListJobs()
	var pbProcessList []*protocol.JobDefinition
	for uuid, info := range jobMap {
		status, _ := task.Status()
		if status == concurrency.ABORTED {
			return nil, fail.AbortedError(nil)
		}
		pbProcessList = append(pbProcessList, &protocol.JobDefinition{Uuid: uuid, Info: info})
	}
	return &protocol.JobList{List: pbProcessList}, nil
}
