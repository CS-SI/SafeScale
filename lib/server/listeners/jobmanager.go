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

    "github.com/asaskevich/govalidator"
    googleprotobuf "github.com/golang/protobuf/ptypes/empty"
    "github.com/sirupsen/logrus"

    "github.com/CS-SI/SafeScale/lib/protocol"
    "github.com/CS-SI/SafeScale/lib/server"
    "github.com/CS-SI/SafeScale/lib/server/iaas"
    "github.com/CS-SI/SafeScale/lib/utils/concurrency"
    "github.com/CS-SI/SafeScale/lib/utils/debug"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
)

// PrepareJob creates a new job
func PrepareJob(ctx context.Context, tenantID string, jobDescription string) (server.Job, fail.Error) {
    if ctx == nil {
        return nil, fail.InvalidParameterError("ctx", "cannot be nil")
    }

    var tenant *Tenant
    if tenantID != "" {
        service, xerr := iaas.UseService(tenantID)
        if xerr != nil {
            return nil, xerr
        }
        tenant = &Tenant{name: tenantID, Service: service}
    } else {
        tenant = GetCurrentTenant()
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

// JobManagerListener service server gRPC
type JobManagerListener struct{}

// Stop specified process
func (s *JobManagerListener) Stop(ctx context.Context, in *protocol.JobDefinition) (empty *googleprotobuf.Empty, err error) {
    defer fail.OnExitConvertToGRPCStatus(&err)
    defer fail.OnExitWrapError(&err, "cannot stop job")

    empty = &googleprotobuf.Empty{}
    if s == nil {
        return empty, fail.InvalidInstanceError()
    }
    if in == nil {
        return empty, fail.InvalidParameterError("in", "cannot be nil")
    }
    if ctx == nil {
        return empty, fail.InvalidParameterError("ctx", "cannot be nil")
    }

    if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
        logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
    }

    uuid := in.Uuid
    if in.Uuid == "" {
        return empty, fail.InvalidRequestError("cannot stop job: job id not set")
    }

    // ctx, cancelFunc := context.WithCancel(ctx)
    task, xerr := concurrency.NewTaskWithContext(ctx, nil)
    if xerr != nil {
        return nil, xerr
    }

    tracer := debug.NewTracer(task, true, "('%s')", uuid).Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

    tracer.Trace("Receiving stop order for job identified by '%s'...", uuid)

    // ctx, cancelFunc := context.WithCancel(ctx)
    // // LATER: handle jobregister error
    // if err := srvutils.JobRegister(ctx, cancelFunc, "Stop job "+uuid); err == nil {
    // 	defer srvutils.JobDeregister(ctx)
    // } /* else {
    // 	return empty, fail.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
    // }*/

    // tenant := GetCurrentTenant()
    // if tenant == nil {
    // 	msg := "cannot stop process: no tenant set"
    // 	tracer.Trace(strprocess.Capitalize(msg))
    // 	return empty, status.Errorf(codes.FailedPrecondition, msg)
    // }

    // handler := JobManagerHandler(tenant.GetService)
    // handler.Stop(ctx, in.Uuid)
    // srvutils.JobCancelUUID(uuid)

    return empty, server.AbortJobByID(uuid)
}

// List running process
func (s *JobManagerListener) List(ctx context.Context, in *googleprotobuf.Empty) (jl *protocol.JobList, err error) {
    defer fail.OnExitConvertToGRPCStatus(&err)
    defer fail.OnExitWrapError(&err, "cannot list jobs")

    if s == nil {
        return nil, fail.InvalidInstanceError()
    }
    if ctx == nil {
        return nil, fail.InvalidParameterError("ctx", "cannot be nil")
    }

    if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
        logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
    }

    task, xerr := concurrency.NewTaskWithContext(ctx, nil)
    if xerr != nil {
        return nil, xerr
    }

    tracer := debug.NewTracer(task, true, "").Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&err, tracer.TraceMessage())

    // ctx, cancelFunc := context.WithCancel(ctx)
    // // LATER: handle jobregister error
    // if err := srvutils.JobRegister(ctx, cancelFunc, "ErrorList Processes"); err == nil {
    // 	defer srvutils.JobDeregister(ctx)
    // } /* else {
    // 	return nil, fail.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
    // }*/

    // tenant := GetCurrentTenant()
    // if tenant == nil {
    // 	msg := "cannot list process: no tenant set"
    // 	tracer.Trace(strprocess.Capitalize(msg))
    // 	return nil, status.Errorf(codes.FailedPrecondition, msg)
    // }

    // handler := JobManagerHandler(tenant.GetService)
    jobMap := server.ListJobs()
    var pbProcessList []*protocol.JobDefinition
    for uuid, info := range jobMap {
        status, _ := task.GetStatus()
        if status == concurrency.ABORTED {
            return nil, fail.AbortedError(nil)
        }
        pbProcessList = append(pbProcessList, &protocol.JobDefinition{Uuid: uuid, Info: info})
    }
    return &protocol.JobList{List: pbProcessList}, nil
}
