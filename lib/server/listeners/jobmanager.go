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
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// PrepareJob creates a new job
func PrepareJob(ctx context.Context, tenantName string, jobDescription string) (server.Job, fail.Report) {
	if ctx == nil {
		return nil, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	var tenant *Tenant
	if tenantName != "" {
		service, err := iaas.UseService(tenantName)
		if err != nil {
			return nil, err
		}
		tenant = &Tenant{name: tenantName, Service: service}
	} else {
		tenant = GetCurrentTenant()
		if tenant == nil {
			return nil, fail.NotFoundReport("no tenant set")
		}
	}
	newctx, cancel := context.WithCancel(ctx)

	job, err := server.NewJob(newctx, cancel, tenant.Service, jobDescription)
	if err != nil {
		return nil, err
	}
	return job, nil
}

// JobManagerListener service server gRPC
type JobManagerListener struct{}

// Stop specified process
func (s *JobManagerListener) Stop(ctx context.Context, in *protocol.JobDefinition) (empty *googleprotobuf.Empty, err fail.Report) {
	defer func() {
		if err != nil {
			err = fail.Wrap(err, "cannot stop job").ToGRPCStatus()
		}
	}()

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceReport()
	}
	if in == nil {
		return empty, fail.InvalidParameterReport("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err == nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	uuid := in.Uuid
	if in.Uuid == "" {
		return empty, fail.InvalidRequestReport("cannot stop job: job id not set")
	}

	// ctx, cancelFunc := context.WithCancel(ctx)
	task, err := concurrency.NewTaskWithContext(ctx, nil)
	if err != nil {
		return nil, err
	}

	tracer := concurrency.NewTracer(task, true, "('%s')", uuid).Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	tracer.Trace("Receiving stop order for job identified by '%s'...", uuid)

	// ctx, cancelFunc := context.WithCancel(ctx)
	// // LATER: handle jobregister error
	// if err := srvutils.JobRegister(ctx, cancelFunc, "Stop job "+uuid); err == nil {
	// 	defer srvutils.JobDeregister(ctx)
	// } /* else {
	// 	return empty, fail.InvalidInstanceContentReport("ctx", "has no uuid").ToGRPCStatus()
	// }*/

	// tenant := GetCurrentTenant()
	// if tenant == nil {
	// 	msg := "cannot stop process: no tenant set"
	// 	tracer.Trace(strprocess.Capitalize(msg))
	// 	return empty, status.Errorf(codes.FailedPrecondition, msg)
	// }

	// handler := JobManagerHandler(tenant.Service)
	// handler.Stop(ctx, in.Uuid)
	// srvutils.JobCancelUUID(uuid)

	return empty, server.AbortJobByID(uuid)
}

// ErrorList running process
func (s *JobManagerListener) List(ctx context.Context, in *googleprotobuf.Empty) (jl *protocol.JobList, err error) {
	defer func() {
		if err != nil {
			err = fail.Wrap(err, "cannot list jobs").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	task, err := concurrency.NewTaskWithContext(ctx, nil)
	if err != nil {
		return nil, err
	}

	tracer := concurrency.NewTracer(task, true, "").Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	// ctx, cancelFunc := context.WithCancel(ctx)
	// // LATER: handle jobregister error
	// if err := srvutils.JobRegister(ctx, cancelFunc, "ErrorList Processes"); err == nil {
	// 	defer srvutils.JobDeregister(ctx)
	// } /* else {
	// 	return nil, fail.InvalidInstanceContentReport("ctx", "has no uuid").ToGRPCStatus()
	// }*/

	// tenant := GetCurrentTenant()
	// if tenant == nil {
	// 	msg := "cannot list process: no tenant set"
	// 	tracer.Trace(strprocess.Capitalize(msg))
	// 	return nil, status.Errorf(codes.FailedPrecondition, msg)
	// }

	// handler := JobManagerHandler(tenant.Service)
	jobMap := server.ListJobs()
	var pbProcessList []*protocol.JobDefinition
	for uuid, info := range jobMap {
		status, _ := task.GetStatus()
		if status == concurrency.ABORTED {
			return nil, fail.AbortedReport(nil)
		}
		pbProcessList = append(pbProcessList, &protocol.JobDefinition{Uuid: uuid, Info: info})
	}
	return &protocol.JobList{List: pbProcessList}, nil
}
