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
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
)

// PrepareJob creates a new job
func PrepareJob(ctx context.Context, tenantID string, jobDescription string) (_ backend.Job, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	var tenant *operations.Tenant
	if tenantID != "" {
		service, xerr := iaas.UseService(ctx, tenantID, "")
		if xerr != nil {
			return nil, xerr
		}

		bucket, ierr := service.GetMetadataBucket(ctx)
		if ierr != nil {
			return nil, ierr
		}

		tenant = &operations.Tenant{Name: tenantID, BucketName: bucket.GetName(), Service: service}
	} else {
		tenant = operations.CurrentTenant(ctx)
		if tenant == nil {
			return nil, fail.NotFoundError("no tenant set")
		}
	}

	newctx, cancel := context.WithCancel(ctx)
	job, xerr := backend.NewJob(newctx, cancel, tenant.Service, jobDescription)
	if xerr != nil {
		return nil, xerr
	}

	return job, nil
}

func PrepareInspectionJob(ctx context.Context, tenantID string, jobDescription string) (_ backend.Job, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	newctx, cancel := context.WithCancel(ctx)
	job, xerr := backend.NewJob(newctx, cancel, nil, jobDescription)
	if xerr != nil {
		return nil, xerr
	}

	return job, nil
}

// JobManagerListener service server gRPC
type JobManagerListener struct {
	protocol.UnimplementedJobServiceServer
}

// Stop specified process
func (s *JobManagerListener) Stop(ctx context.Context, in *protocol.JobDefinition) (empty *googleprotobuf.Empty, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(ctx, &ferr)
	defer fail.OnExitWrapError(ctx, &ferr, "cannot stop job")
	defer fail.OnPanic(&ferr)

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

	uuid := in.Uuid
	if in.Uuid == "" {
		return empty, fail.InvalidRequestError("cannot stop job: job id not set")
	}

	logrus.WithContext(ctx).Infof("Receiving stop order for job identified by '%s'...", uuid)

	xerr := backend.AbortJobByID(uuid)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// If uuid is not found, it's done
			logrus.WithContext(ctx).Infof("Job '%s' already terminated.", uuid)
		default:
			return empty, xerr
		}
	}
	return empty, nil
}

// List running process
func (s *JobManagerListener) List(inctx context.Context, _ *googleprotobuf.Empty) (jl *protocol.JobList, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot list jobs")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	jobMap := backend.ListJobs()
	var pbProcessList []*protocol.JobDefinition
	for uuid, info := range jobMap {
		select {
		case <-inctx.Done():
			return nil, fail.AbortedError(inctx.Err())
		default:
		}
		pbProcessList = append(pbProcessList, &protocol.JobDefinition{Uuid: uuid, Info: info})
	}
	return &protocol.JobList{List: pbProcessList}, nil
}
