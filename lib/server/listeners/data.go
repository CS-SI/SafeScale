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
	"github.com/asaskevich/govalidator"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	conv "github.com/CS-SI/SafeScale/lib/server/utils"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// DataHandler ...
var DataHandler = handlers.NewDataHandler

// DataListener is the data service grpc server
type DataListener struct{}

// List will returns all the files from one or several ObjectStorages
func (s *DataListener) List(ctx context.Context, in *google_protobuf.Empty) (_ *pb.FileList, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			log.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	tracer := concurrency.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "Data List"); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenants := GetCurrentStorageTenants()
	if tenants == nil {
		log.Info("Can't list buckets: no storage tenants set")
		return nil, status.Errorf(codes.FailedPrecondition, "cannot list buckets: no storage tenants set")
	}

	handler := DataHandler(tenants.StorageServices)
	fileNames, uploadDates, fileSizes, fileBuckets, err := handler.List(ctx)
	if err != nil {
		return nil, scerr.Wrap(err, "cannot list buckets").ToGRPCStatus()
	}

	return conv.ToPBFileList(fileNames, uploadDates, fileSizes, fileBuckets), nil
}

// Push upload a file to one or several ObjectStorages
func (s *DataListener) Push(ctx context.Context, in *pb.File) (empty *google_protobuf.Empty, err error) {
	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return empty, scerr.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}
	if ctx == nil {
		return empty, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			log.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	objectName := in.GetName()
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", objectName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "Data Push"); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenants := GetCurrentStorageTenants()
	if tenants == nil {
		// log.Info("Can't list buckets: no storage tenants set")
		return empty, status.Errorf(codes.FailedPrecondition, "cannot list buckets: no storage tenants set")
	}

	handler := DataHandler(tenants.StorageServices)
	err = handler.Push(ctx, in.GetLocalPath(), objectName)
	if err != nil {
		return empty, scerr.Wrap(err, "cannot push data").ToGRPCStatus()
	}

	return empty, nil
}

// Pull fetches a file from one or several ObjectStorages
func (s *DataListener) Pull(ctx context.Context, in *pb.File) (empty *google_protobuf.Empty, err error) {
	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return empty, scerr.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}
	if ctx == nil {
		return empty, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			log.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	objectName := in.GetName()
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", objectName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "Data Pull"); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenants := GetCurrentStorageTenants()
	if tenants == nil {
		// log.Info("Can't list buckets: no storage tenants set")
		return empty, status.Errorf(codes.FailedPrecondition, "cannot pull data: no storage tenants set")
	}

	handler := DataHandler(tenants.StorageServices)
	err = handler.Get(ctx, in.GetLocalPath(), objectName)
	if err != nil {
		return empty, scerr.Wrap(err, "cannot pull data").ToGRPCStatus()
	}

	return empty, nil
}

// Delete remove a file from one or several Object Storages
func (s *DataListener) Delete(ctx context.Context, in *pb.File) (empty *google_protobuf.Empty, err error) {
	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return empty, scerr.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}
	if ctx == nil {
		return empty, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			log.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	objectName := in.GetName()
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", objectName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "Data Delete"); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenants := GetCurrentStorageTenants()
	if tenants == nil {
		return empty, status.Errorf(codes.FailedPrecondition, "cannot list buckets: no storage tenants set")
	}

	handler := DataHandler(tenants.StorageServices)
	err = handler.Delete(ctx, objectName)
	if err != nil {
		return empty, scerr.Wrap(err, "cannot delete data").ToGRPCStatus()
	}

	return empty, nil
}
