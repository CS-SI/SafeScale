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

	"github.com/asaskevich/govalidator"
	"github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	convert "github.com/CS-SI/SafeScale/lib/server/utils"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
)

// safescale nas|share create share1 host1 --path="/shared/data"
// safescale nas|share delete share1
// safescale nas|share mount share1 host2 --path="/data"
// safescale nas|share umount share1 host2
// safescale nas|share list
// safescale nas|share inspect share1

// ShareListener Share service server grpc
type ShareListener struct{}

// Create calls share service creation
func (s *ShareListener) Create(ctx context.Context, in *pb.ShareDefinition) (_ *pb.ShareDefinition, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot create share").ToGRPCStatus()
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

	shareName := in.GetName()
	hostRef := srvutils.GetReference(in.GetHost())
	sharePath := in.GetPath()
	shareType := in.GetType()

	job, err := PrepareJob(ctx, "", "share create")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.Task(), fmt.Sprintf("('%s', '%s', '%s', %s)", shareName, hostRef, sharePath, shareType), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := ShareHandler(job)
	share, err := handler.Create(
		shareName,
		hostRef, sharePath,
		in.GetSecurityModes(),
		in.GetOptions().GetReadOnly(),
		in.GetOptions().GetRootSquash(),
		in.GetOptions().GetSecure(),
		in.GetOptions().GetAsync(),
		in.GetOptions().GetNoHide(),
		in.GetOptions().GetCrossMount(),
		in.GetOptions().GetSubtreeCheck(),
	)
	if err != nil {
		return nil, err
	}
	return convert.ToPBShare(in.GetName(), share), err
}

// Delete call share service deletion
func (s *ShareListener) Delete(ctx context.Context, in *pb.Reference) (empty *google_protobuf.Empty, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot delete share").ToGRPCStatus()
		}
	}()

	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, scerr.InvalidParameterError("ctx", "cannot be nil")
	}
	if in == nil {
		return empty, scerr.InvalidParameterError("in", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	shareName := in.GetName()

	job, err := PrepareJob(ctx, "", "share delete")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.Task(), fmt.Sprintf("('%s')", shareName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := ShareHandler(job)
	_, _, _, err = handler.Inspect(shareName)
	if err != nil {
		return empty, err
	}

	err = handler.Delete(shareName)
	if err != nil {
		return empty, err
	}
	return empty, nil
}

// List return the list of all available shares
func (s *ShareListener) List(ctx context.Context, in *google_protobuf.Empty) (_ *pb.ShareList, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot list shares").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, scerr.InvalidInstanceError()
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

	job, err := PrepareJob(ctx, "", "share list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.Task(), "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := ShareHandler(job)
	shares, err := handler.List()
	if err != nil {
		return nil, err
	}

	var pbshares []*pb.ShareDefinition
	for k, item := range shares {
		for _, share := range item {
			pbshares = append(pbshares, convert.ToPBShare(k, share))
		}
	}
	list := &pb.ShareList{ShareList: pbshares}
	return list, nil
}

// Mount mounts share on a local directory of the given host
func (s *ShareListener) Mount(ctx context.Context, in *pb.ShareMountDefinition) (smd *pb.ShareMountDefinition, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot mount share").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, "", "share mount")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	hostRef := srvutils.GetReference(in.GetHost())
	shareRef := srvutils.GetReference(in.GetShare())
	hostPath := in.GetPath()
	shareType := in.GetType()
	tracer := concurrency.NewTracer(job.Task(), fmt.Sprintf("('%s', '%s', '%s', %s)", hostRef, shareRef, hostPath, shareType), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := ShareHandler(job)
	mount, err := handler.Mount(shareRef, hostRef, hostPath, in.GetWithCache())
	if err != nil {
		return nil, err
	}
	return convert.ToPBShareMount(in.GetShare().GetName(), in.GetHost().GetName(), mount), nil
}

// Unmount unmounts share from the given host
func (s *ShareListener) Unmount(ctx context.Context, in *pb.ShareMountDefinition) (empty *google_protobuf.Empty, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot unmount share").ToGRPCStatus()
		}
	}()

	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, scerr.InvalidParameterError("ctx", "cannot be nil")
	}
	if in == nil {
		return empty, scerr.InvalidParameterError("in", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, "", "share unmount")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	hostRef := srvutils.GetReference(in.GetHost())
	shareRef := srvutils.GetReference(in.GetShare())
	hostPath := in.GetPath()
	shareType := in.GetType()
	tracer := concurrency.NewTracer(job.Task(), fmt.Sprintf("('%s', '%s', '%s', %s)", hostRef, shareRef, hostPath, shareType), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := ShareHandler(job)
	err = handler.Unmount(shareRef, hostRef)
	if err != nil {
		return empty, err
	}
	return empty, nil
}

// Inspect shows the detail of a share and all connected clients
func (s *ShareListener) Inspect(ctx context.Context, in *pb.Reference) (sml *pb.ShareMountList, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot inspect share").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	// ctx, cancelFunc := context.WithCancel(ctx)
	task, err := concurrency.NewTaskWithContext(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer task.Close()

	shareRef := srvutils.GetReference(in)
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", shareRef), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	job, err := PrepareJob(ctx, "", "share inspect")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	handler := ShareHandler(job)
	host, share, mounts, err := handler.Inspect(shareRef)
	if err != nil {
		return nil, err
	}
	// this _must not_ happen, but InspectHost has different implementations for each stack, and sometimes mistakes happens, so the test is necessary
	if host == nil {
		return nil, resources.ResourceNotFoundError("share", shareRef)
	}

	return convert.ToPBShareMountList(host.Name, share, mounts), nil
}
