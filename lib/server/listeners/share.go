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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	convert "github.com/CS-SI/SafeScale/lib/server/utils"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

// ShareHandler ...
var ShareHandler = handlers.NewShareHandler

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
	if s == nil {
		return nil, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil").ToGRPCStatus()
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	shareName := in.GetName()
	hostRef := srvutils.GetReference(in.GetHost())
	sharePath := in.GetPath()
	shareType := in.GetType()
	// FIXME: validate parameters

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s', '%s', %s)", shareName, hostRef, sharePath, shareType), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Create share "+in.GetName()); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return nil, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	tenant := GetCurrentTenant()
	if tenant == nil {
		msg := "cannot create share: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return nil, status.Errorf(codes.FailedPrecondition, msg)
	}

	handler := ShareHandler(tenant.Service)
	share, err := handler.Create(ctx, shareName, hostRef, sharePath, in.GetSecurityModes(), in.GetOptions().GetReadOnly(), in.GetOptions().GetRootSquash(), in.GetOptions().GetSecure(), in.GetOptions().GetAsync(), in.GetOptions().GetNoHide(), in.GetOptions().GetCrossMount(), in.GetOptions().GetSubtreeCheck())
	if err != nil {
		return nil, scerr.Wrap(err, "cannot create share").ToGRPCStatus()
	}
	return convert.ToPBShare(in.GetName(), share), err
}

// Delete call share service deletion
func (s *ShareListener) Delete(ctx context.Context, in *pb.Reference) (empty *google_protobuf.Empty, err error) {
	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Error())
	}
	if in == nil {
		return empty, status.Errorf(codes.InvalidArgument, scerr.InvalidParameterError("in", "cannot be nil").Error())
	}
	if ctx == nil {
		return empty, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	shareName := in.GetName()
	// FIXME: validate parameters

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", shareName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Delete share "+in.GetName()); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return empty, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	tenant := GetCurrentTenant()
	if tenant == nil {
		msg := "cannot delete share: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return empty, status.Errorf(codes.FailedPrecondition, msg)
	}

	handler := ShareHandler(tenant.Service)
	_, _, _, err = handler.Inspect(ctx, shareName)
	if err != nil {
		return empty, scerr.Wrap(err, "cannot delete share").ToGRPCStatus()
	}

	err = handler.Delete(ctx, shareName)
	if err != nil {
		return empty, scerr.Wrap(err, "cannot delete share").ToGRPCStatus()
	}
	return empty, nil
}

// List return the list of all available shares
func (s *ShareListener) List(ctx context.Context, in *google_protobuf.Empty) (_ *pb.ShareList, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	tracer := concurrency.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "List shares "); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return nil, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	tenant := GetCurrentTenant()
	if tenant == nil {
		msg := "cannot list shares: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return nil, status.Errorf(codes.FailedPrecondition, msg)
	}

	handler := ShareHandler(tenant.Service)
	shares, err := handler.List(ctx)
	if err != nil {
		return nil, scerr.Wrap(err, "cannot list Shares").ToGRPCStatus()
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
	if s == nil {
		return nil, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil").ToGRPCStatus()
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	hostRef := srvutils.GetReference(in.GetHost())
	shareRef := srvutils.GetReference(in.GetShare())
	hostPath := in.GetPath()
	shareType := in.GetType()
	// FIXME: validate parameters

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s', '%s', %s)", hostRef, shareRef, hostPath, shareType), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Mount share "+in.GetShare().GetName()+" on host "+in.GetHost().GetName()); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return nil, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	tenant := GetCurrentTenant()
	if tenant == nil {
		msg := "cannot mount share: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return nil, status.Errorf(codes.FailedPrecondition, msg)
	}

	handler := ShareHandler(tenant.Service)
	mount, err := handler.Mount(ctx, shareRef, hostRef, hostPath, in.GetWithCache())
	if err != nil {
		return nil, scerr.Wrap(err, "cannot mount share").ToGRPCStatus()
	}
	return convert.ToPBShareMount(in.GetShare().GetName(), in.GetHost().GetName(), mount), nil
}

// Unmount unmounts share from the given host
func (s *ShareListener) Unmount(ctx context.Context, in *pb.ShareMountDefinition) (empty *google_protobuf.Empty, err error) {
	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Error())
	}
	if in == nil {
		return empty, status.Errorf(codes.InvalidArgument, scerr.InvalidParameterError("in", "cannot be nil").Error())
	}
	if ctx == nil {
		return empty, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	hostRef := srvutils.GetReference(in.GetHost())
	shareRef := srvutils.GetReference(in.GetShare())
	hostPath := in.GetPath()
	shareType := in.GetType()
	// FIXME: validate parameters

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s', '%s', %s)", hostRef, shareRef, hostPath, shareType), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Unmount share "+shareRef+" from host "+hostRef); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return empty, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	tenant := GetCurrentTenant()
	if tenant == nil {
		msg := "cannot unmount share: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return empty, status.Errorf(codes.FailedPrecondition, msg)
	}

	handler := ShareHandler(tenant.Service)
	err = handler.Unmount(ctx, shareRef, hostRef)
	if err != nil {
		return empty, scerr.Wrap(err, "cannot unmount share").ToGRPCStatus()
	}
	return empty, nil
}

// Inspect shows the detail of a share and all connected clients
func (s *ShareListener) Inspect(ctx context.Context, in *pb.Reference) (sml *pb.ShareMountList, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil").ToGRPCStatus()
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	shareRef := srvutils.GetReference(in)
	// FIXME: validate parameters

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", shareRef), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Inspect share "+shareRef); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return nil, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	tenant := GetCurrentTenant()
	if tenant == nil {
		msg := "cannot inspect share: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return nil, status.Errorf(codes.FailedPrecondition, msg)
	}

	handler := ShareHandler(tenant.Service)
	host, share, mounts, err := handler.Inspect(ctx, shareRef)
	if err != nil {
		return nil, scerr.Wrap(err, "cannot inspect share").ToGRPCStatus()
	}
	// this _must not_ happen, but InspectHost has different implementations for each stack, and sometimes mistakes happens, so the test is necessary
	if host == nil {
		return nil, scerr.Wrap(resources.ResourceNotFoundError("share", shareRef), "cannot inspect share").ToGRPCStatus()
	}

	return convert.ToPBShareMountList(host.Name, share, mounts), nil
}
