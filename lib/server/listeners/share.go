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
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"

	"github.com/asaskevich/govalidator"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	sharefactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/share"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
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
func (s *ShareListener) Create(ctx context.Context, in *protocol.ShareDefinition) (_ *protocol.ShareDefinition, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot create share")

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
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	shareName := in.GetName()
	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	sharePath := in.GetPath()
	shareType := in.GetType()

	job, xerr := PrepareJob(ctx, in.GetHost().GetTenantId(), "share create")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	task := job.GetTask()
	tracer := debug.NewTracer(task, true, "('%s', %s, '%s', %s)", shareName, hostRefLabel, sharePath, shareType).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	// LEGACY: NFSExportOptions of protocol has been deprecated and replaced by OptionsAsString
	if in.OptionsAsString == "" && in.Options != nil {
		in.OptionsAsString = converters.NFSExportOptionsFromProtocolToString(in.Options)
	}
	svc := job.GetService()
	rh, xerr := hostfactory.Load(task, svc, hostRef)
	if xerr != nil {
		return nil, xerr
	}
	rs, xerr := sharefactory.New(svc)
	if xerr != nil {
		return nil, xerr
	}
	if err != nil {
		return nil, err
	}
	xerr = rs.Create(
		task,
		shareName,
		rh, sharePath,
		in.OptionsAsString,
		// in.GetSecurityModes(),
		// in.GetOptions().GetReadOnly(),
		// in.GetOptions().GetRootSquash(),
		// in.GetOptions().GetSecure(),
		// in.GetOptions().GetAsync(),
		// in.GetOptions().GetNoHide(),
		// in.GetOptions().GetCrossMount(),
		// in.GetOptions().GetSubtreeCheck(),
	)
	if xerr != nil {
		return nil, xerr
	}
	psml, xerr := rs.ToProtocol(task)
	if xerr != nil {
		return nil, xerr
	}
	return psml.Share, nil
}

// Delete call share service deletion
func (s *ShareListener) Delete(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot delete share")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	shareName := in.GetName()

	job, err := PrepareJob(ctx, in.GetTenantId(), "share delete")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.share"), "('%s')", shareName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rs, xerr := sharefactory.Load(job.GetTask(), job.GetService(), shareName)
	if xerr != nil {
		return empty, xerr
	}
	if xerr = rs.Delete(job.GetTask()); xerr != nil {
		return empty, xerr
	}
	return empty, nil
}

// List return the list of all available shares
func (s *ShareListener) List(ctx context.Context, in *protocol.Reference) (_ *protocol.ShareList, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list shares")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "share list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.share")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewShareHandler(job)
	shares, xerr := handler.List()
	if xerr != nil {
		return nil, xerr
	}

	var pbshares []*protocol.ShareDefinition
	for k, item := range shares {
		for _, share := range item {
			pbshares = append(pbshares, converters.ShareFromPropertyToProtocol(k, share))
		}
	}
	list := &protocol.ShareList{ShareList: pbshares}
	return list, nil
}

// Mount mounts share on a local directory of the given host
func (s *ShareListener) Mount(ctx context.Context, in *protocol.ShareMountDefinition) (smd *protocol.ShareMountDefinition, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot mount share")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, xerr := PrepareJob(ctx, in.GetHost().GetTenantId(), "share mount")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	shareRef, _ := srvutils.GetReference(in.GetShare())
	hostPath := in.GetPath()
	shareType := in.GetType()
	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.share"), "(%s, '%s', '%s', %s)", hostRefLabel, shareRef, hostPath, shareType).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewShareHandler(job)
	mount, xerr := handler.Mount(shareRef, hostRef, hostPath, in.GetWithCache())
	if xerr != nil {
		return nil, xerr
	}
	return converters.ShareMountFromPropertyToProtocol(in.GetShare().GetName(), in.GetHost().GetName(), mount), nil
}

// Unmount unmounts share from the given host
func (s *ShareListener) Unmount(ctx context.Context, in *protocol.ShareMountDefinition) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot unmount share")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, xerr := PrepareJob(ctx, in.GetHost().GetTenantId(), "share unmount")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	shareRef, _ := srvutils.GetReference(in.GetShare())
	hostPath := in.GetPath()
	shareType := in.GetType()
	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.share"), "(%s, '%s', '%s', %s)", hostRefLabel, shareRef, hostPath, shareType).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewShareHandler(job)
	if xerr = handler.Unmount(shareRef, hostRef); xerr != nil {
		return empty, xerr
	}
	return empty, nil
}

// Inspect shows the detail of a share and all connected clients
func (s *ShareListener) Inspect(ctx context.Context, in *protocol.Reference) (sml *protocol.ShareMountList, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot inspect share")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
		}
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "share inspect")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	shareRef, _ := srvutils.GetReference(in)
	task := job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.share"), "('%s')", shareRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewShareHandler(job)
	rh, xerr := handler.Inspect(shareRef)
	if xerr != nil {
		return nil, xerr
	}
	// DEFENSIVE CODING: this _must not_ happen, but InspectHost has different implementations for each stack, and sometimes mistakes happens, so the test is necessary
	if rh == nil {
		return nil, abstract.ResourceNotFoundError("share", shareRef)
	}

	return rh.ToProtocol(task)
}
