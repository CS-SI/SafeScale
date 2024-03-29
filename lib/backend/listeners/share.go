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
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"

	"github.com/CS-SI/SafeScale/v22/lib/backend/handlers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/v22/lib/backend/utils"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
)

// safescale share create --path="/shared/data" share1 host1
// safescale share delete share1
// safescale share mount --path="/data" share1 host2
// safescale share umount share1 host2
// safescale share list
// safescale share inspect share1

// ShareListener Share service server grpc
type ShareListener struct {
	protocol.UnimplementedShareServiceServer
}

// Create calls share service creation
func (s *ShareListener) Create(inctx context.Context, in *protocol.ShareDefinition) (_ *protocol.ShareDefinition, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot create share")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	shareName := in.GetName()
	job, xerr := PrepareJob(inctx, in.GetHost().GetTenantId(), fmt.Sprintf("/share/%s/create", shareName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	hostRef, _ := srvutils.GetReference(in.GetHost())
	sharePath := in.GetPath()

	// LEGACY: NFSExportOptions of protocol has been deprecated and replaced by OptionsAsString
	if in.OptionsAsString == "" && in.Options != nil {
		in.OptionsAsString = converters.NFSExportOptionsFromProtocolToString(in.Options)
	}

	handler := handlers.NewShareHandler(job)
	shareInstance, xerr := handler.Create(shareName, hostRef, sharePath, in.GetOptionsAsString())
	if xerr != nil {
		return nil, xerr
	}

	out, xerr := shareInstance.ToProtocol(ctx)
	if xerr != nil {
		return nil, xerr
	}

	return out.Share, nil
}

// Delete call share service deletion
func (s *ShareListener) Delete(inctx context.Context, in *protocol.ShareDeleteRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot delete share")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}

	shareName := in.GetName()
	job, xerr := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/share/%s/delete", shareName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	handler := handlers.NewShareHandler(job)
	return empty, handler.Delete(shareName)
}

// List return the list of all available shares
func (s *ShareListener) List(inctx context.Context, in *protocol.Reference) (_ *protocol.ShareList, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot list shares")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	job, xerr := PrepareJob(inctx, in.GetTenantId(), "/shares/list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

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
func (s *ShareListener) Mount(inctx context.Context, in *protocol.ShareMountDefinition) (smd *protocol.ShareMountDefinition, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot mount share")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	hostRef, _ := srvutils.GetReference(in.GetHost())
	shareRef, _ := srvutils.GetReference(in.GetShare())
	job, xerr := PrepareJob(inctx, in.GetHost().GetTenantId(), fmt.Sprintf("/share/%s/host/%s/mount", shareRef, hostRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	hostPath := in.GetPath()

	handler := handlers.NewShareHandler(job)
	mount, xerr := handler.Mount(shareRef, hostRef, hostPath, in.GetWithCache())
	if xerr != nil {
		return nil, xerr
	}

	return converters.ShareMountFromPropertyToProtocol(in.GetShare().GetName(), in.GetHost().GetName(), mount), nil
}

// Unmount unmounts share from the given host
func (s *ShareListener) Unmount(inctx context.Context, in *protocol.ShareMountDefinition) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot unmount share")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}

	hostRef, _ := srvutils.GetReference(in.GetHost())
	shareRef, _ := srvutils.GetReference(in.GetShare())
	job, xerr := PrepareJob(inctx, in.GetHost().GetTenantId(), fmt.Sprintf("/share/%s/host/%s/unmount", shareRef, hostRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	handler := handlers.NewShareHandler(job)
	if xerr = handler.Unmount(shareRef, hostRef); xerr != nil {
		return empty, xerr
	}
	return empty, nil
}

// Inspect shows the detail of a share and all connected clients
func (s *ShareListener) Inspect(inctx context.Context, in *protocol.Reference) (sml *protocol.ShareMountList, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot inspect share")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	shareRef, _ := srvutils.GetReference(in)
	job, xerr := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/share/%s/inspect", shareRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()

	handler := handlers.NewShareHandler(job)
	shareInstance, xerr := handler.Inspect(shareRef)
	if xerr != nil {
		return nil, xerr
	}

	if shareInstance == nil {
		return nil, abstract.ResourceNotFoundError("share", shareRef)
	}

	return shareInstance.ToProtocol(ctx)
}
