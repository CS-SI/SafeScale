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

	"github.com/CS-SI/SafeScale/v22/lib/backend/handlers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
)

// TenantListener server is used to implement SafeScale.safescale.
type TenantListener struct {
	protocol.UnimplementedTenantServiceServer
}

// List lists registered tenants
func (s *TenantListener) List(inctx context.Context, in *googleprotobuf.Empty) (_ *protocol.TenantList, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot list tenants")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	defer fail.OnExitLogError(inctx, &err)

	tenants, xerr := iaas.GetTenantNames()
	if xerr != nil {
		return nil, xerr
	}

	var list []*protocol.Tenant
	for tenantName, providerName := range tenants {
		list = append(list, &protocol.Tenant{
			Name:     tenantName,
			Provider: providerName,
		})
	}

	return &protocol.TenantList{Tenants: list}, nil
}

// Get returns the name of the current tenant used
func (s *TenantListener) Get(inctx context.Context, in *googleprotobuf.Empty) (_ *protocol.TenantName, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	defer fail.OnExitLogError(inctx, &err)

	currentTenant := operations.CurrentTenant(inctx)
	if currentTenant == nil {
		return nil, fail.NotFoundError("no tenant set")
	}

	prvName, xerr := currentTenant.Service.GetProviderName()
	if xerr != nil {
		return nil, xerr
	}

	return &protocol.TenantName{
		Name:       currentTenant.Name,
		BucketName: currentTenant.BucketName,
		Provider:   prvName,
	}, nil
}

// Set sets the tenant to use for each command
func (s *TenantListener) Set(inctx context.Context, in *protocol.TenantName) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot set tenant")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil")
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}

	defer fail.OnExitLogError(inctx, &err)

	xerr := operations.SetCurrentTenant(inctx, in.GetName())
	if xerr != nil {
		return empty, xerr
	}

	return empty, nil
}

// Cleanup removes everything corresponding to SafeScale from tenant (metadata in particular)
func (s *TenantListener) Cleanup(inctx context.Context, in *protocol.TenantCleanupRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot cleanup tenant")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil")
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}

	name := in.GetName()
	job, xerr := PrepareJob(inctx, "", fmt.Sprintf("tenant/%s/metadata/delete", name))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()

	currentTenant := operations.CurrentTenant(ctx)
	if currentTenant != nil && currentTenant.Name == in.GetName() {
		return empty, nil
	}

	// no need to set metadataVersion in UseService, we will remove content...
	service, xerr := iaas.UseService(ctx, in.GetName(), "")
	if xerr != nil {
		return empty, xerr
	}

	xerr = service.TenantCleanup(ctx, in.Force)
	return empty, xerr
}

// Scan proceeds a scan of host corresponding to each template to gather real data(metadata in particular)
func (s *TenantListener) Scan(inctx context.Context, in *protocol.TenantScanRequest) (_ *protocol.ScanResultList, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot scan tenant")

	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}

	name := in.GetName()
	job, xerr := PrepareJob(inctx, "", fmt.Sprintf("/tenant/%s/scan", name))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	handler := handlers.NewTenantHandler(job)
	var resultList *protocol.ScanResultList
	resultList, err = handler.Scan(name, in.GetDryRun(), in.GetTemplates())

	return resultList, err
}

// Inspect returns information about a tenant
func (s *TenantListener) Inspect(inctx context.Context, in *protocol.TenantName) (_ *protocol.TenantInspectResponse, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &ferr)
	defer fail.OnExitWrapError(inctx, &ferr, "cannot inspect tenant")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}

	name := in.GetName()
	job, xerr := PrepareJob(inctx, "", fmt.Sprintf("/tenant/%s/inspect", name))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	handler := handlers.NewTenantHandler(job)
	tenantInfo, err := handler.Inspect(name)
	if err != nil {
		return nil, err
	}

	return tenantInfo, nil
}
