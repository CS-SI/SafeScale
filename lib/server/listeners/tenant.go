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
	"fmt"

	"github.com/CS-SI/SafeScale/lib/server/resources/operations/metadataupgrade"
	"github.com/asaskevich/govalidator"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	// "github.com/CS-SI/SafeScale/lib/server/resources/operations/metadataupgrade"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// TenantListener server is used to implement SafeScale.safescale.
type TenantListener struct{}

// List lists registered tenants
func (s *TenantListener) List(ctx context.Context, in *googleprotobuf.Empty) (_ *protocol.TenantList, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list tenants")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	defer fail.OnExitLogError(&err)

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
func (s *TenantListener) Get(ctx context.Context, in *googleprotobuf.Empty) (_ *protocol.TenantName, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil && !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	defer fail.OnExitLogError(&err)

	currentTenant := operations.CurrentTenant()
	if currentTenant == nil {
		return nil, fail.NotFoundError("no tenant set")
	}
	return &protocol.TenantName{Name: currentTenant.Name}, nil
}

// Set the the tenant to use for each command
func (s *TenantListener) Set(ctx context.Context, in *protocol.TenantName) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot set tenant")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	defer fail.OnExitLogError(&err)

	xerr := operations.SetCurrentTenant(in.GetName())
	if xerr != nil {
		return empty, xerr
	}

	return empty, nil
}

// Cleanup removes everything corresponding to SafeScale from tenant (metadata in particular)
func (s *TenantListener) Cleanup(ctx context.Context, in *protocol.TenantCleanupRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot cleanup tenant")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
		}
	}

	name := in.GetName()
	job, xerr := PrepareJob(ctx, "", fmt.Sprintf("tenant/%s/metadata/delete", name))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.tenant"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	currentTenant := operations.CurrentTenant()
	if currentTenant != nil && currentTenant.Name == in.GetName() {
		return empty, nil
	}

	// no need to set metadataVersion in UseService, we will remove content...
	service, xerr := iaas.UseService(in.GetName(), "")
	if xerr != nil {
		return empty, xerr
	}

	xerr = service.TenantCleanup(in.Force)
	return empty, xerr
}

// Scan proceeds a scan of host corresponding to each template to gather real data(metadata in particular)
func (s *TenantListener) Scan(ctx context.Context, in *protocol.TenantScanRequest) (_ *protocol.ScanResultList, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot scan tenant")

	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}

	name := in.GetName()
	job, xerr := PrepareJob(ctx, "", fmt.Sprintf("/tenant/%s/scan", name))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.tenant"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewTenantHandler(job)
	var resultList *protocol.ScanResultList
	resultList, err = handler.Scan(name, in.GetDryRun(), in.GetTemplates())

	return resultList, err
}

// Inspect returns information about a tenant
func (s *TenantListener) Inspect(ctx context.Context, in *protocol.TenantName) (_ *protocol.TenantInspectResponse, xerr error) {
	defer fail.OnExitConvertToGRPCStatus(&xerr)
	defer fail.OnExitWrapError(&xerr, "cannot inspect tenant")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	name := in.GetName()
	job, xerr := PrepareJob(ctx, "", fmt.Sprintf("/tenant/%s/inspect", name))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.tenant"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return nil, fail.NotImplementedError("tenant inspect not yet implemented")
}

// Upgrade upgrades metadata of a tenant if needed
func (s *TenantListener) Upgrade(ctx context.Context, in *protocol.TenantUpgradeRequest) (_ *protocol.TenantUpgradeResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot upgrade tenant")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	name := in.GetName()
	job, xerr := PrepareJobWithoutService(ctx, fmt.Sprintf("/tenant/%s/metadata/upgrade", name))
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.tenant"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	// Not setting metadataVersion prevents to overwrite current version file if it exists...
	svc, xerr := iaas.UseService(name, "")
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	var currentVersion string
	if !in.Force {
		currentVersion, xerr = operations.CheckMetadataVersion(svc)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrForbidden, *fail.ErrNotFound:
				// continue
				debug.IgnoreError(xerr)
			default:
				return nil, xerr
			}
		}
	}

	xerr = metadataupgrade.Upgrade(svc, currentVersion, operations.MinimumMetadataVersion, false, false)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return &protocol.TenantUpgradeResponse{}, nil
}
