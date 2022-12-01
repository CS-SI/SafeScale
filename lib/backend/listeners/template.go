/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/oscarpicas/scribble"

	srvutils "github.com/CS-SI/SafeScale/v22/lib/backend/common"
	"github.com/CS-SI/SafeScale/v22/lib/backend/handlers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// safescale template list --all=false

// TemplateListener host service server grpc
type TemplateListener struct {
	protocol.UnimplementedTemplateServiceServer
}

// List available templates
func (s *TemplateListener) List(inctx context.Context, in *protocol.TemplateListRequest) (_ *protocol.TemplateList, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot list templates")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	job, xerr := prepareJob(inctx, in, "/templates/list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	scannedOnly := in.GetScannedOnly()
	all := in.GetAll()
	ctx := job.Context()

	tracer := debug.NewTracer(ctx, true, "(scannedOnly=%v, all=%v)", scannedOnly, all).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewTemplateHandler(job)
	originalList, xerr := handler.List(all)
	if xerr != nil {
		return nil, xerr
	}

	finalList, xerr := complementWithScan(ctx, job.Service(), scannedOnly, originalList...)
	if xerr != nil {
		return nil, xerr
	}

	return &protocol.TemplateList{Templates: finalList}, nil
}

// Match lists templates that match the sizing
func (s *TemplateListener) Match(inctx context.Context, in *protocol.TemplateMatchRequest) (tl *protocol.TemplateList, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot list templates")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	job, xerr := prepareJob(inctx, in, "/template/match")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	sizing := in.GetSizing()
	ctx := job.Context()
	tracer := debug.NewTracer(ctx, true, "%s", sizing).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	ahsr, _, xerr := converters.HostSizingRequirementsFromStringToAbstract(sizing)
	if xerr != nil {
		return nil, xerr
	}

	handler := handlers.NewTemplateHandler(job)
	templates, xerr := handler.Match(*ahsr)
	if xerr != nil {
		return nil, xerr
	}

	var pbTemplates []*protocol.HostTemplate
	for _, template := range templates {
		pbTemplates = append(pbTemplates, converters.HostTemplateFromAbstractToProtocol(*template))
	}
	rv := &protocol.TemplateList{Templates: pbTemplates}
	return rv, nil
}

// Inspect returns information about a tenant
func (s *TemplateListener) Inspect(inctx context.Context, in *protocol.TemplateInspectRequest) (_ *protocol.HostTemplate, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &ferr)
	defer fail.OnExitWrapError(inctx, &ferr, "cannot inspect tenant")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	ref, _ := srvutils.GetReference(in.GetTemplate())

	job, xerr := prepareJob(inctx, in.GetTemplate(), fmt.Sprintf("template/%s/inspect", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.template"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage())

	handler := handlers.NewTemplateHandler(job)
	at, xerr := handler.Inspect(ref)
	if xerr != nil {
		return nil, xerr
	}

	out, xerr := complementWithScan(ctx, job.Service(), false, at)
	if xerr != nil {
		return nil, xerr
	}

	return out[0], nil
}

func complementWithScan(ctx context.Context, svc iaasapi.Service, scanOnly bool, templates ...*abstract.HostTemplate) ([]*protocol.HostTemplate, fail.Error) {
	authOpts, xerr := svc.AuthenticationOptions()
	if xerr != nil {
		return nil, xerr
	}

	region := authOpts.Region
	svcName, xerr := svc.GetName()
	if xerr != nil {
		return nil, xerr
	}

	folder := fmt.Sprintf("images/%s/%s", svcName, region)
	db, err := scribble.New(utils.AbsPathify("$HOME/.safescale/scanner/db"), nil)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	var finalList []*protocol.HostTemplate
	for _, item := range templates {
		entry := converters.HostTemplateFromAbstractToProtocol(*item)
		acpu := StoredCPUInfo{}
		if err := db.Read(folder, item.Name, &acpu); err != nil {
			if scanOnly {
				continue
			}
		} else {
			entry.Scanned = &protocol.ScannedInfo{
				TenantName:      acpu.TenantName,
				TemplateId:      acpu.ID,
				TemplateName:    acpu.TemplateName,
				ImageId:         acpu.ImageID,
				ImageName:       acpu.ImageName,
				LastUpdated:     acpu.LastUpdated,
				NumberOfCpu:     int64(acpu.NumberOfCPU),
				NumberOfCore:    int64(acpu.NumberOfCore),
				NumberOfSocket:  int64(acpu.NumberOfSocket),
				CpuFrequencyGhz: acpu.CPUFrequency,
				CpuArch:         acpu.CPUArch,
				Hypervisor:      acpu.Hypervisor,
				CpuModel:        acpu.CPUModel,
				RamSizeGb:       acpu.RAMSize,
				RamFreq:         acpu.RAMFreq,
				Gpu:             int64(acpu.GPU),
				GpuModel:        acpu.GPUModel,
				// DiskSizeGb:           acpu.DiskSize,
				// MainDiskType:         acpu.MainDiskType,
				// MainDiskSpeedMbps:    acpu.MainDiskSpeed,
				// SampleNetSpeedKbps:   acpu.SampleNetSpeed,
				// EphDiskSize_Gb:       acpu.EphDiskSize,
				// PriceInDollarsSecond: acpu.PricePerSecond,
				// PriceInDollarsHour:   acpu.PricePerHour,
				// Not yet implemented, FIXME: Implement this
				// Prices: []*protocol.PriceInfo{{
				// 	Currency:      "euro-fake",
				// 	DurationLabel: "perMonth",
				// 	Duration:      1,
				// 	Price:         30,
				// }},
			}
		}
		finalList = append(finalList, entry)
	}

	return finalList, nil
}
