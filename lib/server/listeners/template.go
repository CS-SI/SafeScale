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

	srvutils "github.com/CS-SI/SafeScale/v21/lib/server/utils"
	"github.com/oscarpicas/scribble"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v21/lib/protocol"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v21/lib/utils"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

// safescale template list --all=false

// TemplateListener host service server grpc
type TemplateListener struct {
	protocol.UnimplementedTemplateServiceServer
}

// List available templates
func (s *TemplateListener) List(ctx context.Context, in *protocol.TemplateListRequest) (_ *protocol.TemplateList, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list templates")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "/templates/list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	scannedOnly := in.GetScannedOnly()
	all := in.GetAll()
	tracer := debug.NewTracer(job.Task(), true, "(scannedOnly=%v, all=%v)", scannedOnly, all).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	svc := job.Service()
	originalList, xerr := svc.ListTemplates(all)
	if xerr != nil {
		return nil, xerr
	}

	authOpts, xerr := svc.GetAuthenticationOptions()
	if xerr != nil {
		return nil, xerr
	}

	region, ok := authOpts.Get("Region")
	if !ok {
		return nil, fail.InvalidRequestError("'Region' not set in tenant 'compute' section")
	}

	svcName, xerr := svc.GetName()
	if xerr != nil {
		return nil, xerr
	}

	folder := fmt.Sprintf("images/%s/%s", svcName, region)

	db, err := scribble.New(utils.AbsPathify("$HOME/.safescale/scanner/db"), nil)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	var finalList []*protocol.HostTemplate
	for _, item := range originalList {
		entry := converters.HostTemplateFromAbstractToProtocol(item)
		acpu := StoredCPUInfo{}
		if err := db.Read(folder, item.Name, &acpu); err != nil {
			if scannedOnly {
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

	return &protocol.TemplateList{Templates: finalList}, nil
}

// Match lists templates that match the sizing
func (s *TemplateListener) Match(ctx context.Context, in *protocol.TemplateMatchRequest) (tl *protocol.TemplateList, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list templates")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "/template/match")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	sizing := in.GetSizing()
	tracer := debug.NewTracer(job.Task(), true, "%s", sizing).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	ahsr, _, xerr := converters.HostSizingRequirementsFromStringToAbstract(sizing)
	if xerr != nil {
		return nil, xerr
	}

	templates, xerr := job.Service().ListTemplatesBySizing(*ahsr, false)
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
func (s *TemplateListener) Inspect(ctx context.Context, in *protocol.TemplateInspectRequest) (_ *protocol.HostTemplate, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(&ferr)
	defer fail.OnExitWrapError(&ferr, "cannot inspect tenant")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}

	ref, _ := srvutils.GetReference(in.GetTemplate())
	job, xerr := PrepareJob(ctx, in.GetTemplate().GetTenantId(), fmt.Sprintf("template/%s/inspect", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.template"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage())

	svc := job.Service()
	authOpts, xerr := svc.GetAuthenticationOptions()
	if xerr != nil {
		return nil, xerr
	}

	region, ok := authOpts.Get("Region")
	if !ok {
		return nil, fail.InvalidRequestError("'Region' not set in tenant 'compute' section")
	}

	svcName, xerr := svc.GetName()
	if xerr != nil {
		return nil, xerr
	}

	folder := fmt.Sprintf("images/%s/%s", svcName, region)

	db, err := scribble.New(utils.AbsPathify("$HOME/.safescale/scanner/db"), nil)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	at, xerr := svc.FindTemplateByName(ref)
	if xerr != nil {
		return nil, xerr
	}
	out := &protocol.HostTemplate{
		Id:       at.ID,
		Name:     at.Name,
		Cores:    int32(at.Cores),
		Ram:      int32(at.RAMSize),
		Disk:     int32(at.DiskSize),
		GpuCount: int32(at.GPUNumber),
		GpuType:  at.GPUType,
	}
	acpu := StoredCPUInfo{}
	if err = db.Read(folder, at.Name, &acpu); err != nil {
		logrus.Error(err.Error())
	} else {
		out.Scanned = &protocol.ScannedInfo{
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

	return out, nil
}
