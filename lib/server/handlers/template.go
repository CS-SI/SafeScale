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

package handlers

import (
	"fmt"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	scribble "github.com/nanobox-io/golang-scribble"
)

//go:generate minimock -o ../mocks/mock_templateapi.go -i github.com/CS-SI/SafeScale/lib/server/handlers.TemplateHandler

// TODO: At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// TemplateHandler defines API to manipulate hosts
type TemplateHandler interface {
	List(all bool) ([]abstract.HostTemplate, fail.Error)
	Inspect(all bool, onlyScanned bool) (tlist *protocol.TemplateList, xerr fail.Error)
}

// templateHandler template service
type templateHandler struct {
	job server.Job
}

// NewTemplateHandler creates a template service
func NewTemplateHandler(job server.Job) TemplateHandler {
	return &templateHandler{job: job}
}

// List returns the template list
func (handler *templateHandler) List(all bool) (tlist []abstract.HostTemplate, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	tracer := debug.NewTracer(handler.job.GetTask(), tracing.ShouldTrace("handlers.template"), "(%v)", all).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	return handler.job.GetService().ListTemplates(all)
}

// Inspect returns the templates and the corresponding scanned metrics
func (handler *templateHandler) Inspect(all bool, onlyScanned bool) (templateList *protocol.TemplateList, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	tracer := debug.NewTracer(handler.job.GetTask(), tracing.ShouldTrace("handlers.template")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	svc := handler.job.GetService()

	authOpts, xerr := svc.GetAuthenticationOptions()
	if xerr != nil {
		return nil, xerr
	}

	region, ok := authOpts.Get("Region")
	if !ok {
		return nil, fail.InvalidRequestError("'Region' not set in tenant 'compute' section")
	}
	folder := fmt.Sprintf("images/%s/%s", svc.GetName(), region)

	db, err := scribble.New(utils.AbsPathify("$HOME/.safescale/scanner/db"), nil)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	var scannedTemplateList []*protocol.HostTemplate

	absTemplates, xerr := svc.ListTemplates(all)
	if xerr != nil {
		return nil, xerr
	}

	for _, template := range absTemplates {
		acpu := StoredCPUInfo{}
		if err := db.Read(folder, template.Name, &acpu); err != nil {
			if !onlyScanned {
				scannedTemplateList = append(scannedTemplateList, &protocol.HostTemplate{
					Id:       template.ID,
					Name:     template.Name,
					Cores:    int32(template.Cores),
					Ram:      int32(template.RAMSize),
					Disk:     int32(template.DiskSize),
					GpuCount: int32(template.GPUNumber),
					GpuType:  template.GPUType,
				})
			}
		} else {
			scannedTemplateList = append(scannedTemplateList, &protocol.HostTemplate{
				Id:       template.ID,
				Name:     template.Name,
				Cores:    int32(template.Cores),
				Ram:      int32(template.RAMSize),
				Disk:     int32(template.DiskSize),
				GpuCount: int32(template.GPUNumber),
				GpuType:  template.GPUType,
				Scanned: &protocol.ScannedInfo{
					TenantName:           acpu.TenantName,
					TemplateId:           acpu.ID,
					TemplateName:         acpu.TemplateName,
					ImageId:              acpu.ImageID,
					ImageName:            acpu.ImageName,
					LastUpdated:          acpu.LastUpdated,
					NumberOfCpu:          int64(acpu.NumberOfCPU),
					NumberOfCore:         int64(acpu.NumberOfCore),
					NumberOfSocket:       int64(acpu.NumberOfSocket),
					CpuFrequency_Ghz:     acpu.CPUFrequency,
					CpuArch:              acpu.CPUArch,
					Hypervisor:           acpu.Hypervisor,
					CpuModel:             acpu.CPUModel,
					RamSize_Gb:           acpu.RAMSize,
					RamFreq:              acpu.RAMFreq,
					Gpu:                  int64(acpu.GPU),
					GpuModel:             acpu.GPUModel,
					DiskSize_Gb:          acpu.DiskSize,
					MainDiskType:         acpu.MainDiskType,
					MainDiskSpeed_MBps:   acpu.MainDiskSpeed,
					SampleNetSpeed_KBps:  acpu.SampleNetSpeed,
					EphDiskSize_Gb:       acpu.EphDiskSize,
					PriceInDollarsSecond: acpu.PricePerSecond,
					PriceInDollarsHour:   acpu.PricePerHour,
					// Not yet implemented, FIXME: Implement this
					// Prices: []*protocol.PriceInfo{{
					// 	Currency:      "euro-fake",
					// 	DurationLabel: "perMonth",
					// 	Duration:      1,
					// 	Price:         30,
					// }},
				},
			})
		}
	}

	return &protocol.TemplateList{Templates: scannedTemplateList}, nil

}
