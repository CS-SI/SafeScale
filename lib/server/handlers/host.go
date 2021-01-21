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
	"reflect"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

//go:generate mockgen -destination=../mocks/mock_hostapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers HostHandler

// TODO: At service level, we need to log before returning, because it's the last chance to track the real issue in server side

// HostHandler defines API to manipulate hosts
type HostHandler interface {
	Create(req abstract.HostRequest, sizing abstract.HostSizingRequirements, force bool) (resources.Host, fail.Error)
	List(all bool) (abstract.HostList, fail.Error)
	Inspect(ref string) (resources.Host, fail.Error)
	Delete(ref string) fail.Error
	SSH(ref string) (*system.SSHConfig, fail.Error)
	Reboot(ref string) fail.Error
	Resize(name string, sizing abstract.HostSizingRequirements) (resources.Host, fail.Error)
	Start(ref string) fail.Error
	Stop(ref string) fail.Error
}

// hostHandler host service
type hostHandler struct {
	job server.Job
}

// NewHostHandler ...
func NewHostHandler(job server.Job) HostHandler {
	return &hostHandler{job: job}
}

// Start starts a host
func (handler *hostHandler) Start(ref string) (xerr fail.Error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	objh, xerr := hostfactory.Load(task, handler.job.GetService(), ref)
	if xerr != nil {
		return xerr
	}
	return objh.Start(task)
}

// Stop stops a host
func (handler *hostHandler) Stop(ref string) (xerr fail.Error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	objh, xerr := hostfactory.Load(task, handler.job.GetService(), ref)
	if xerr != nil {
		return xerr
	}
	return objh.Stop(task)
}

// Reboot reboots a host
func (handler *hostHandler) Reboot(ref string) (xerr fail.Error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	objh, xerr := hostfactory.Load(task, handler.job.GetService(), ref)
	if xerr != nil {
		return xerr
	}
	return objh.Reboot(task)
}

// Resize ...
func (handler *hostHandler) Resize(ref string, sizing abstract.HostSizingRequirements) (newHost resources.Host, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return nil, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.host"), "('%s', %v)", ref, sizing).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
	defer fail.OnPanic(&xerr)

	objh, xerr := hostfactory.Load(task, handler.job.GetService(), ref)
	if xerr != nil {
		return nil, xerr
	}

	reduce := false
	xerr = objh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.SizingV1, func(clonable data.Clonable) fail.Error {
			nhs, ok := clonable.(*propertiesv1.HostSizing)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			reduce = reduce || (sizing.MinCores < nhs.RequestedSize.MinCores)
			reduce = reduce || (sizing.MinRAMSize < nhs.RequestedSize.MinRAMSize)
			reduce = reduce || (sizing.MinGPU < nhs.RequestedSize.MinGPU)
			reduce = reduce || (sizing.MinCPUFreq < nhs.RequestedSize.MinCPUFreq)
			reduce = reduce || (sizing.MinDiskSize < nhs.RequestedSize.MinDiskSize)
			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}
	if reduce {
		logrus.Warn("Asking for less resource..., ain't gonna happen :(")
	}

	xerr = objh.Resize(sizing)
	return objh, xerr
}

// Create creates a host
func (handler *hostHandler) Create(
	req abstract.HostRequest, sizing abstract.HostSizingRequirements, force bool,
) (newHost resources.Host, xerr fail.Error) {

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if req.ResourceName == "" {
		return nil, fail.InvalidParameterError("req.Name", "cannot be empty string")
	}

	task := handler.job.GetTask()

	var subnetName string
	if !req.PublicIP {
		if len(req.Subnets) > 0 {
			subnetName = req.Subnets[0].Name
		} else {
			return nil, fail.InvalidParameterError("req.Subnets", "must contain at least one Subnet if req.PublicIP is false")
		}
	} else {
		subnetName = abstract.SingleHostNetworkName
	}
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.host"), "('%s', '%s', '%s', %v, <sizingParam>, %v)", req.ResourceName, subnetName, req.ImageID, req.PublicIP, force).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())
	defer fail.OnPanic(&xerr)

	objh, xerr := hostfactory.New(handler.job.GetService())
	if xerr != nil {
		return nil, xerr
	}
	if _, xerr = objh.Create(task, req, sizing); xerr != nil {
		return nil, xerr
	}
	return objh, nil
}

// List returns the host list
func (handler *hostHandler) List(all bool) (hosts abstract.HostList, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.host"), "(%v)", all).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	return hostfactory.List(task, handler.job.GetService(), all)
	//if all {
	//	return handler.job.GetService().ListHosts(true)
	//}
	//
	//objh, xerr := hostfactory.New(handler.job.GetService())
	//if xerr != nil {
	//	return nil, xerr
	//}
	//hosts = abstract.HostList{}
	//xerr = objh.Browse(task, func(ahc *abstract.HostCore) fail.Error {
	//	hosts = append(hosts, converters.HostCoreToHostFull(*ahc))
	//	return nil
	//})
	//return hosts, xerr
}

// Inspect returns the host identified by ref, ref can be the name or the id
// If not found, returns (nil, nil)
func (handler *hostHandler) Inspect(ref string) (host resources.Host, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return nil, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	objh, xerr := hostfactory.Load(task, handler.job.GetService(), ref)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); ok {
			return nil, abstract.ResourceNotFoundError("host", ref)
		}
		return nil, xerr
	}

	// VPL: temporary
	_, _ = handler.job.GetService().InspectHost(objh.GetID())

	return objh, nil
}

// Delete deletes host referenced by ref
func (handler *hostHandler) Delete(ref string) (xerr fail.Error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
	defer fail.OnPanic(&xerr)

	objh, xerr := hostfactory.Load(task, handler.job.GetService(), ref)
	if xerr != nil {
		return xerr
	}
	return objh.Delete(task)
}

// SSH returns ssh parameters to access the host referenced by ref
func (handler *hostHandler) SSH(ref string) (sshConfig *system.SSHConfig, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return nil, fail.InvalidParameterError("ref", "cannot be nil")
	}

	tracer := debug.NewTracer(handler.job.GetTask(), tracing.ShouldTrace("handlers.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	sshHandler := NewSSHHandler(handler.job)
	sshConfig, xerr = sshHandler.GetConfig(ref)
	if xerr != nil {
		return nil, xerr
	}
	return sshConfig, nil
}
