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

package handlers

import (
	"reflect"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

//go:generate mockgen -destination=../mocks/mock_hostapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers HostHandler

// TODO: At service level, we need to log before returning, because it's the last chance to track the real issue in server side

// HostHandler defines API to manipulate hosts
type HostHandler interface {
	Create(req abstract.HostRequest, sizing abstract.HostSizingRequirements, force bool) (resources.Host, error)
	List(all bool) (abstract.HostList, error)
	Inspect(ref string) (resources.Host, error)
	Delete(ref string) error
	SSH(ref string) (*system.SSHConfig, error)
	Reboot(ref string) error
	Resize(name string, sizing abstract.HostSizingRequirements) (resources.Host, error)
	Start(ref string) error
	Stop(ref string) error
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
func (handler *hostHandler) Start(ref string) (err error) { // FIXME Unused ctx
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	objh, err := hostfactory.Load(task, handler.job.SafeGetService(), ref)
	if err != nil {
		return err
	}
	return objh.Start(task)
}

// Stop stops a host
func (handler *hostHandler) Stop(ref string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	objh, err := hostfactory.Load(task, handler.job.SafeGetService(), ref)
	if err != nil {
		return err
	}
	return objh.Stop(task)
}

// Reboot reboots a host
func (handler *hostHandler) Reboot(ref string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	objh, err := hostfactory.Load(task, handler.job.SafeGetService(), ref)
	if err != nil {
		return err
	}
	return objh.Reboot(task)
}

// Resize ...
func (handler *hostHandler) Resize(ref string, sizing abstract.HostSizingRequirements) (newHost resources.Host, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return nil, scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.host"), "('%s', %v)", ref, sizing).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	objh, err := hostfactory.Load(task, handler.job.SafeGetService(), ref)
	if err != nil {
		return nil, err
	}

	reduce := false
	err = objh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(hostproperty.SizingV1, func(clonable data.Clonable) error {
			nhs, ok := clonable.(*propertiesv1.HostSizing)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			reduce = reduce || (sizing.MinCores < nhs.RequestedSize.MinCores)
			reduce = reduce || (sizing.MinRAMSize < nhs.RequestedSize.MinRAMSize)
			reduce = reduce || (sizing.MinGPU < nhs.RequestedSize.MinGPU)
			reduce = reduce || (sizing.MinCPUFreq < nhs.RequestedSize.MinFreq)
			reduce = reduce || (sizing.MinDiskSize < nhs.RequestedSize.MinDiskSize)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if reduce {
		logrus.Warn("Asking for less resource..., ain't gonna happen :(")
	}

	err = objh.Resize(sizing)
	return objh, err
}

// Create creates a host
func (handler *hostHandler) Create(
	req abstract.HostRequest, sizing abstract.HostSizingRequirements, force bool,
) (newHost resources.Host, err error) {

	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if req.ResourceName == "" {
		return nil, scerr.InvalidParameterError("req.Name", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()

	var networkName string
	if !req.PublicIP {
		if len(req.Networks) > 0 {
			networkName = req.Networks[0].Name
		} else {
			return nil, scerr.InvalidParameterError("req.Networks", "must contain at least on network if req.PublicIP is false")
		}
	} else {
		networkName = abstract.SingleHostNetworkName
	}
	tracer := concurrency.NewTracer(
		task,
		debug.IfTrace("handlers.host"),
		"('%s', '%s', '%s', %v, <sizingParam>, %v)", req.ResourceName, networkName, req.ImageID, req.PublicIP, force,
	).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	objh, err := hostfactory.New(handler.job.SafeGetService())
	if err != nil {
		return nil, err
	}
	err = objh.Create(task, req, sizing)
	if err != nil {
		return nil, err
	}
	return objh, nil
}

// List returns the host list
func (handler *hostHandler) List(all bool) (hosts abstract.HostList, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.host"), "(%v)", all).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	if all {
		return handler.job.SafeGetService().ListHosts(true)
	}

	objh, err := hostfactory.New(handler.job.SafeGetService())
	if err != nil {
		return nil, err
	}
	hosts = abstract.HostList{}
	err = objh.Browse(task, func(host *abstract.HostCore) error {
		hosts = append(hosts, converters.HostCoreToHostFull(*host))
		return nil
	})
	return hosts, err
}

// Inspect returns the host identified by ref, ref can be the name or the id
// If not found, returns (nil, nil)
func (handler *hostHandler) Inspect(ref string) (host resources.Host, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return nil, scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	objh, err := hostfactory.Load(task, handler.job.SafeGetService(), ref)
	if err != nil {
		if _, ok := err.(*scerr.ErrNotFound); ok {
			return nil, nil
		}
		return nil, err
	}
	return objh, nil
}

// Delete deletes host referenced by ref
func (handler *hostHandler) Delete(ref string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	objh, err := hostfactory.Load(task, handler.job.SafeGetService(), ref)
	if err != nil {
		return err
	}
	return objh.Delete(task)
}

// SSH returns ssh parameters to access the host referenced by ref
func (handler *hostHandler) SSH(ref string) (sshConfig *system.SSHConfig, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return nil, scerr.InvalidParameterError("ref", "cannot be nil")
	}

	tracer := concurrency.NewTracer(handler.job.SafeGetTask(), debug.IfTrace("handlers.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	sshHandler := NewSSHHandler(handler.job)
	sshConfig, err = sshHandler.GetConfig(ref)
	if err != nil {
		return nil, err
	}
	return sshConfig, nil
}
