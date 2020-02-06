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
	"fmt"
	"reflect"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstracts"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

//go:generate mockgen -destination=../mocks/mock_hostapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers HostAPI

// TODO: At service level, we need to log before returning, because it's the last chance to track the real issue in server side

// HostAPI defines API to manipulate hosts
type HostHandler interface {
	Create(name string, net string, os string, public bool, sizingParam interface{}, force bool) (*resources.Host, error)
	List(all bool) ([]*resources.Host, error)
	ForceInspect(ref string) (*resources.Host, error)
	Inspect(ref string) (*resources.Host, error)
	Delete(ref string) error
	SSH(ref string) (*system.SSHConfig, error)
	Reboot(ref string) error
	Resize(name string, cpu int, ram float32, disk int, gpuNumber int, freq float32) (*resources.Host, error)
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

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	objh, err := hostfactory.Load(task, handler.service, ref)
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

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	objh, err := hostfactory.Load(task, handler.service, ref)
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

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	objh, err := hostfactory.Load(task, handler.service, ref)
	if err != nil {
		return err
	}
	return objh.Reboot(task)
}

// Resize ...
func (handler *HostHandler) Resize(ref string, cpu int, ram float32, disk int, gpuNumber int, freq float32) (newHost resources.Host, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return nil, scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, fmt.Sprintf("('%s', %d, %.02f, %d, %d, %.02f)", ref, cpu, ram, disk, gpuNumber, freq), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	objh, err := hostfactory.Load(task, handler.service, ref)
	if err != nil {
		return nil, err
	}

	hostSizeRequest := abstracts.SizingRequirements{
		MinDiskSize: disk,
		MinRAMSize:  ram,
		MinCores:    cpu,
		MinFreq:     freq,
		MinGPU:      gpuNumber,
	}

	descent := false
	err = objh.Inspect(task, func(clonable data.Clonabl, props *serialize.JSONProperties) error {
		return props.Inspect(hostproperty.SizingV1, func(clonable data.Clonable) error {
			nhs, ok := clonable.(*propertiesv1.HostSizing)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			descent = descent || (hostSizeRequest.MinCores < nhs.RequestedSize.Cores)
			descent = descent || (hostSizeRequest.MinRAMSize < nhs.RequestedSize.RAMSize)
			descent = descent || (hostSizeRequest.MinGPU < nhs.RequestedSize.GPUNumber)
			descent = descent || (hostSizeRequest.MinFreq < nhs.RequestedSize.CPUFreq)
			descent = descent || (hostSizeRequest.MinDiskSize < nhs.RequestedSize.DiskSize)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if descent {
		log.Warn("Asking for less abstracts..., ain't gonna happen :(")
	}

	err = objh.Resize(hostSizeRequest)
	return objh, err
}

// Create creates a host
func (handler *HostHandler) Create(
	req abstracts.HostRequest, sizing abstracts.SizingRequirements, force bool,
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

	task := handler.job.Task()

	var networkName string
	if !req.PublicIP {
		if len(req.Networks) > 0 {
			networkName = req.Networks[0].Name
		} else {
			return nil, scerr.InvalidParameterError("req.Networks", "must contain at least on network if req.PublicIP is false")
		}
	} else {
		networkName = abstracts.SingleHostNetworkName
	}
	tracer := concurrency.NewTracer(
		task,
		fmt.Sprintf("('%s', '%s', '%s', %v, <sizingParam>, %v)",
			req.ResourceName, networkName, req.ImageID, req.PublicIP, force),
		true,
	).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	objh, err := hostfactory.New(handler.service)
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
func (handler *hostHandler) List(all bool) (hosts []*abstracts.Host, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError()
	}

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, fmt.Sprintf("(%v)", all), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	if all {
		return handler.job.Service().ListHosts()
	}

	objh, err := hostfactory.New(handler.service)
	if err != nil {
		return nil, err
	}
	hosts = []*abstracts.Host{}
	err = objh.Browse(task, func(host *abstracts.Host) error {
		hosts = append(hosts, host)
		return nil
	})
	return hosts, err
}

// Inspect returns the host identified by ref, ref can be the name or the id
// If not found, returns (nil, nil)
func (handler *HostHandler) Inspect(ctx context.Context, ref string) (host resources.Host, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return nil, scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	objh, err := hostfactory.Load(task, handler.service, ref)
	if err != nil {
		if _, ok := err.(*scerr.ErrNotFound); ok {
			return nil, nil
		}
		return nil, err
	}
	return objh, nil
}

// Delete deletes host referenced by ref
func (handler *HostHandler) Delete(ref string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	objh, err := hostfactory.Load(task, handler.service, ref)
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

	tracer := concurrency.NewTracer(handler.job.Task(), fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	sshHandler := NewSSHHandler(handler.job)
	sshConfig, err = sshHandler.GetConfig(ref)
	if err != nil {
		return nil, err
	}
	return sshConfig, nil
}
