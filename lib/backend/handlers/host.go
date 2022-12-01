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

package handlers

import (
	"github.com/sirupsen/logrus"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/labelproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupstate"
	hostfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/host"
	labelfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/label"
	securitygroupfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/securitygroup"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/backend/handlers.HostHandler -o mocks/mock_host.go

// HostHandler ...
type HostHandler interface {
	BindSecurityGroup(string, string, resources.SecurityGroupActivation) fail.Error
	Create(abstract.HostRequest, abstract.HostSizingRequirements) (resources.Host, fail.Error)
	Delete(string) fail.Error
	DisableSecurityGroup(string, string) fail.Error
	EnableSecurityGroup(string, string) fail.Error
	Inspect(string) (resources.Host, fail.Error)
	List(bool) (abstract.HostList, fail.Error)
	ListSecurityGroups(string) ([]*propertiesv1.SecurityGroupBond, fail.Error)
	Reboot(string) fail.Error
	Resize(string, abstract.HostSizingRequirements) (resources.Host, fail.Error)
	Start(string) fail.Error
	Status(string) (hoststate.Enum, fail.Error)
	Stop(string) fail.Error
	UnbindSecurityGroup(string, string) fail.Error
	BindLabel(hostRef, labelRef, value string) fail.Error
	InspectLabel(hostRef, labelRef string) (resources.Label, string, fail.Error)
	ListLabels(hostRef string, kind string) ([]*protocol.LabelInspectResponse, fail.Error)
	ResetLabel(hostRef, labelRef string) fail.Error
	UnbindLabel(hostRef, labelRef string) fail.Error
	UpdateLabel(hostRef, labelRef, value string) fail.Error
}

// hostHandler is an implementation of interface HostHandler
type hostHandler struct {
	job jobapi.Job
}

// NewHostHandler is the constructor for HostHandler
func NewHostHandler(job jobapi.Job) HostHandler {
	return &hostHandler{job}
}

// Start ...
func (handler *hostHandler) Start(ref string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if ref == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "(%s)", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), ref)
	if xerr != nil {
		return xerr
	}

	xerr = hostInstance.Start(handler.job.Context())
	if xerr != nil {
		return xerr
	}

	return nil
}

// Stop shutdowns a host.
func (handler *hostHandler) Stop(ref string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if ref == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "(%s)", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), ref)
	if xerr != nil {
		return xerr
	}

	if xerr = hostInstance.Stop(handler.job.Context()); xerr != nil {
		return xerr
	}

	return nil
}

// Reboot reboots a host.
func (handler *hostHandler) Reboot(ref string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if ref == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "(%s)", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), ref)
	if xerr != nil {
		return xerr
	}

	xerr = hostInstance.Reboot(handler.job.Context(), false)
	if xerr != nil {
		return xerr
	}

	return nil
}

// List lists hosts managed by SafeScale only, or all hosts.
func (handler *hostHandler) List(all bool) (_ abstract.HostList, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "(%v)", all).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	return hostfactory.List(handler.job.Context(), all)
}

// Create creates a new host
// Note: returned resources.Host has to be .Released() by caller
func (handler *hostHandler) Create(req abstract.HostRequest, sizing abstract.HostSizingRequirements) (_ resources.Host, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "('%s')", req.ResourceName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.New(handler.job.Context())
	if xerr != nil {
		return nil, xerr
	}

	_, xerr = hostInstance.Create(handler.job.Context(), req, sizing, nil)
	if xerr != nil {
		return nil, xerr
	}

	return hostInstance, nil
}

// Resize a Host
func (handler *hostHandler) Resize(ref string, sizing abstract.HostSizingRequirements) (_ resources.Host, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), ref)
	if xerr != nil {
		return nil, xerr
	}

	reduce := false
	xerr = hostInstance.Inspect(handler.job.Context(), func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.SizingV2, func(p clonable.Clonable) fail.Error {
			hostSizingV2, innerErr := clonable.Cast[*propertiesv2.HostSizing](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			reduce = reduce || (sizing.MinCores < hostSizingV2.RequestedSize.MinCores)
			reduce = reduce || (sizing.MinRAMSize < hostSizingV2.RequestedSize.MinRAMSize)
			reduce = reduce || (sizing.MinGPU < hostSizingV2.RequestedSize.MinGPU)
			reduce = reduce || (sizing.MinCPUFreq < hostSizingV2.RequestedSize.MinCPUFreq)
			reduce = reduce || (sizing.MinDiskSize < hostSizingV2.RequestedSize.MinDiskSize)
			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}

	if reduce {
		logrus.Warn("Asking for less resource... is not going to happen")
	}

	xerr = hostInstance.Resize(handler.job.Context(), sizing)
	if xerr != nil {
		return nil, xerr
	}

	return hostInstance, nil
}

// Status returns the status of a host (running or stopped mainly)
func (handler *hostHandler) Status(ref string) (_ hoststate.Enum, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return hoststate.Unknown, fail.InvalidInstanceError()
	}
	if ref == "" {
		return hoststate.Unknown, fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "(%s)", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), ref)
	if xerr != nil {
		return hoststate.Unknown, xerr
	}

	// Data sync
	xerr = hostInstance.Reload(handler.job.Context())
	if xerr != nil {
		return hoststate.Unknown, xerr
	}

	// Gather host state from Cloud provider
	return hostInstance.ForceGetState(handler.job.Context())
}

// Inspect a host
func (handler *hostHandler) Inspect(ref string) (_ resources.Host, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ref == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), ref)
	if xerr != nil {
		return nil, xerr
	}

	_, xerr = hostInstance.ForceGetState(handler.job.Context())
	if xerr != nil {
		return nil, xerr
	}

	return hostInstance, nil
}

// Delete a host
func (handler *hostHandler) Delete(ref string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if ref == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "(%s)", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), ref)
	if xerr != nil {
		return xerr
	}

	xerr = hostInstance.Delete(handler.job.Context())
	if xerr != nil {
		return xerr
	}

	return nil
}

// BindSecurityGroup attaches a Security Group to a host
func (handler *hostHandler) BindSecurityGroup(hostRef, sgRef string, enable resources.SecurityGroupActivation) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if hostRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}
	if sgRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("sgRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "(%s, %s)", hostRef, sgRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), hostRef)
	if xerr != nil {
		return xerr
	}

	sgInstance, xerr := securitygroupfactory.Load(handler.job.Context(), sgRef)
	if xerr != nil {
		return xerr
	}

	xerr = hostInstance.BindSecurityGroup(handler.job.Context(), sgInstance, enable)
	if xerr != nil {
		return xerr
	}

	return nil
}

// UnbindSecurityGroup detaches a Security Group from a host
func (handler *hostHandler) UnbindSecurityGroup(hostRef, sgRef string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if hostRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}
	if sgRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("sgRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "(%s, %s)", hostRef, sgRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), hostRef)
	if xerr != nil {
		return xerr
	}

	sgInstance, xerr := securitygroupfactory.Load(handler.job.Context(), sgRef)
	if xerr != nil {
		return xerr
	}

	return hostInstance.UnbindSecurityGroup(handler.job.Context(), sgInstance)
}

// EnableSecurityGroup applies a Security Group already attached (if not already applied)
func (handler *hostHandler) EnableSecurityGroup(hostRef, sgRef string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if hostRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}
	if sgRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("sgRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "(%s, %s)", hostRef, sgRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), hostRef)
	if xerr != nil {
		return xerr
	}

	sgInstance, xerr := securitygroupfactory.Load(handler.job.Context(), sgRef)
	if xerr != nil {
		return xerr
	}

	xerr = hostInstance.EnableSecurityGroup(handler.job.Context(), sgInstance)
	if xerr != nil {
		return xerr
	}

	return nil
}

// DisableSecurityGroup applies a Security Group already attached (if not already applied)
func (handler *hostHandler) DisableSecurityGroup(hostRef, sgRef string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if hostRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}
	if sgRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("sgRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "(%s, %s)", hostRef, sgRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), hostRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// disabling a SecurityGroup from a non existing Host is considered as a success
			debug.IgnoreError(xerr)
			return nil

		default:
			return xerr
		}
	}

	sgInstance, xerr := securitygroupfactory.Load(handler.job.Context(), sgRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// disabling a non-existent SecurityGroup from a Host is also considered as a success
			debug.IgnoreError(xerr)
			return nil
		default:
			return xerr
		}
	}

	if xerr = hostInstance.DisableSecurityGroup(handler.job.Context(), sgInstance); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// disabling a non-existent SecurityGroup from a Host is also considered as a success
			debug.IgnoreError(xerr)
			return nil

		default:
			return xerr
		}
	}

	return nil
}

// ListSecurityGroups applies a Security Group already attached (if not already applied)
func (handler *hostHandler) ListSecurityGroups(hostRef string) (_ []*propertiesv1.SecurityGroupBond, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if hostRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "(%s)", hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), hostRef)
	if xerr != nil {
		return nil, xerr
	}

	return hostInstance.ListSecurityGroups(handler.job.Context(), securitygroupstate.All)
}

// ListLabels lists Label/Tag bound to an Host
func (handler *hostHandler) ListLabels(hostRef string, kind string) (_ []*protocol.LabelInspectResponse, ferr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if hostRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "(%s, kind=%s)", hostRef, kind).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), hostRef)
	if xerr != nil {
		return nil, xerr
	}

	var list []*protocol.LabelInspectResponse
	xerr = hostInstance.Review(handler.job.Context(), func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.LabelsV1, func(p clonable.Clonable) fail.Error {
			hlV1, innerErr := clonable.Cast[*propertiesv1.HostLabels](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			for k := range hlV1.ByID {
				labelInstance, innerXErr := labelfactory.Load(handler.job.Context(), k)
				if innerXErr != nil {
					return innerXErr
				}

				item, innerXErr := labelInstance.ToProtocol(handler.job.Context(), false)
				if innerXErr != nil {
					return innerXErr
				}

				list = append(list, item)
			}
			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}

	return list, nil
}

// InspectLabel inspects a Label of a Host
func (handler *hostHandler) InspectLabel(hostRef, labelRef string) (_ resources.Label, _ string, ferr fail.Error) {
	if handler == nil {
		return nil, "", fail.InvalidInstanceError()
	}
	if hostRef == "" {
		return nil, "", fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}
	if labelRef == "" {
		return nil, "", fail.InvalidParameterCannotBeEmptyStringError("labelRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "(%s, %s)", hostRef, labelRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), hostRef)
	if xerr != nil {
		return nil, "", xerr
	}

	labelInstance, xerr := labelfactory.Load(handler.job.Context(), labelRef)
	if xerr != nil {
		return nil, "", xerr
	}

	var outValue string
	xerr = labelInstance.Review(handler.job.Context(), func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(labelproperty.HostsV1, func(p clonable.Clonable) fail.Error {
			lhV1, innerErr := clonable.Cast[*propertiesv1.LabelHosts](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			hin, err := hostInstance.GetID()
			if err != nil {
				return fail.ConvertError(err)
			}

			var ok bool
			outValue, ok = lhV1.ByID[hin]
			if !ok {
				return fail.NotFoundError()
			}

			return nil
		})
	})
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return nil, "", fail.NotFoundError("failed to find Label '%s' bound to Host '%s'", labelInstance.GetName(), hostInstance.GetName())
		default:
			return nil, "", xerr
		}
	}

	return labelInstance, outValue, nil
}

// BindLabel binds a Label to a Host
func (handler *hostHandler) BindLabel(hostRef, labelRef, value string) (ferr fail.Error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if hostRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}
	if labelRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("labelRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "(%s, %s)", hostRef, labelRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), hostRef)
	if xerr != nil {
		return xerr
	}

	labelInstance, xerr := labelfactory.Load(handler.job.Context(), labelRef)
	if xerr != nil {
		return xerr
	}

	if value == "" {
		value, xerr = labelInstance.DefaultValue(handler.job.Context())
		if xerr != nil {
			return xerr
		}
	}
	xerr = hostInstance.BindLabel(handler.job.Context(), labelInstance, value)
	if xerr != nil {
		return xerr
	}

	return nil
}

// UnbindLabel unbinds a Label from a Host
func (handler *hostHandler) UnbindLabel(hostRef, labelRef string) (ferr fail.Error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if hostRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}
	if labelRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("labelRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "(%s, %s)", hostRef, labelRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), hostRef)
	if xerr != nil {
		return xerr
	}

	labelInstance, xerr := labelfactory.Load(handler.job.Context(), labelRef)
	if xerr != nil {
		return xerr
	}

	xerr = hostInstance.UnbindLabel(handler.job.Context(), labelInstance)
	if xerr != nil {
		return xerr
	}

	return nil
}

// UpdateLabel updates Label value for the Host
func (handler *hostHandler) UpdateLabel(hostRef, labelRef, value string) (ferr fail.Error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if hostRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}
	if labelRef == "" {
		return fail.InvalidRequestError("neither name nor id given as reference of Label")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "(%s, %s)", hostRef, labelRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), hostRef)
	if xerr != nil {
		return xerr
	}

	labelInstance, xerr := labelfactory.Load(handler.job.Context(), labelRef)
	if xerr != nil {
		return xerr
	}

	xerr = hostInstance.UpdateLabel(handler.job.Context(), labelInstance, value)
	if xerr != nil {
		return xerr
	}

	return nil
}

// ResetLabel restores default value of Label to the Host
func (handler *hostHandler) ResetLabel(hostRef, labelRef string) (ferr fail.Error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if hostRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}
	if labelRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("labelRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "(%s, %s)", hostRef, labelRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), hostRef)
	if xerr != nil {
		return xerr
	}

	labelInstance, xerr := labelfactory.Load(handler.job.Context(), labelRef)
	if xerr != nil {
		return xerr
	}

	if xerr = hostInstance.ResetLabel(handler.job.Context(), labelInstance); xerr != nil {
		return xerr
	}

	return nil
}
