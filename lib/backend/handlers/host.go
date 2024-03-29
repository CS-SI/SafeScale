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

package handlers

import (
	"reflect"

	"github.com/CS-SI/SafeScale/v22/lib/backend"
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
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
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
	job backend.Job
}

// NewHostHandler is the constructor for HostHandler
func NewHostHandler(job backend.Job) HostHandler {
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), ref, isTerraform)
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), ref, isTerraform)
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), ref, isTerraform)
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

	return hostfactory.List(handler.job.Context(), handler.job.Service(), all)
}

// Create creates a new host
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return nil, xerr
	}
	isTerraform = pn == "terraform"

	hostInstance, xerr := hostfactory.New(handler.job.Service(), isTerraform)
	if xerr != nil {
		return nil, xerr
	}

	_, xerr = hostInstance.Create(handler.job.Context(), req, sizing, nil)
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return hoststate.Unknown, xerr
	}
	isTerraform = pn == "terraform"

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), ref, isTerraform)
	if xerr != nil {
		return hoststate.Unknown, xerr
	}

	// Data sync
	xerr = hostInstance.Reload(handler.job.Context())
	if xerr != nil {
		return hoststate.Unknown, xerr
	}

	// Gather host state from Cloud Provider
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return nil, xerr
	}
	isTerraform = pn == "terraform"

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), ref, isTerraform)
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), ref, isTerraform)
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), hostRef, isTerraform)
	if xerr != nil {
		return xerr
	}

	sgInstance, xerr := securitygroupfactory.Load(handler.job.Context(), handler.job.Service(), sgRef, isTerraform)
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), hostRef, isTerraform)
	if xerr != nil {
		return xerr
	}

	sgInstance, xerr := securitygroupfactory.Load(handler.job.Context(), handler.job.Service(), sgRef, isTerraform)
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), hostRef, isTerraform)
	if xerr != nil {
		return xerr
	}

	sgInstance, xerr := securitygroupfactory.Load(handler.job.Context(), handler.job.Service(), sgRef, isTerraform)
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), hostRef, isTerraform)
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

	sgInstance, xerr := securitygroupfactory.Load(handler.job.Context(), handler.job.Service(), sgRef, isTerraform)
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return nil, xerr
	}
	isTerraform = pn == "terraform"

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), hostRef, isTerraform)
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return nil, xerr
	}
	isTerraform = pn == "terraform"

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), hostRef, isTerraform)
	if xerr != nil {
		return nil, xerr
	}

	if !isTerraform {
		var list []*protocol.LabelInspectResponse
		xerr = hostInstance.Inspect(handler.job.Context(), func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Inspect(hostproperty.LabelsV1, func(clonable data.Clonable) fail.Error {
				hlV1, ok := clonable.(*propertiesv1.HostLabels)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.HostLabels' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				for k := range hlV1.ByID {
					labelInstance, innerXErr := labelfactory.Load(handler.job.Context(), handler.job.Service(), k, isTerraform)
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

	var fact []*protocol.LabelInspectResponse
	labels, xerr := hostInstance.ListLabels(handler.job.Context())
	if xerr != nil {
		return nil, xerr
	}

	for k, v := range labels {
		item := &protocol.LabelInspectResponse{
			Name:       k,
			HasDefault: v != "",
			Value:      v,
		}
		if xerr != nil {
			return nil, xerr
		}
		fact = append(fact, item)
	}

	return fact, nil
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return nil, "", xerr
	}
	isTerraform = pn == "terraform"

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), hostRef, isTerraform)
	if xerr != nil {
		return nil, "", xerr
	}

	labelInstance, xerr := labelfactory.Load(handler.job.Context(), handler.job.Service(), labelRef, isTerraform)
	if xerr != nil {
		return nil, "", xerr
	}

	if !isTerraform {
		var outValue string
		xerr = labelInstance.Inspect(handler.job.Context(), func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Inspect(labelproperty.HostsV1, func(clonable data.Clonable) fail.Error {
				lhV1, ok := clonable.(*propertiesv1.LabelHosts)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.LabelHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				hin, err := hostInstance.GetID()
				if err != nil {
					return fail.ConvertError(err)
				}

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

	val, _ := labelInstance.DefaultValue(handler.job.Context())
	return labelInstance, val, nil
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), hostRef, isTerraform)
	if xerr != nil {
		return xerr
	}

	labelInstance, xerr := labelfactory.Load(handler.job.Context(), handler.job.Service(), labelRef, isTerraform)
	if xerr != nil {
		return xerr
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), hostRef, isTerraform)
	if xerr != nil {
		return xerr
	}

	labelInstance, xerr := labelfactory.Load(handler.job.Context(), handler.job.Service(), labelRef, isTerraform)
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), hostRef, isTerraform)
	if xerr != nil {
		return xerr
	}

	labelInstance, xerr := labelfactory.Load(handler.job.Context(), handler.job.Service(), labelRef, isTerraform)
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), hostRef, isTerraform)
	if xerr != nil {
		return xerr
	}

	labelInstance, xerr := labelfactory.Load(handler.job.Context(), handler.job.Service(), labelRef, isTerraform)
	if xerr != nil {
		return xerr
	}

	if xerr = hostInstance.ResetLabel(handler.job.Context(), labelInstance); xerr != nil {
		return xerr
	}

	return nil
}
