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
	"reflect"

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/labelproperty"
	hostfactory "github.com/CS-SI/SafeScale/v22/lib/server/resources/factories/host"
	labelfactory "github.com/CS-SI/SafeScale/v22/lib/server/resources/factories/label"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// HostHandler defines API to manipulate Hosts
type HostHandler interface {
	BindLabel(hostRef, labelRef, value string) fail.Error
	InspectLabel(hostRef, labelRef string) (_ resources.Label, value string, ferr fail.Error)
	ListLabels(hostRef string, kind string) (_ []*protocol.LabelInspectResponse, ferr fail.Error)
	ResetLabel(hostRef, labelRef string) fail.Error
	UnbindLabel(hostRef, labelRef string) fail.Error
	UpdateLabel(hostRef, labelRef, value string) fail.Error
}

// hostHandler ...
type hostHandler struct {
	job server.Job
}

// NewHostHandler creates a HostHandler
func NewHostHandler(job server.Job) HostHandler {
	return &hostHandler{job: job}
}

// ListLabels lists Label/Tag bound to an Host
func (handler *hostHandler) ListLabels(hostRef string, kind string) (_ []*protocol.LabelInspectResponse, ferr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if hostRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}

	tracer := debug.NewTracer(handler.job.Task(), tracing.ShouldTrace("handlers.host"), "(%s, kind=%s)", hostRef, kind).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), hostRef)
	if xerr != nil {
		return nil, xerr
	}

	var list []*protocol.LabelInspectResponse
	xerr = hostInstance.Review(handler.job.Context(), func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.LabelsV1, func(clonable data.Clonable) fail.Error {
			hlV1, ok := clonable.(*propertiesv1.HostLabels)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostLabels' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			for k := range hlV1.ByID {
				labelInstance, innerXErr := labelfactory.Load(handler.job.Context(), handler.job.Service(), k)
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
func (handler *hostHandler) InspectLabel(hostRef, labelRef string) (_ resources.Label, value string, ferr fail.Error) {
	if handler == nil {
		return nil, "", fail.InvalidInstanceError()
	}
	if hostRef == "" {
		return nil, "", fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}
	if labelRef == "" {
		return nil, "", fail.InvalidParameterCannotBeEmptyStringError("labelRef")
	}

	tracer := debug.NewTracer(handler.job.Task(), tracing.ShouldTrace("handlers.host"), "(%s, %s)", hostRef, labelRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), hostRef)
	if xerr != nil {
		return nil, "", xerr
	}

	labelInstance, xerr := labelfactory.Load(handler.job.Context(), handler.job.Service(), labelRef)
	if xerr != nil {
		return nil, "", xerr
	}

	var outValue string
	xerr = labelInstance.Review(handler.job.Context(), func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(labelproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			lhV1, ok := clonable.(*propertiesv1.LabelHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.LabelHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			outValue, ok = lhV1.ByID[hostInstance.GetID()]
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

	tracer := debug.NewTracer(handler.job.Task(), tracing.ShouldTrace("handlers.host"), "(%s, %s)", hostRef, labelRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), hostRef)
	if xerr != nil {
		return xerr
	}

	labelInstance, xerr := labelfactory.Load(handler.job.Context(), handler.job.Service(), labelRef)
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

	tracer := debug.NewTracer(handler.job.Task(), tracing.ShouldTrace("handlers.host"), "(%s, %s)", hostRef, labelRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), hostRef)
	if xerr != nil {
		return xerr
	}

	labelInstance, xerr := labelfactory.Load(handler.job.Context(), handler.job.Service(), labelRef)
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

	tracer := debug.NewTracer(handler.job.Task(), tracing.ShouldTrace("handlers.host"), "(%s, %s)", hostRef, labelRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), hostRef)
	if xerr != nil {
		return xerr
	}

	labelInstance, xerr := labelfactory.Load(handler.job.Context(), handler.job.Service(), labelRef)
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

	tracer := debug.NewTracer(handler.job.Task(), tracing.ShouldTrace("handlers.host"), "(%s, %s)", hostRef, labelRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), hostRef)
	if xerr != nil {
		return xerr
	}

	labelInstance, xerr := labelfactory.Load(handler.job.Context(), handler.job.Service(), labelRef)
	if xerr != nil {
		return xerr
	}

	if xerr = hostInstance.ResetLabel(handler.job.Context(), labelInstance); xerr != nil {
		return xerr
	}

	return nil
}
