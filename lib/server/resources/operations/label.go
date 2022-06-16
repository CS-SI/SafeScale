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

package operations

import (
	"context"
	"reflect"
	"strings"

	uuidpkg "github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/labelproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	labelKind        = "label"
	labelsFolderName = "labels" // is the name of the Object Storage MetadataFolder used to store Label info
)

// label links Object Storage MetadataFolder and Labels/Tags
type label struct {
	*MetadataCore
}

// verify that Label satisfies resources.Label
var _ resources.Label = (*label)(nil)

// NewLabel creates an instance of Label
func NewLabel(svc iaas.Service) (_ resources.Label, ferr fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	coreInstance, xerr := NewCore(svc, labelKind, labelsFolderName, abstract.NewLabel())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	instance := &label{
		MetadataCore: coreInstance,
	}
	return instance, nil
}

// LoadLabel loads the metadata of a Label
func LoadLabel(ctx context.Context, svc iaas.Service, ref string, options ...data.ImmutableKeyValue) (_ resources.Label, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if ref = strings.TrimSpace(ref); ref == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	cacheMissLoader := func() (data.Identifiable, fail.Error) { return onLabelCacheMiss(ctx, svc, ref) }
	anon, xerr := cacheMissLoader()
	if xerr != nil {
		return nil, xerr
	}

	labelInstance, ok := anon.(resources.Label)
	if !ok {
		return nil, fail.InconsistentError("value in cache for Label with key '%s' is not a resources.Label", ref)
	}
	if labelInstance == nil {
		return nil, fail.InconsistentError("nil value in cache for Label with key '%s'", ref)
	}

	return labelInstance, nil
}

// onLabelCacheMiss is called when there is no instance in cache of Label 'ref'
func onLabelCacheMiss(ctx context.Context, svc iaas.Service, ref string) (data.Identifiable, fail.Error) {
	labelInstance, innerXErr := NewLabel(svc)
	if innerXErr != nil {
		return nil, innerXErr
	}

	blank, innerXErr := NewLabel(svc)
	if innerXErr != nil {
		return nil, innerXErr
	}

	innerXErr = labelInstance.Read(ctx, ref)
	if innerXErr != nil {
		return nil, innerXErr
	}

	if strings.Compare(fail.IgnoreError(labelInstance.Sdump(ctx)).(string), fail.IgnoreError(blank.Sdump(ctx)).(string)) == 0 {
		return nil, fail.NotFoundError("Label with ref '%s' does NOT exist", ref)
	}

	return labelInstance, nil
}

// IsNull tells if the instance is a null value
func (instance *label) IsNull() bool {
	return instance == nil || instance.MetadataCore == nil || valid.IsNil(instance.MetadataCore)
}

// carry overloads rv.core.Carry() to add Label to service cache
func (instance *label) carry(ctx context.Context, clonable data.Clonable) (ferr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance) {
		if instance.MetadataCore.IsTaken() {
			return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
		}
	}
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
	}

	// Note: do not validate parameters, this call will do it
	xerr := instance.MetadataCore.Carry(ctx, clonable)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Browse walks through tag MetadataFolder and executes a callback for each entry
func (instance *label) Browse(ctx context.Context, callback func(*abstract.Label) fail.Error) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// Note: Browse is intended to be callable from null value, so do not validate instance with .IsNull()
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "cannot be nil")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.label")).Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	return instance.MetadataCore.BrowseFolder(ctx, func(buf []byte) fail.Error {
		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		at := abstract.NewLabel()
		xerr = at.Deserialize(buf)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		return callback(at)
	})
}

// Delete deletes Label and its metadata
func (instance *label) Delete(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterError("ctx", "cannot be nil")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.label")).Entering()
	defer tracer.Exiting()

	xerr = instance.Review(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(labelproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			lhV1, ok := clonable.(*propertiesv1.LabelHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.LabelHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if len(lhV1.ByID) > 0 {
				return fail.NotAvailableError("'%s' still bound to Hosts", instance.GetName())
			}

			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			logrus.Debugf("Unable to find the tag on provider side, cleaning up metadata")
		default:
			return xerr
		}
	}

	// remove metadata
	return instance.MetadataCore.Delete(ctx)
}

// Create a tag
func (instance *label) Create(ctx context.Context, name string, hasDefault bool, defaultValue string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance.MetadataCore) {
		if instance.MetadataCore.IsTaken() {
			return fail.InconsistentError("already carrying information")
		}
	}
	if ctx == nil {
		return fail.InvalidParameterError("ctx", "cannot be nil")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.label"), "('%s')", name).Entering()
	defer tracer.Exiting()

	var kind string
	switch hasDefault {
	case true:
		kind = "Label"
	case false:
		kind = "Tag"
	}

	// Check if Label exists and is managed by SafeScale
	svc := instance.Service()
	_, xerr = LoadLabel(ctx, svc, name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			debug.IgnoreError(xerr)
		default:
			return fail.Wrap(xerr, "failed to check if %s '%s' already exists", kind, name)
		}
	} else {
		return fail.DuplicateError("there is already a %s named '%s'", kind, name)
	}

	uuid, err := uuidpkg.NewV4()
	if err != nil {
		return fail.Wrap(err, "failed to generate uuid for %s", kind)
	}

	at := abstract.Label{
		Name:         name,
		ID:           uuid.String(),
		HasDefault:   hasDefault,
		DefaultValue: defaultValue,
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Sets err to possibly trigger defer calls
	return instance.carry(ctx, &at)
}

// ToProtocol converts the label to protocol message LabelInspectResponse
func (instance *label) ToProtocol(ctx context.Context) (*protocol.LabelInspectResponse, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	out := &protocol.LabelInspectResponse{}
	return out, instance.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		alabel, ok := clonable.(*abstract.Label)
		if !ok {
			return fail.InconsistentError("'*abstract.Label' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		out.Id = alabel.GetID()
		out.Name = alabel.GetName()
		out.HasDefault = alabel.HasDefault
		out.DefaultValue = alabel.DefaultValue

		var labelHostsV1 *propertiesv1.LabelHosts
		innerXErr := props.Inspect(labelproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			var ok bool
			labelHostsV1, ok = clonable.(*propertiesv1.LabelHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.LabelHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		hosts := make([]*protocol.Host, 0)
		for k, v := range labelHostsV1.ByName {
			hosts = append(hosts, &protocol.Host{
				Name: k,
				Id:   v,
			})
		}
		out.Hosts = hosts
		return nil
	})
}

// IsTag tells of the Label represents a Tag (ie a Label that does not carry a defaut value)
func (instance label) IsTag(ctx context.Context) (bool, fail.Error) {
	var out bool
	xerr := instance.Review(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		alabel, ok := clonable.(*abstract.Label)
		if !ok {
			return fail.InconsistentError("'*abstract.Label' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		out = !alabel.HasDefault
		return nil
	})
	if xerr != nil {
		return false, xerr
	}

	return out, nil
}

// DefaultValue returns the default value of the Label
func (instance label) DefaultValue(ctx context.Context) (string, fail.Error) {
	var out string
	xerr := instance.Review(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		alabel, ok := clonable.(*abstract.Label)
		if !ok {
			return fail.InconsistentError("'*abstract.Label' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		out = alabel.DefaultValue
		return nil
	})
	if xerr != nil {
		return "", xerr
	}

	return out, nil
}

// BindToHost binds Host to the Label
func (instance *label) BindToHost(ctx context.Context, hostInstance resources.Host, value string) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if valid.IsNull(hostInstance) {
		return fail.InvalidParameterError("hostInstance", "cannot be null value of 'resources.Host'")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.label"), "('%s', '%s')", instance.GetName(), hostInstance.GetName()).Entering()
	defer tracer.Exiting()

	xerr = instance.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		alabel, ok := clonable.(*abstract.Label)
		if !ok {
			return fail.InconsistentError("'*abstract.Label' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		isTag := !alabel.HasDefault

		return props.Alter(labelproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			labelHostsV1, ok := clonable.(*propertiesv1.LabelHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.LabelHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// If the tag has this host, consider it a success
			hostID := hostInstance.GetID()
			hostName := hostInstance.GetName()
			_, ok = labelHostsV1.ByID[hostID]
			if !ok {
				if isTag {
					value = ""
				}
				labelHostsV1.ByID[hostID] = value
				labelHostsV1.ByName[hostName] = value
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// UnbindFromHost removes Host from Label metadata, unbinding Host from Label
// Note: still need to call Host.UnbindLabel to remove reference of Label in Host...
func (instance *label) UnbindFromHost(ctx context.Context, hostInstance resources.Host) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if valid.IsNull(hostInstance) {
		return fail.InvalidParameterError("hostInstance", "cannot be null value of 'resources.Host'")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.label"), "(label='%s', host='%s')", instance.GetName(), hostInstance.GetName()).Entering()
	defer tracer.Exiting()

	xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(labelproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			labelHostsV1, ok := clonable.(*propertiesv1.LabelHosts)
			if !ok {
				return fail.InconsistentError("'*abstract.Label' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			hID := hostInstance.GetID()
			hName := hostInstance.GetName()

			// If the Label does not reference this Host, consider it a success
			if _, ok = labelHostsV1.ByID[hID]; ok {
				delete(labelHostsV1.ByID, hID)
				delete(labelHostsV1.ByName, hName)
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}
