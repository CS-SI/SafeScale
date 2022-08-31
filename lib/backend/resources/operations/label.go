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
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/eko/gocache/v2/store"
	uuidpkg "github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/labelproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
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
func LoadLabel(inctx context.Context, svc iaas.Service, ref string, options ...data.ImmutableKeyValue) (resources.Label, fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  resources.Label
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		ga, gerr := func() (_ resources.Label, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if svc == nil {
				return nil, fail.InvalidParameterCannotBeNilError("svc")
			}
			if ref = strings.TrimSpace(ref); ref == "" {
				return nil, fail.InvalidParameterCannotBeEmptyStringError("ref")
			}

			// trick to avoid collisions
			var kt *label
			cacheref := fmt.Sprintf("%T/%s", kt, ref)

			cache, xerr := svc.GetCache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				if val, xerr := cache.Get(ctx, cacheref); xerr == nil {
					casted, ok := val.(resources.Label)
					if ok {
						return casted, nil
					}
				}
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

			// if cache failed we are here, so we better retrieve updated information...
			xerr = labelInstance.Reload(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, labelInstance.GetName()), labelInstance, &store.Options{Expiration: 1 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(10 * time.Millisecond) // consolidate cache.Set
				hid, err := labelInstance.GetID()
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), labelInstance, &store.Options{Expiration: 1 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(10 * time.Millisecond) // consolidate cache.Set

				if val, xerr := cache.Get(ctx, cacheref); xerr == nil {
					casted, ok := val.(resources.Label)
					if ok {
						return casted, nil
					} else {
						logrus.WithContext(ctx).Warnf("wrong type of resources.Label")
					}
				} else {
					logrus.WithContext(ctx).Warnf("cache response: %v", xerr)
				}
			}

			return labelInstance, nil
		}()
		chRes <- result{ga, gerr}
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
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

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.label")).Entering()
	defer tracer.Exiting()

	return instance.MetadataCore.BrowseFolder(ctx, func(buf []byte) fail.Error {
		at := abstract.NewLabel()
		xerr := at.Deserialize(buf)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		return callback(at)
	})
}

// Delete deletes Label and its metadata
func (instance *label) Delete(inctx context.Context) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterError("inctx", "cannot be nil")
	}

	tracer := debug.NewTracer(inctx, tracing.ShouldTrace("resources.label")).Entering()
	defer tracer.Exiting()

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			xerr := instance.Review(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
					logrus.WithContext(ctx).Debugf("Unable to find the tag on provider side, cleaning up metadata")
				default:
					return xerr
				}
			}

			// remove metadata
			return instance.MetadataCore.Delete(ctx)
		}()
		chRes <- result{gerr}
	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}
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

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.label"), "('%s')", name).Entering()
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
	_, xerr := LoadLabel(ctx, svc, name)
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

	// Sets err to possibly trigger defer calls
	return instance.carry(ctx, &at)
}

// ToProtocol converts the label to protocol message LabelInspectResponse
func (instance *label) ToProtocol(ctx context.Context, withHosts bool) (*protocol.LabelInspectResponse, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	var labelHostsV1 *propertiesv1.LabelHosts
	out := &protocol.LabelInspectResponse{}
	xerr := instance.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		alabel, ok := clonable.(*abstract.Label)
		if !ok {
			return fail.InconsistentError("'*abstract.Label' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		var err error
		out.Id, err = alabel.GetID()
		if err != nil {
			return fail.ConvertError(err)
		}
		out.Name = alabel.GetName()
		out.HasDefault = alabel.HasDefault
		out.DefaultValue = alabel.DefaultValue

		return props.Inspect(labelproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			var ok bool
			labelHostsV1, ok = clonable.(*propertiesv1.LabelHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.LabelHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}

	if withHosts {
		hosts := make([]*protocol.LabelHostResponse, 0)
		for k, v := range labelHostsV1.ByID {
			hostInstance, xerr := LoadHost(ctx, instance.Service(), k)
			if xerr != nil {
				return nil, xerr
			}
			hosts = append(hosts, &protocol.LabelHostResponse{
				Host: &protocol.Reference{
					Id:   k,
					Name: hostInstance.GetName(),
				},
				Value: v,
			})
		}
		out.Hosts = hosts
	}
	return out, nil
}

// IsTag tells of the Label represents a Tag (ie a Label that does not carry a default value)
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

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.label"), "('%s', '%s')", instance.GetName(), hostInstance.GetName()).Entering()
	defer tracer.Exiting()

	xerr := instance.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
			hostID, err := hostInstance.GetID()
			if err != nil {
				return fail.ConvertError(err)
			}
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

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.label"), "(label='%s', host='%s')", instance.GetName(), hostInstance.GetName()).Entering()
	defer tracer.Exiting()

	xerr := instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(labelproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			labelHostsV1, ok := clonable.(*propertiesv1.LabelHosts)
			if !ok {
				return fail.InconsistentError("'*abstract.Label' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			hID, err := hostInstance.GetID()
			if err != nil {
				return fail.ConvertError(err)
			}
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