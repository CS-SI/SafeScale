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

package resources

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/eko/gocache/v2/store"
	uuidpkg "github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/labelproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	labelKind        = "Label"
	labelsFolderName = "labels" // is the name of the Object Storage MetadataFolder used to store Label info
)

// Label links Object Storage MetadataFolder and Labels/Tags
type Label struct {
	*metadata.Core[*abstract.Label]
}

// NewLabel creates an instance of Label
func NewLabel(ctx context.Context) (_ *Label, ferr fail.Error) {
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	coreInstance, xerr := metadata.NewCore(ctx, metadata.MethodObjectStorage, labelKind, labelsFolderName, abstract.NewEmptyLabel())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	instance := &Label{
		Core: coreInstance,
	}
	return instance, nil
}

// LoadLabel loads the metadata of a Label
func LoadLabel(inctx context.Context, ref string) (*Label, fail.Error) {
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if ref = strings.TrimSpace(ref); ref == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	myjob, xerr := jobapi.FromContext(inctx)
	if xerr != nil {
		return nil, xerr
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  *Label
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		ga, gerr := func() (_ *Label, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// trick to avoid collisions
			var kt *Label
			refcache := fmt.Sprintf("%T/%s", kt, ref)

			cache, xerr := myjob.Service().Cache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			var (
				labelInstance *Label
				inCache       bool
				err           error
			)
			if cache != nil {
				entry, err := cache.Get(ctx, refcache)
				if err == nil {
					labelInstance, err = lang.Cast[*Label](entry)
					if err != nil {
						return nil, fail.Wrap(err)
					}

					inCache = true

					// -- reload from metadata storage
					xerr := labelInstance.Core.Reload(ctx)
					if xerr != nil {
						return nil, xerr
					}
				} else {
					logrus.WithContext(ctx).Warnf("cache response: %v", xerr)
				}
			}
			if labelInstance == nil {
				anon, xerr := onLabelCacheMiss(ctx, ref)
				if xerr != nil {
					return nil, xerr
				}

				labelInstance, err = lang.Cast[*Label](anon)
				if err != nil {
					return nil, fail.Wrap(err)
				}
			}

			if cache != nil {
				if !inCache {
					// -- add host instance in cache by name
					err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, labelInstance.GetName()), labelInstance, &store.Options{Expiration: 1 * time.Minute})
					if err != nil {
						return nil, fail.Wrap(err)
					}

					time.Sleep(10 * time.Millisecond) // consolidate cache.Set
					hid, err := labelInstance.GetID()
					if err != nil {
						return nil, fail.Wrap(err)
					}

					// -- add host instance in cache by id
					err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), labelInstance, &store.Options{Expiration: 1 * time.Minute})
					if err != nil {
						return nil, fail.Wrap(err)
					}

					time.Sleep(10 * time.Millisecond) // consolidate cache.Set

					val, xerr := cache.Get(ctx, refcache)
					if xerr == nil {
						if _, ok := val.(*Network); !ok {
							logrus.WithContext(ctx).Warnf("wrong type of *Label")
						}
					} else {
						logrus.WithContext(ctx).Warnf("cache response: %v", xerr)
					}
				}
			}

			if myjob.Service().Capabilities().UseTerraformer {
				labelTrx, xerr := newLabelTransaction(ctx, labelInstance)
				if xerr != nil {
					return nil, xerr
				}
				defer labelTrx.TerminateFromError(ctx, &ferr)

				xerr = inspectLabelMetadataAbstract(ctx, labelTrx, func(al *abstract.Label) fail.Error {
					_, innerXErr := myjob.Scope().RegisterAbstractIfNeeded(al)
					return innerXErr
				})
				if xerr != nil {
					return nil, xerr
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
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	}
}

// onLabelCacheMiss is called when there is no instance in cache of Label 'ref'
func onLabelCacheMiss(ctx context.Context, ref string) (data.Identifiable, fail.Error) {
	labelInstance, innerXErr := NewLabel(ctx)
	if innerXErr != nil {
		return nil, innerXErr
	}

	blank, innerXErr := NewLabel(ctx)
	if innerXErr != nil {
		return nil, innerXErr
	}

	innerXErr = labelInstance.Read(ctx, ref)
	if innerXErr != nil {
		return nil, innerXErr
	}

	if strings.Compare(fail.IgnoreError(labelInstance.String()).(string), fail.IgnoreError(blank.String()).(string)) == 0 {
		return nil, fail.NotFoundError("Label with ref '%s' does NOT exist", ref)
	}

	return labelInstance, nil
}

// IsNull tells if the instance is a null value
func (instance *Label) IsNull() bool {
	return instance == nil || valid.IsNil(instance.Core)
}

func (instance *Label) Clone() (clonable.Clonable, error) {
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}

	newInstance, err := newBulkLabel()
	if err != nil {
		return nil, err
	}

	return newInstance, newInstance.Replace(instance)
}

// newBulkLabel ...
func newBulkLabel() (*Label, fail.Error) {
	protected, err := abstract.NewLabel()
	if err != nil {
		return nil, fail.Wrap(err)
	}

	core, err := metadata.NewEmptyCore(abstract.LabelKind, protected)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	instance := &Label{Core: core}
	return instance, nil
}

func (instance *Label) Replace(in clonable.Clonable) error {
	if instance == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*Subnet](in)
	if err != nil {
		return err
	}

	return instance.Core.Replace(src.Core)
}

// Exists checks if the resource actually exists in provider side (not in stow metadata)
func (instance *Label) Exists(_ context.Context) (bool, fail.Error) {
	return false, fail.NotImplementedError()
}

// Carry ...
func (instance *Label) Carry(ctx context.Context, al *abstract.Label) (ferr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance) && instance.IsTaken() {
		return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
	}
	if al == nil {
		return fail.InvalidParameterCannotBeNilError("al")
	}

	// Note: do not validate parameters, this call will do it
	xerr := instance.Core.Carry(ctx, al)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = instance.Job().Scope().RegisterAbstract(al)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Browse walks through tag MetadataFolder and executes a callback for each entry
func (instance *Label) Browse(ctx context.Context, callback func(*abstract.Label) fail.Error) (ferr fail.Error) {
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

	return instance.Core.BrowseFolder(ctx, func(buf []byte) fail.Error {
		at, _ := abstract.NewLabel()
		xerr := at.Deserialize(buf)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		return callback(at)
	})
}

// Delete deletes Label and its metadata
func (instance *Label) Delete(inctx context.Context) (ferr fail.Error) {
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

	labelTrx, xerr := newLabelTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer labelTrx.TerminateFromError(ctx, &ferr)

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			xerr := inspectLabelMetadataProperty(ctx, labelTrx, labelproperty.HostsV1, func(lhV1 *propertiesv1.LabelHosts) fail.Error {
				if len(lhV1.ByID) > 0 {
					return fail.NotAvailableError("'%s' still bound to Hosts", instance.GetName())
				}

				return nil
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

			// Need to terminate label transaction to be able to Delete metadata (dead-lock otherwise)
			labelTrx.SilentTerminate(ctx)

			// remove metadata
			return instance.Core.Delete(ctx)
		}()
		chRes <- result{gerr}
	}()

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// Create a tag
func (instance *Label) Create(ctx context.Context, name string, hasDefault bool, defaultValue string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance.Core) {
		if instance.Core.IsTaken() {
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
	_, xerr := LoadLabel(ctx, name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			debug.IgnoreErrorWithContext(ctx, xerr)
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

	at, xerr := abstract.NewLabel(abstract.WithName(name))
	if xerr != nil {
		return xerr
	}
	at.ID = uuid.String()
	at.HasDefault = hasDefault
	at.DefaultValue = defaultValue

	// Sets err to possibly trigger defer calls
	return instance.Carry(ctx, at)
}

// ToProtocol converts the Label to protocol message LabelInspectResponse
func (instance *Label) ToProtocol(ctx context.Context, withHosts bool) (_ *protocol.LabelInspectResponse, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	labelTrx, xerr := newLabelTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer labelTrx.TerminateFromError(ctx, &ferr)

	var labelHostsV1 *propertiesv1.LabelHosts
	out := &protocol.LabelInspectResponse{}
	xerr = inspectLabelMetadata(ctx, labelTrx, func(alabel *abstract.Label, props *serialize.JSONProperties) fail.Error {
		var err error
		out.Id, err = alabel.GetID()
		if err != nil {
			return fail.Wrap(err)
		}
		out.Name = alabel.GetName()
		out.HasDefault = alabel.HasDefault
		out.DefaultValue = alabel.DefaultValue

		return props.Inspect(labelproperty.HostsV1, func(p clonable.Clonable) fail.Error {
			var innerErr error
			labelHostsV1, innerErr = clonable.Cast[*propertiesv1.LabelHosts](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
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
			hostInstance, xerr := LoadHost(ctx, k)
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

// IsTag tells of the Label represents a Tag (ie a Label that does not Carry a default value)
func (instance *Label) IsTag(ctx context.Context) (_ bool, ferr fail.Error) {
	if valid.IsNull(instance) {
		return false, fail.InvalidInstanceError()
	}

	labelTrx, xerr := newLabelTransaction(ctx, instance)
	if xerr != nil {
		return false, xerr
	}
	defer labelTrx.TerminateFromError(ctx, &ferr)

	var out bool
	xerr = inspectLabelMetadataAbstract(ctx, labelTrx, func(alabel *abstract.Label) fail.Error {
		out = !alabel.HasDefault
		return nil
	})
	if xerr != nil {
		return false, xerr
	}

	return out, nil
}

// DefaultValue returns the default value of the Label
func (instance *Label) DefaultValue(ctx context.Context) (_ string, ferr fail.Error) {
	if valid.IsNull(instance) {
		return "", fail.InvalidInstanceError()
	}

	labelTrx, xerr := newLabelTransaction(ctx, instance)
	if xerr != nil {
		return "", xerr
	}
	defer labelTrx.TerminateFromError(ctx, &ferr)

	var out string
	xerr = inspectLabelMetadataAbstract(ctx, labelTrx, func(alabel *abstract.Label) fail.Error {
		out = alabel.DefaultValue
		return nil
	})
	if xerr != nil {
		return "", xerr
	}

	return out, nil
}

// BindToHost binds Host to the Label
func (instance *Label) BindToHost(ctx context.Context, hostInstance *Host, value string) (ferr fail.Error) {
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

	labelTrx, xerr := newLabelTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer labelTrx.TerminateFromError(ctx, &ferr)

	hostTrx, xerr := newHostTransaction(ctx, hostInstance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	return labelTrx.BindToHost(ctx, hostTrx, value)
}

// UnbindFromHost removes Host from Label metadata, unbinding Host from Label
// Note: still need to call Host.UnbindLabel to remove reference of Label in Host...
func (instance *Label) UnbindFromHost(ctx context.Context, hostInstance *Host) (ferr fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if valid.IsNull(hostInstance) {
		return fail.InvalidParameterError("hostInstance", "cannot be null value of 'resources.Host'")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.label"), "(Label='%s', host='%s')", instance.GetName(), hostInstance.GetName()).Entering()
	defer tracer.Exiting()

	labelTrx, xerr := newLabelTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer labelTrx.TerminateFromError(ctx, &ferr)

	hostTrx, xerr := newHostTransaction(ctx, hostInstance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	return labelTrx.UnbindFromHost(ctx, hostTrx)
}
