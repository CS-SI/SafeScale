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

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	uuidpkg "github.com/gofrs/uuid"
)

const (
	tagKind        = "tag"
	tagsFolderName = "tags" // is the name of the Object Storage MetadataFolder used to store tag info
)

// Tag links Object Storage MetadataFolder and unsafeGetTags
type tag struct {
	*MetadataCore
}

// NewTag creates an instance of Tag
func NewTag(svc iaas.Service) (_ resources.Tag, ferr fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	coreInstance, xerr := NewCore(svc, tagKind, tagsFolderName, &abstract.Tag{})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	instance := &tag{
		MetadataCore: coreInstance,
	}
	return instance, nil
}

// LoadTag loads the metadata of a tag
func LoadTag(ctx context.Context, svc iaas.Service, ref string, options ...data.ImmutableKeyValue) (tagInstance resources.Tag, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if ref = strings.TrimSpace(ref); ref == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	cacheMissLoader := func() (data.Identifiable, fail.Error) { return onTagCacheMiss(svc, ref) }
	anon, xerr := cacheMissLoader()
	if xerr != nil {
		return nil, xerr
	}

	var ok bool
	tagInstance, ok = anon.(resources.Tag)
	if !ok {
		return nil, fail.InconsistentError("value in cache for Tag with key '%s' is not a resources.Tag", ref)
	}
	if tagInstance == nil {
		return nil, fail.InconsistentError("nil value in cache for Tag with key '%s'", ref)
	}

	return tagInstance, nil
}

// onTagCacheMiss is called when there is no instance in cache of Tag 'ref'
func onTagCacheMiss(svc iaas.Service, ref string) (data.Identifiable, fail.Error) {
	tagInstance, innerXErr := NewTag(svc)
	if innerXErr != nil {
		return nil, innerXErr
	}

	blank, innerXErr := NewTag(svc)
	if innerXErr != nil {
		return nil, innerXErr
	}

	if innerXErr = tagInstance.Read(ref); innerXErr != nil {
		return nil, innerXErr
	}

	if strings.Compare(fail.IgnoreError(tagInstance.Sdump()).(string), fail.IgnoreError(blank.Sdump()).(string)) == 0 {
		return nil, fail.NotFoundError("tag with ref '%s' does NOT exist", ref)
	}

	return tagInstance, nil
}

// IsNull tells if the instance is a null value
func (instance *tag) IsNull() bool {
	return instance == nil || instance.MetadataCore == nil || valid.IsNil(instance.MetadataCore)
}

// carry overloads rv.core.Carry() to add Tag to service cache
func (instance *tag) carry(ctx context.Context, clonable data.Clonable) (ferr fail.Error) {
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
	xerr := instance.MetadataCore.Carry(clonable)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Browse walks through tag MetadataFolder and executes a callback for each entry
func (instance *tag) Browse(ctx context.Context, callback func(*abstract.Tag) fail.Error) (ferr fail.Error) {
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

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.tag")).Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	return instance.MetadataCore.BrowseFolder(func(buf []byte) fail.Error {
		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		at := abstract.NewTag()
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

// Delete deletes Tag and its metadata
func (instance *tag) Delete(ctx context.Context) (ferr fail.Error) {
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

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.tag")).Entering()
	defer tracer.Exiting()

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
	return instance.MetadataCore.Delete()
}

// Create a tag
func (instance *tag) Create(ctx context.Context, req abstract.TagRequest) (ferr fail.Error) {
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

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.tag"), "('%s')", req.Name).Entering()
	defer tracer.Exiting()

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	// Check if Tag exists and is managed by SafeScale
	svc := instance.Service()
	_, xerr = LoadTag(ctx, svc, req.Name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			debug.IgnoreError(xerr)
		default:
			return fail.Wrap(xerr, "failed to check if Tag '%s' already exists", req.Name)
		}
	} else {
		return fail.DuplicateError("there is already a Tag named '%s'", req.Name)
	}

	uuid, err := uuidpkg.NewV4()
	if err != nil {
		return fail.Wrap(err, "failed to generate uuid for Tag")
	}

	at := abstract.Tag{
		Name: req.Name,
		ID:   uuid.String(),
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Sets err to possibly trigger defer calls
	return instance.carry(ctx, &at)
}

// ToProtocol converts the tag to protocol message TagInspectResponse
func (instance *tag) ToProtocol(ctx context.Context) (*protocol.TagInspectResponse, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	out := &protocol.TagInspectResponse{}
	return out, instance.Inspect(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		atag, ok := clonable.(*abstract.Tag)
		if !ok {
			return fail.InconsistentError("'*abstract.Tag' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		out.Id = atag.GetID()
		out.Name = atag.GetName()

		hosts := make([]*protocol.Host, 0)
		for k, v := range atag.HostsByName {
			hosts = append(hosts, &protocol.Host{
				Name: k,
				Id:   v,
			})
		}
		out.Hosts = hosts
		return nil
	})
}
