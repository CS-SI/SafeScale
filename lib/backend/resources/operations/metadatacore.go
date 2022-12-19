//go:build !debug
// +build !debug

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
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	serializer "github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/shielded"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	// byIDFolderName tells in what MetadataFolder to put 'byID' information
	byIDFolderName = "byID"
	// byNameFolderName tells in what MetadataFolder to store 'byName' information
	byNameFolderName = "byName"
)

// MetadataCore contains the core functions of a persistent object
type MetadataCore struct {
	id    atomic.Value
	name  atomic.Value
	taken atomic.Value

	shielded   *shielded.Shielded
	properties *serializer.JSONProperties
	sync.RWMutex

	kind   string
	folder MetadataFolder

	lastUpdate time.Time

	loaded            bool
	committed         bool
	deleted           bool
	kindSplittedStore bool // tells if data read/write is done directly from/to folder (when false) or from/to subfolders (when true)
}

// NewCore creates an instance of MetadataCore
func NewCore(svc iaas.Service, kind string, path string, instance data.Clonable) (_ *MetadataCore, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if kind == "" {
		return nil, fail.InvalidParameterError("kind", "cannot be empty string")
	}
	if path == "" {
		return nil, fail.InvalidParameterError("path", "cannot be empty string")
	}

	fld, xerr := NewMetadataFolder(svc, path)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	props, err := serializer.NewJSONProperties("resources." + kind)
	err = debug.InjectPlannedFail(err)
	if err != nil {
		return nil, err
	}

	protected, cerr := shielded.NewShielded(instance)
	if cerr != nil {
		return nil, fail.Wrap(cerr)
	}

	c := MetadataCore{
		kind:       kind,
		folder:     fld,
		properties: props,
		shielded:   protected,
	}
	switch kind {
	case clusterKind:
		c.kindSplittedStore = false
	default:
		c.kindSplittedStore = true
	}
	c.taken.Store(false)

	return &c, nil
}

// IsNull returns true if the MetadataCore instance represents the null value for MetadataCore
func (myself *MetadataCore) IsNull() bool {
	return myself == nil || myself.kind == ""
}

// Service returns the iaas.Service used to create/load the persistent object
func (myself *MetadataCore) Service() iaas.Service {
	return myself.folder.Service()
}

// GetID returns the id of the data protected
// satisfies interface data.Identifiable
func (myself *MetadataCore) GetID() (string, error) {
	val, err := myself.getID()
	if err != nil {
		panic(err)
	}
	return val, nil
}

func (myself *MetadataCore) getID() (string, fail.Error) {
	if myself == nil {
		return "", fail.InvalidInstanceError()
	}

	id, ok := myself.id.Load().(string) // nolint
	if !ok {
		return "", fail.InvalidInstanceError()
	}
	return id, nil
}

// GetName returns the name of the data protected
// satisfies interface data.Identifiable
func (myself *MetadataCore) GetName() string {
	name, err := myself.getName()
	if err != nil {
		panic(err)
	}
	return name
}

func (myself *MetadataCore) getName() (string, fail.Error) {
	if myself == nil {
		return "", fail.InvalidInstanceError()
	}

	name, ok := myself.name.Load().(string) // nolint
	if !ok {
		return "", fail.InvalidInstanceError()
	}
	return name, nil
}

func (myself *MetadataCore) IsValid() (bool, fail.Error) {
	if myself == nil {
		return false, fail.InvalidInstanceError()
	}

	aID, xerr := myself.getID()
	if xerr != nil {
		return false, nil
	}

	if aID == "" {
		return false, nil
	}

	name, xerr := myself.getName()
	if xerr != nil {
		return false, nil
	}

	if name == "" {
		return false, nil
	}

	if !myself.loaded && !myself.committed {
		return false, nil
	}

	if myself.deleted {
		return false, nil
	}

	return true, nil
}

func (myself *MetadataCore) IsTaken() bool {
	taken, ok := myself.taken.Load().(bool)
	if !ok {
		return false
	}
	return taken
}

// GetKind returns the kind of object served
func (myself *MetadataCore) GetKind() string {
	return myself.kind
}

// Inspect protects the data for shared read
func (myself *MetadataCore) Inspect(inctx context.Context, callback resources.Callback) (rerr fail.Error) {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}

	if itis, xerr := myself.IsValid(); xerr == nil && !itis {
		return fail.InconsistentError("the instance is not valid")
	}

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

			if callback == nil {
				return fail.InvalidParameterCannotBeNilError("callback")
			}
			if myself.properties == nil {
				return fail.InvalidInstanceContentError("myself.properties", "cannot be nil")
			}

			timings, xerr := myself.Service().Timings()
			if xerr != nil {
				return xerr
			}

			// Reload reloads data from Object Storage to be sure to have the last revision
			xerr = retry.WhileUnsuccessfulWithLimitedRetries(func() error {
				select {
				case <-ctx.Done():
					return retry.StopRetryError(ctx.Err())
				default:
				}

				myself.Lock()
				xerr = myself.unsafeReload(ctx)
				myself.Unlock() // nolint
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return fail.Wrap(xerr, "failed to unsafeReload metadata")
				}
				return nil
			},
				timings.SmallDelay(),
				timings.ContextTimeout(),
				6)
			if xerr != nil {
				return fail.ConvertError(xerr.Cause())
			}

			myself.RLock()
			defer myself.RUnlock()

			xerr = retry.WhileUnsuccessfulWithLimitedRetries(func() error {
				select {
				case <-ctx.Done():
					return retry.StopRetryError(ctx.Err())
				default:
				}
				return myself.shielded.Inspect(func(clonable data.Clonable) fail.Error {
					return callback(clonable, myself.properties)
				})
			},
				timings.SmallDelay(),
				timings.ConnectionTimeout(),
				6)
			if xerr != nil {
				return fail.ConvertError(xerr.Cause())
			}
			return nil
		}()
		chRes <- result{gerr}
	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		<-chRes
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return fail.ConvertError(inctx.Err())
	}
}

// Review allows to access data contained in the instance, without reloading from the Object Storage; it's intended
// to speed up operations that accept data is not up-to-date (for example, SSH configuration to access host should not
// change through time).
func (myself *MetadataCore) Review(inctx context.Context, callback resources.Callback) (rerr fail.Error) {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}

	if itis, xerr := myself.IsValid(); xerr == nil && !itis {
		return fail.InconsistentError("the instance is not valid")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	myself.RLock()
	defer myself.RUnlock()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if callback == nil {
				return fail.InvalidParameterCannotBeNilError("callback")
			}
			if myself.properties == nil {
				return fail.InvalidInstanceContentError("myself.properties", "cannot be nil")
			}

			return myself.shielded.Inspect(func(clonable data.Clonable) fail.Error {
				return callback(clonable, myself.properties)
			})
		}()
		chRes <- result{gerr}
	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		<-chRes
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return fail.ConvertError(inctx.Err())
	}
}

// Alter protects the data for exclusive write
// Valid keyvalues for options are :
// - "Reload": bool = allow disabling reloading from Object Storage if set to false (default is true)
func (myself *MetadataCore) Alter(inctx context.Context, callback resources.Callback) (rerr fail.Error) {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}

	if itis, xerr := myself.IsValid(); xerr == nil && !itis {
		return fail.InconsistentError("the instance is not valid")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	myself.Lock()
	defer myself.Unlock()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if callback == nil {
				return fail.InvalidParameterCannotBeNilError("callback")
			}
			if myself.shielded == nil {
				return fail.InvalidInstanceContentError("myself.shielded", "cannot be nil")
			}

			if name, err := myself.getName(); err != nil {
				return fail.InconsistentError("uninitialized metadata should not be altered")
			} else if name == "" {
				return fail.InconsistentError("uninitialized metadata should not be altered")
			}

			if id, err := myself.getID(); err != nil {
				return fail.InconsistentError("uninitialized metadata should not be altered")
			} else if id == "" {
				return fail.InconsistentError("uninitialized metadata should not be altered")
			}

			// Make sure myself.properties is populated
			if myself.properties == nil {
				var xerr fail.Error
				myself.properties, xerr = serializer.NewJSONProperties("resources." + myself.kind)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}
			}

			xerr := myself.unsafeReload(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return fail.Wrap(xerr, "failed to unsafeReload metadata")
			}

			rollbacked, err := myself.shielded.UnWrap()
			if err != nil {
				return fail.ConvertError(err)
			}

			defer func() {
				if ferr != nil {
					err := myself.shielded.RollBack(rollbacked)
					if err != nil {
						return
					}
					myself.committed = true
				}
			}()

			xerr = myself.shielded.Alter(func(clonable data.Clonable) fail.Error {
				return callback(clonable, myself.properties)
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrAlteredNothing:
					return nil
				default:
					return xerr
				}
			}

			myself.committed = false

			var aerr fail.Error
			aerr = debug.InjectPlannedFail(aerr)
			if aerr != nil {
				return aerr
			}

			xerr = myself.write(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			return nil
		}()
		chRes <- result{gerr}
	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		<-chRes
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return fail.ConvertError(inctx.Err())
	}
}

// Carry links metadata with real data
// If c is already carrying a shielded data, returns fail.NotAvailableError
//
// errors returned :
// - fail.ErrInvalidInstance
// - fail.ErrInvalidParameter
// - fail.ErrNotAvailable if the MetadataCore instance already carries a data
func (myself *MetadataCore) Carry(inctx context.Context, clonable data.Clonable) (rerr fail.Error) {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	myself.Lock()
	defer myself.Unlock()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if myself == nil {
				return fail.InvalidInstanceError()
			}
			if !valid.IsNil(myself) {
				if myself.IsTaken() {
					return fail.InvalidRequestError("cannot carry, already carries something")
				}
			}
			if clonable == nil {
				return fail.InvalidParameterCannotBeNilError("clonable")
			}
			if myself.shielded == nil {
				return fail.InvalidInstanceContentError("myself.shielded", "cannot be nil")
			}
			if myself.loaded {
				return fail.NotAvailableError("already carrying a value")
			}

			var cerr error
			myself.shielded, cerr = shielded.NewShielded(clonable)
			if cerr != nil {
				return fail.Wrap(cerr)
			}
			myself.loaded = true

			xerr := myself.updateIdentity()
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			myself.committed = false

			xerr = myself.write(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			return nil
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

// updateIdentity updates instance cached identity
func (myself *MetadataCore) updateIdentity() fail.Error {
	if myself.loaded {
		issue := myself.shielded.Alter(func(clonable data.Clonable) fail.Error {
			ident, ok := clonable.(data.Identifiable)
			if !ok {
				return fail.InconsistentError("'data.Identifiable' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			idd, err := ident.GetID()
			if err != nil {
				return fail.ConvertError(err)
			}

			if loaded, ok := myself.id.Load().(string); ok {
				if idd == loaded {
					return nil
				}
			}

			named, ok := clonable.(data.Named)
			if !ok {
				return fail.InconsistentError("expected Identifiable and Named")
			}
			if myself.kindSplittedStore {
				myself.id.Store(idd)
			} else {
				myself.id.Store(named.GetName())
			}
			myself.name.Store(named.GetName())
			myself.taken.Store(true)

			return nil
		})
		if issue != nil {
			return issue
		}

		return nil
	}

	return fail.InconsistentError("uninitialized data should NOT be updated")
}

// Read gets the data from Object Storage
func (myself *MetadataCore) Read(inctx context.Context, ref string) (_ fail.Error) {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}

	myself.Lock()
	defer myself.Unlock()

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

			if myself == nil {
				return fail.InvalidInstanceError()
			}
			if ref = strings.TrimSpace(ref); ref == "" {
				return fail.InvalidParameterError("ref", "cannot be empty string")
			}
			if myself.loaded {
				return fail.NotAvailableError("metadata is already carrying a value")
			}

			bu, xerr := myself.folder.getBucket(ctx)
			if xerr != nil {
				return xerr
			}

			if !myself.kindSplittedStore {
				isName, xerr := myself.Service().HasObject(ctx, bu.GetName(), myself.folder.absolutePath("", ref))
				if xerr != nil {
					return xerr
				}

				if isName {
					xerr := myself.readByName(ctx, ref)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						return xerr
					}

					myself.loaded = true
					myself.committed = true

					return myself.updateIdentity()
				}

				return fail.NotFoundError("%s was NOT found in the bucket", myself.folder.absolutePath("", ref))
			}

			isName, xerr := myself.Service().HasObject(ctx, bu.GetName(), myself.folder.absolutePath(byNameFolderName, ref))
			if xerr != nil {
				return xerr
			}

			if isName {
				xerr := myself.readByName(ctx, ref)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}
			}

			isID, xerr := myself.Service().HasObject(ctx, bu.GetName(), myself.folder.absolutePath(byIDFolderName, ref))
			if xerr != nil {
				return xerr
			}

			if isID {
				xerr := myself.readByID(ctx, ref)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}
			}

			if !isID && !isName {
				return fail.NotFoundError("neither %s nor %s were found in the bucket", myself.folder.absolutePath(byNameFolderName, ref), myself.folder.absolutePath(byIDFolderName, ref))
			}

			myself.loaded = true
			myself.committed = true

			return myself.updateIdentity()
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

// ReadByID reads a metadata identified by ID from Object Storage
func (myself *MetadataCore) ReadByID(inctx context.Context, id string) (_ fail.Error) {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}

	myself.Lock()
	defer myself.Unlock()

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

			if myself == nil {
				return fail.InvalidInstanceError()
			}
			if id = strings.TrimSpace(id); id == "" {
				return fail.InvalidParameterError("id", "cannot be empty string")
			}
			if myself.loaded {
				return fail.NotAvailableError("metadata is already carrying a value")
			}

			timings, xerr := myself.Service().Timings()
			if xerr != nil {
				return xerr
			}

			if myself.kindSplittedStore {
				xerr = retry.WhileUnsuccessful(
					func() error {
						select {
						case <-ctx.Done():
							return retry.StopRetryError(ctx.Err())
						default:
						}

						if innerXErr := myself.readByID(ctx, id); innerXErr != nil {
							switch innerXErr.(type) {
							case *fail.ErrNotFound: // If not found, stop immediately
								return retry.StopRetryError(innerXErr)
							case *fail.ErrInconsistent, *fail.ErrInvalidParameter, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent:
								return retry.StopRetryError(innerXErr)
							default:
								return innerXErr
							}
						}
						return nil
					},
					timings.SmallDelay(),
					timings.ContextTimeout(),
				)
			} else {
				xerr = retry.WhileUnsuccessful(
					func() error {
						select {
						case <-ctx.Done():
							return retry.StopRetryError(ctx.Err())
						default:
						}

						if innerXErr := myself.readByName(ctx, id); innerXErr != nil {
							switch innerXErr.(type) {
							case *fail.ErrNotFound: // If not found, stop immediately
								return retry.StopRetryError(innerXErr)
							case *fail.ErrInconsistent, *fail.ErrInvalidParameter, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent:
								return retry.StopRetryError(innerXErr)
							default:
								return innerXErr
							}
						}
						return nil
					},
					timings.SmallDelay(),
					timings.ContextTimeout(),
				)
			}
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *retry.ErrTimeout:
					return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", myself.kind, id)
				case *retry.ErrStopRetry:
					return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", myself.kind, id)
				default:
					return fail.Wrap(xerr, "failed to read %s by id %s", myself.kind, id)
				}
			}

			myself.loaded = true
			myself.committed = true

			return myself.updateIdentity()
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

// readByID reads a metadata identified by ID from Object Storage
func (myself *MetadataCore) readByID(inctx context.Context, id string) fail.Error {
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

			var path string
			if myself.kindSplittedStore {
				path = byIDFolderName
			}

			timings, xerr := myself.Service().Timings()
			if xerr != nil {
				return xerr
			}

			rerr := retry.WhileUnsuccessful(func() error {
				select {
				case <-ctx.Done():
					return retry.StopRetryError(ctx.Err())
				default:
				}

				werr := myself.folder.Read(ctx, path, id, func(buf []byte) fail.Error {
					select {
					case <-ctx.Done():
						return retry.StopRetryError(ctx.Err())
					default:
					}

					if innerXErr := myself.unsafeDeserialize(ctx, buf); innerXErr != nil {
						switch innerXErr.(type) {
						case *fail.ErrNotAvailable:
							return fail.Wrap(innerXErr, "failed to unsafeDeserialize %s resource", myself.kind)
						case *fail.ErrSyntax:
							return fail.Wrap(innerXErr, "failed to unsafeDeserialize %s resource", myself.kind)
						case *fail.ErrInconsistent, *fail.ErrInvalidParameter, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent:
							return retry.StopRetryError(innerXErr)
						default:
							return fail.Wrap(innerXErr, "failed to unsafeDeserialize %s resource", myself.kind)
						}
					}
					return nil
				})
				if werr != nil {
					switch werr.Cause().(type) {
					case *fail.ErrNotFound:
						return retry.StopRetryError(werr, "quit trying")
					default:
						return werr
					}
				}
				return nil
			},
				timings.SmallDelay(),
				timings.ContextTimeout())

			if rerr != nil {
				return fail.ConvertError(rerr.Cause())
			}

			return nil
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

// readByName reads a metadata identified by name
func (myself *MetadataCore) readByName(inctx context.Context, name string) fail.Error {
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

			var path string
			if myself.kindSplittedStore {
				path = byNameFolderName
			}

			timings, xerr := myself.Service().Timings()
			if xerr != nil {
				return xerr
			}

			rerr := retry.WhileUnsuccessful(func() error {
				select {
				case <-ctx.Done():
					return retry.StopRetryError(ctx.Err())
				default:
				}
				werr := myself.folder.Read(ctx, path, name, func(buf []byte) fail.Error {
					select {
					case <-ctx.Done():
						return retry.StopRetryError(ctx.Err())
					default:
					}

					if innerXErr := myself.unsafeDeserialize(ctx, buf); innerXErr != nil {
						return fail.Wrap(innerXErr, "failed to unsafeDeserialize %s '%s'", myself.kind, name)
					}
					return nil
				})
				if werr != nil {
					switch werr.Cause().(type) {
					case *fail.ErrNotFound:
						return retry.StopRetryError(werr, "quit trying")
					default:
						return werr
					}
				}
				return nil
			},
				timings.SmallDelay(),
				timings.ContextTimeout())

			if rerr != nil {
				return fail.ConvertError(rerr.Cause())
			}

			return nil
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

// write updates the metadata corresponding to the host in the Object Storage
func (myself *MetadataCore) write(inctx context.Context) fail.Error {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	var aerr fail.Error
	aerr = debug.InjectPlannedFail(aerr)
	if aerr != nil {
		return aerr
	}

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if !myself.committed {
				jsoned, xerr := myself.unsafeSerialize(ctx)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}

				name, ok := myself.name.Load().(string)
				if !ok {
					return fail.InconsistentError("field 'name' is not set with string")
				}

				if myself.kindSplittedStore {
					xerr = myself.folder.Write(ctx, byNameFolderName, name, jsoned)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						return xerr
					}

					id, ok := myself.id.Load().(string)
					if !ok {
						return fail.InconsistentError("field 'id' is not set with string")
					}

					xerr = myself.folder.Write(ctx, byIDFolderName, id, jsoned)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						return xerr
					}
				} else {
					xerr = myself.folder.Write(ctx, "", name, jsoned)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						return xerr
					}
				}

				myself.loaded = true
				myself.committed = true
			}
			return nil
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

// Reload reloads the content from the Object Storage
func (myself *MetadataCore) Reload(inctx context.Context) (ferr fail.Error) {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}

	myself.Lock()
	defer myself.Unlock()

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

			return myself.unsafeReload(ctx)
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

// unsafeReload loads the content from the Object Storage
// Note: must be called after locking the instance
func (myself *MetadataCore) unsafeReload(inctx context.Context) fail.Error {
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

			timings, xerr := myself.Service().Timings()
			if xerr != nil {
				return xerr
			}

			if myself.kindSplittedStore {
				xerr = retry.WhileUnsuccessful(
					func() error {
						select {
						case <-ctx.Done():
							return retry.StopRetryError(ctx.Err())
						default:
						}

						id, ok := myself.id.Load().(string)
						if !ok {
							return fail.InconsistentError("field 'id' is not set with string")
						}

						if myself.loaded && !myself.committed {
							name, ok := myself.name.Load().(string)
							if ok {
								return fail.InconsistentError("cannot unsafeReload a not committed data with name %s and kind %s", name, myself.kind)
							}
							return fail.InconsistentError("cannot unsafeReload a not committed data without name and kind %s", myself.kind)
						}

						if innerXErr := myself.readByID(ctx, id); innerXErr != nil {
							switch innerXErr.(type) {
							case *fail.ErrNotFound: // If not found, stop immediately
								return retry.StopRetryError(innerXErr)
							case *fail.ErrInconsistent, *fail.ErrInvalidParameter, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent:
								return retry.StopRetryError(innerXErr)
							default:
								return innerXErr
							}
						}
						return nil
					},
					timings.SmallDelay(),
					2*timings.MetadataTimeout(),
				)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *retry.ErrTimeout:
						return fail.Wrap(fail.RootCause(xerr), "failed to unsafeReload (kind %s) %s", myself.kind, myself.id)
					case *retry.ErrStopRetry:
						return fail.Wrap(fail.RootCause(xerr), "failed to unsafeReload (kind %s) %s", myself.kind, myself.id)
					default:
						return fail.Wrap(xerr, "failed to unsafeReload (kind %s) %s", myself.kind, myself.id)
					}
				}
			} else {
				xerr = retry.WhileUnsuccessful(
					func() error {
						select {
						case <-ctx.Done():
							return retry.StopRetryError(ctx.Err())
						default:
						}

						name, ok := myself.name.Load().(string)
						if !ok {
							return fail.InconsistentError("field 'name' is not set with string")
						}
						if name == "" {
							return fail.InconsistentError("field 'name' cannot be empty")
						}

						if myself.loaded && !myself.committed {
							name, ok := myself.name.Load().(string)
							if ok {
								return fail.InconsistentError("cannot unsafeReload a not committed data with name %s and kind %s", name, myself.kind)
							}
							return fail.InconsistentError("cannot unsafeReload a not committed data without name and kind %s", myself.kind)
						}

						if innerXErr := myself.readByName(ctx, name); innerXErr != nil {
							switch innerXErr.(type) {
							case *fail.ErrNotFound: // If not found, stop immediately
								return retry.StopRetryError(innerXErr)
							case *fail.ErrInconsistent, *fail.ErrInvalidParameter, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent:
								return retry.StopRetryError(innerXErr)
							default:
								return innerXErr
							}
						}
						return nil
					},
					timings.SmallDelay(),
					timings.ContextTimeout(),
				)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *retry.ErrTimeout:
						return fail.Wrap(fail.RootCause(xerr), "failed (timeout) to unsafeReload (kind %s) %s", myself.kind, myself.name)
					case *retry.ErrStopRetry:
						return fail.Wrap(fail.RootCause(xerr), "failed to  to unsafeReload (kind %s) %s", myself.kind, myself.name)
					default:
						return fail.Wrap(xerr, "failed to  to unsafeReload (kind %s) %s", myself.kind, myself.name)
					}
				}
			}

			myself.loaded = true
			myself.committed = true

			return nil
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

// BrowseFolder walks through MetadataFolder and executes a callback for each entry
func (myself *MetadataCore) BrowseFolder(inctx context.Context, callback func(buf []byte) fail.Error) (_ fail.Error) {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}

	myself.RLock()
	defer myself.RUnlock()

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

			if callback == nil {
				return fail.InvalidParameterError("callback", "cannot be nil")
			}

			if myself.kindSplittedStore {
				return myself.folder.Browse(ctx, byIDFolderName, func(buf []byte) fail.Error {
					return callback(buf)
				})
			}
			return myself.folder.Browse(ctx, "", func(buf []byte) fail.Error {
				return callback(buf)
			})
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

// Delete deletes the metadata
func (myself *MetadataCore) Delete(inctx context.Context) (_ fail.Error) {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}

	myself.Lock()
	defer myself.Unlock()

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

			var (
				idFound, nameFound bool
				errors             []error
			)

			// Checks entries exist in Object Storage
			if myself.kindSplittedStore {
				id, ok := myself.id.Load().(string)
				if !ok {
					return fail.InconsistentError("field 'id' is not set with string")
				}

				xerr := myself.folder.Lookup(ctx, byIDFolderName, id)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// If entry not found, consider operation not an error
						logrus.WithContext(ctx).Tracef("MetadataFolder not found by id, maybe not an error")
					default:
						errors = append(errors, xerr)
					}
				} else {
					idFound = true
				}

				name, ok := myself.name.Load().(string)
				if !ok {
					return fail.InconsistentError("field 'name' is not set with string")
				}
				if name == "" {
					return fail.InconsistentError("field 'name' cannot be empty")
				}

				xerr = myself.folder.Lookup(ctx, byNameFolderName, name)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// If entry not found, consider operation not an error
						logrus.WithContext(ctx).Tracef("MetadataFolder not found by name, maybe not an error")
					default:
						errors = append(errors, xerr)
					}
				} else {
					nameFound = true
				}

				// Deletes entries found
				if idFound {
					xerr = myself.folder.Delete(ctx, byIDFolderName, id)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						errors = append(errors, xerr)
					}
				}
				if nameFound {
					xerr = myself.folder.Delete(ctx, byNameFolderName, name)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						errors = append(errors, xerr)
					}
				}
			} else {
				name, ok := myself.name.Load().(string)
				if !ok {
					return fail.InconsistentError("field 'name' is not set with string")
				}

				xerr := myself.folder.Lookup(ctx, "", name)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// If entry not found, consider operation not an error
						logrus.WithContext(ctx).Tracef("MetadataFolder not found by name, maybe not an error")
					default:
						errors = append(errors, xerr)
					}
				} else {
					nameFound = true
				}
				if nameFound {
					xerr = myself.folder.Delete(ctx, "", name)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						errors = append(errors, xerr)
					}
				}
			}

			if len(errors) > 0 {
				return fail.NewErrorList(errors)
			}

			myself.loaded = false
			myself.committed = false
			myself.deleted = true

			return nil
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

func (myself *MetadataCore) Sdump(inctx context.Context) (string, fail.Error) {
	if valid.IsNil(myself) {
		return "", fail.InvalidInstanceError()
	}

	myself.RLock()
	defer myself.RUnlock()

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  string
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		dump, gerr := func() (_ string, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			dumped, err := myself.shielded.Sdump()
			if err != nil {
				return "", fail.ConvertError(err)
			}

			props, err := myself.properties.Sdump()
			if err != nil {
				return "", fail.ConvertError(err)
			}

			return dumped + props, nil
		}()
		chRes <- result{dump, gerr}
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return "", fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return "", fail.ConvertError(inctx.Err())
	}
}

// unsafeSerialize serializes instance into bytes (output json code)
// Note: must be called after locking the instance
func (myself *MetadataCore) unsafeSerialize(inctx context.Context) ([]byte, fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  []byte
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gtr, gerr := func() (_ []byte, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			var (
				shieldedMapped = map[string]interface{}{}
				propsMapped    = map[string]string{}
			)

			shieldedJSONed, xerr := myself.shielded.Serialize()
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			err := json.Unmarshal(shieldedJSONed, &shieldedMapped)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return nil, fail.NewErrorWithCause(err, "*MetadataCore.Serialize(): Unmarshalling JSONed shielded into map failed!")
			}

			if myself.properties.Count() > 0 {
				propsJSONed, xerr := myself.properties.Serialize()
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return nil, xerr
				}

				if len(propsJSONed) > 0 && string(propsJSONed) != `"{}"` {
					if jserr := json.Unmarshal(propsJSONed, &propsMapped); jserr != nil {
						return nil, fail.ConvertError(jserr)
					}
				}
			}

			shieldedMapped["properties"] = propsMapped

			r, err := json.Marshal(shieldedMapped)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return nil, fail.ConvertError(err)
			}

			return r, nil
		}()
		chRes <- result{gtr, gerr}
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

// Deserialize reads json code and reinstantiates
func (myself *MetadataCore) Deserialize(inctx context.Context, buf []byte) fail.Error {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}

	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	myself.Lock()
	defer myself.Unlock()

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

			return myself.unsafeDeserialize(ctx, buf)
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

// unsafeDeserialize reads json code and instantiates a MetadataCore
// Note: must be called after locking the instance
func (myself *MetadataCore) unsafeDeserialize(inctx context.Context, buf []byte) fail.Error {
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

			if myself.properties == nil {
				var xerr fail.Error
				myself.properties, xerr = serializer.NewJSONProperties("resources." + myself.kind)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}
			}

			var (
				mapped, props map[string]interface{}
				ok            bool
				jsoned        []byte
			)

			if buf != nil {
				err := json.Unmarshal(buf, &mapped)
				err = debug.InjectPlannedError(err)
				if err != nil {
					if strings.Contains(err.Error(), "unexpected end of input") {
						return fail.NotAvailableErrorWithCause(err, nil, "server returned incomplete data")
					}
					return fail.SyntaxErrorWithCause(err, nil, "unmarshalling JSON to map failed")
				}
				if props, ok = mapped["properties"].(map[string]interface{}); ok {
					delete(mapped, "properties")
				}
			}

			jsoned, err := json.Marshal(mapped)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return fail.SyntaxErrorWithCause(err, nil, "failed to marshal MetadataCore to JSON")
			}

			xerr := myself.shielded.Deserialize(jsoned)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return fail.Wrap(xerr, "deserializing MetadataCore failed")
			}

			if len(props) > 0 {
				jsoned, err = json.Marshal(props)
				err = debug.InjectPlannedError(err)
				if err != nil {
					return fail.SyntaxErrorWithCause(err, nil, "failed to marshal properties to JSON")
				}

				xerr = myself.properties.Deserialize(jsoned)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return fail.Wrap(xerr, "failed to unsafeDeserialize properties")
				}
			}
			return nil
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
