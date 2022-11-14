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

package metadata

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	terraformerapi "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata/storage"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/shielded"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	// byIDFolderName tells in what folder to put 'byID' information
	byIDFolderName = "byID"
	// byNameFolderName tells in what folder to store 'byName' information
	byNameFolderName = "byName"
)

// Core contains the core functions of a persistent object
type Core struct {
	sync.RWMutex
	id                atomic.Value
	name              atomic.Value
	taken             atomic.Value
	shielded          *shielded.Shielded
	properties        *serialize.JSONProperties
	kind              string
	folder            storage.Folder
	loaded            bool
	committed         bool
	kindSplittedStore bool // tells if data read/write is done directly from/to folder (when false) or from/to subfolders (when true)
}

// NewCore creates an instance of Core
func NewCore(ctx context.Context, method string, kind string, path string, instance clonable.Clonable) (_ *Core, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if kind == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("kind")
	}
	if path == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("path")
	}

	fld, xerr := NewFolder(ctx, UseMethod(method), WithPrefix(path))
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	props, err := serialize.NewJSONProperties("resources." + kind)
	err = debug.InjectPlannedFail(err)
	if err != nil {
		return nil, err
	}

	protected, cerr := shielded.NewShielded(instance)
	if cerr != nil {
		return nil, fail.Wrap(cerr)
	}

	c := Core{
		kind:       kind,
		folder:     fld,
		properties: props,
		shielded:   protected,
	}
	switch kind {
	case "organization", "project", "cluster":
		c.kindSplittedStore = false
	default:
		c.kindSplittedStore = true
	}
	c.taken.Store(false)

	return &c, nil
}

// IsNull returns true if the Core instance represents the null value for Core
func (myself *Core) IsNull() bool {
	return myself == nil || myself.kind == ""
}

// Service returns the iaasapi.Service used to create/load the persistent object
func (myself *Core) Service() iaasapi.Service {
	return myself.folder.Service()
}

func (myself *Core) Job() jobapi.Job {
	return myself.folder.Job()
}

// GetID returns the id of the data protected
// satisfies interface data.Identifiable
func (myself *Core) GetID() (string, error) {
	if valid.IsNull(myself) {
		return "--invalid--", fail.InvalidInstanceError()
	}

	val, xerr := myself.getID()
	if xerr != nil {
		return "--invalid--", xerr
	}

	return val, nil
}

func (myself *Core) getID() (string, fail.Error) {
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
func (myself *Core) GetName() string {
	if valid.IsNull(myself) {
		logrus.Error(fail.InvalidInstanceError().Error())
		return "--invalid--"
	}

	name, xerr := myself.getName()
	if xerr != nil {
		logrus.Error(xerr.Error())
		return "--invalid--"
	}

	return name
}

func (myself *Core) getName() (string, fail.Error) {
	if myself == nil {
		return "", fail.InvalidInstanceError()
	}

	name, ok := myself.name.Load().(string) // nolint
	if !ok {
		return "", fail.InvalidInstanceError()
	}

	return name, nil
}

func (myself *Core) IsTaken() bool {
	if valid.IsNull(myself) {
		return false
	}

	taken, ok := myself.taken.Load().(bool)
	if !ok {
		return false
	}

	return taken
}

// Kind returns the kind of object served
func (myself *Core) Kind() string {
	if valid.IsNull(myself) {
		logrus.Errorf(fail.InconsistentError("invalid call of Core.Kind() from null value").Error())
		return "-- invalid --"
	}

	return myself.kind
}

// Inspect protects the data for shared read
func (myself *Core) Inspect(inctx context.Context, callback AnyResourceCallback, opts ...options.Option) (_ fail.Error) {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}
	if myself.properties == nil {
		return fail.InvalidInstanceContentError("myself.properties", "cannot be nil")
	}

	o, xerr := options.New(opts...)
	if xerr != nil {
		return xerr
	}

	noReload, xerr := options.Value[bool](o, OptionWithoutReloadKey)
	if xerr != nil {
		return xerr
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
			var xerr fail.Error

			timings, xerr := myself.Service().Timings()
			if xerr != nil {
				return xerr
			}

			if !noReload {
				// Reload reloads data from Object Storage to be sure to have the last revision
				xerr = retry.WhileUnsuccessfulWithLimitedRetries(
					func() error {
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
							return fail.Wrap(xerr, "failed to reload metadata")
						}

						return nil
					},
					timings.SmallDelay(),
					timings.ContextTimeout(),
					6,
				)
				if xerr != nil {
					return fail.Wrap(xerr.Cause())
				}
			}

			myself.RLock()
			defer myself.RUnlock()

			xerr = retry.WhileUnsuccessfulWithLimitedRetries(
				func() error {
					select {
					case <-ctx.Done():
						return retry.StopRetryError(ctx.Err())
					default:
					}

					return myself.shielded.Inspect(func(p clonable.Clonable) fail.Error {
						return callback(p, myself.properties)
					})
				},
				timings.SmallDelay(),
				timings.ConnectionTimeout(),
				6,
			)
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
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}
}

// InspectProperty allows to inspect directly a single property
func (myself *Core) InspectProperty(ctx context.Context, property string, callback AnyPropertyCallback, opts ...options.Option) fail.Error {
	return myself.Inspect(ctx, func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(property, callback)
	}, opts...)
}

// Review allows to access data contained in the instance, without reloading from the Object Storage; it's intended
// to speed up operations that accept data is not up-to-date (for example, SSH configuration to access host should not
// change through time).
func (myself *Core) Review(inctx context.Context, callback AnyResourceCallback, opts ...options.Option) (_ fail.Error) {
	opts = append(opts, WithoutReload())
	return myself.Inspect(inctx, callback, opts...)
}

// ReviewProperty allows to review directly a single property
func (myself *Core) ReviewProperty(ctx context.Context, property string, callback AnyPropertyCallback, opts ...options.Option) fail.Error {
	return myself.Review(ctx, func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(property, callback)
	}, opts...)
}

// Alter protects the data for exclusive write
// Valid options are :
// - WithoutReload() = disable reloading from metadata storage
func (myself *Core) Alter(inctx context.Context, callback AnyResourceCallback, opts ...options.Option) (_ fail.Error) {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}
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

	o, xerr := options.New(opts...)
	if xerr != nil {
		return xerr
	}

	noReload, xerr := options.Value[bool](o, OptionWithoutReloadKey)
	if xerr != nil {
		return xerr
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
			var xerr fail.Error

			// Make sure myself.properties is populated
			if myself.properties == nil {
				myself.properties, xerr = serialize.NewJSONProperties("resources." + myself.kind)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}
			}

			// Reload reloads data from object storage to be sure to have the last revision
			if !noReload {
				xerr = myself.unsafeReload(ctx)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return fail.Wrap(xerr, "failed to unsafeReload metadata")
				}
			}

			xerr = myself.shielded.Alter(func(p clonable.Clonable) fail.Error {
				return callback(p, myself.properties)
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

// AlterProperty allows to alter directly a single property
func (myself *Core) AlterProperty(ctx context.Context, property string, callback AnyPropertyCallback, opts ...options.Option) fail.Error {
	return myself.Alter(ctx, func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(property, callback)
	}, opts...)
}

// Carry links metadata with real data
// If c is already carrying a shielded data, returns fail.NotAvailableError
//
// errors returned :
// - fail.ErrInvalidInstance
// - fail.ErrInvalidParameter
// - fail.ErrNotAvailable if the Core instance already carries a data
func (myself *Core) Carry(inctx context.Context, abstractResource clonable.Clonable) (_ fail.Error) {
	if myself == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(myself) && myself.IsTaken() {
		return fail.InvalidRequestError("cannot carry, already carries something")
	}
	if abstractResource == nil {
		return fail.InvalidParameterCannotBeNilError("abstractResource")
	}
	if myself.shielded == nil {
		return fail.InvalidInstanceContentError("myself.shielded", "cannot be nil")
	}
	if myself.loaded {
		return fail.NotAvailableError("already carrying a value")
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
			var xerr fail.Error

			var cerr error
			myself.shielded, cerr = shielded.NewShielded(abstractResource)
			if cerr != nil {
				return fail.Wrap(cerr)
			}

			myself.loaded = true

			xerr = myself.updateIdentity()
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

			// Registers the abstract in scope
			myjob, xerr := jobapi.FromContext(inctx)
			if xerr != nil {
				return xerr
			}

			tfResource, err := lang.Cast[terraformerapi.Resource](abstractResource)
			if err != nil {
				return fail.Wrap(err)
			}

			xerr = myjob.Scope().RegisterResource(tfResource)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrDuplicate:
					debug.IgnoreError(xerr)
					// continue
				default:
					return xerr
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

// updateIdentity updates instance cached identity
func (myself *Core) updateIdentity() fail.Error {
	if myself.loaded {
		issue := myself.shielded.Alter(func(p clonable.Clonable) fail.Error {
			ident, err := lang.Cast[data.Identifiable](p)
			if err != nil {
				return fail.InconsistentError("'data.Identifiable' expected, '%s' provided", reflect.TypeOf(p).String())
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

			if myself.kindSplittedStore {
				myself.id.Store(idd)
			} else {
				myself.id.Store(ident.GetName())
			}
			myself.name.Store(ident.GetName())
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
func (myself *Core) Read(inctx context.Context, ref string) (_ fail.Error) {
	if myself == nil {
		return fail.InvalidInstanceError()
	}
	if ref = strings.TrimSpace(ref); ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}
	if myself.loaded {
		return fail.NotAvailableError("metadata is already carrying a value")
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
			var xerr fail.Error

			if !myself.kindSplittedStore {
				xerr = myself.folder.Lookup(ctx, "", ref)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						return fail.NotFoundError("%s was NOT found in the bucket", myself.folder.AbsolutePath("", ref))
					default:
						return xerr
					}
				}

				xerr = myself.readByName(ctx, ref)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}

				goto commit
			}

			xerr = myself.folder.Lookup(ctx, byNameFolderName, ref)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// continue (otherwise, lookup by ID won't be tried
				default:
					return xerr
				}
			} else {
				xerr := myself.readByName(ctx, ref)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}

				goto commit
			}

			xerr = myself.folder.Lookup(ctx, byIDFolderName, ref)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// continue
				default:
					return xerr
				}
			} else {
				xerr := myself.readByID(ctx, ref)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}

				goto commit
			}

			return fail.NotFoundError("neither %s nor %s were found in the bucket", myself.folder.AbsolutePath(byNameFolderName, ref), myself.folder.AbsolutePath(byIDFolderName, ref))

		commit:
			myself.loaded = true
			myself.committed = true

			xerr = myself.updateIdentity()
			if xerr != nil {
				return xerr
			}

			return myself.Review(ctx, func(p clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
				myjob, innerXErr := jobapi.FromContext(ctx)
				if innerXErr != nil {
					return innerXErr
				}

				tfResource, err := lang.Cast[terraformerapi.Resource](p)
				if err != nil {
					return fail.Wrap(err)
				}

				innerXErr = myjob.Scope().RegisterResource(tfResource)
				if innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrDuplicate:
						debug.IgnoreError(innerXErr)
						//continue
					default:
						return innerXErr
					}
				}

				return nil
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

// ReadByID reads a metadata identified by ID from Object Storage
func (myself *Core) ReadByID(inctx context.Context, id string) (_ fail.Error) {
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
func (myself *Core) readByID(inctx context.Context, id string) fail.Error {
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

				werr := myself.folder.Read(
					ctx, path, id,
					func(buf []byte) fail.Error {
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
				timings.ContextTimeout(),
			)

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
func (myself *Core) readByName(inctx context.Context, name string) fail.Error {
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

			rerr := retry.WhileUnsuccessful(
				func() error {
					select {
					case <-ctx.Done():
						return retry.StopRetryError(ctx.Err())
					default:
					}
					werr := myself.folder.Read(
						ctx, path, name,
						func(buf []byte) fail.Error {
							select {
							case <-ctx.Done():
								return retry.StopRetryError(ctx.Err())
							default:
							}

							if innerXErr := myself.unsafeDeserialize(ctx, buf); innerXErr != nil {
								return fail.Wrap(innerXErr, "failed to unsafeDeserialize %s '%s'", myself.kind, name)
							}

							return nil
						},
					)
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
				timings.ContextTimeout(),
			)
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
func (myself *Core) write(inctx context.Context) fail.Error {
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
func (myself *Core) Reload(inctx context.Context) (ferr fail.Error) {
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
func (myself *Core) unsafeReload(inctx context.Context) fail.Error {
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

			if myself.loaded && !myself.committed {
				name, ok := myself.name.Load().(string)
				if ok {
					return fail.InconsistentError("cannot unsafeReload a not committed data with name %s", name)
				}
				return fail.InconsistentError("cannot unsafeReload a not committed data")
			}

			if myself.kindSplittedStore {
				id, ok := myself.id.Load().(string)
				if !ok {
					return fail.InconsistentError("field 'id' is not set with string")
				}

				xerr = retry.WhileUnsuccessful(
					func() error {
						select {
						case <-ctx.Done():
							return retry.StopRetryError(ctx.Err())
						default:
						}

						innerXErr := myself.readByID(ctx, id)
						if innerXErr != nil {
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
						return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", myself.kind, id)
					case *retry.ErrStopRetry:
						return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", myself.kind, id)
					default:
						return fail.Wrap(xerr, "failed to read %s by id %s", myself.kind, myself.id)
					}
				}
			} else {
				name, ok := myself.name.Load().(string)
				if !ok {
					return fail.InconsistentError("field 'name' is not set with string")
				}
				if name == "" {
					return fail.InconsistentError("field 'name' cannot be empty")
				}

				xerr = retry.WhileUnsuccessful(
					func() error {
						select {
						case <-ctx.Done():
							return retry.StopRetryError(ctx.Err())
						default:
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
						return fail.Wrap(fail.RootCause(xerr), "failed (timeout) to read %s '%s'", myself.kind, name)
					case *retry.ErrStopRetry:
						return fail.Wrap(fail.RootCause(xerr), "failed to read %s '%s'", myself.kind, name)
					default:
						return fail.Wrap(xerr, "failed to read %s '%s'", myself.kind, name)
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

// BrowseFolder walks through folder and executes a callback for each entry
func (myself *Core) BrowseFolder(inctx context.Context, callback func(buf []byte) fail.Error) (_ fail.Error) {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
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
func (myself *Core) Delete(inctx context.Context) (_ fail.Error) {
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

			var (
				idFound, nameFound bool
				errors             []error
			)

			// First remove entry from scope registered abstracts
			innerXErr := myself.shielded.Inspect(func(p clonable.Clonable) fail.Error {
				abstractResource, innerErr := lang.Cast[terraformerapi.Resource](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				// Registers the abstract in scope
				myjob, xerr := jobapi.FromContext(inctx)
				if xerr != nil {
					return xerr
				}

				return myjob.Scope().UnregisterResource(abstractResource)
			})
			if innerXErr != nil {
				return innerXErr
			}

			// Checks entries exist in Object Storage
			if myself.kindSplittedStore {
				id, ok := myself.id.Load().(string)
				if !ok {
					return fail.InconsistentError("field 'id' is not set with string")
				}

				var xerr fail.Error
				xerr = myself.folder.Lookup(ctx, byIDFolderName, id)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// If entry not found, consider operation not an error
						logrus.WithContext(ctx).Tracef("folder not found by id, maybe not an error")
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
						logrus.WithContext(ctx).Tracef("folder not found by name, maybe not an error")
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

				var xerr fail.Error
				xerr = myself.folder.Lookup(ctx, "", name)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// If entry not found, consider operation not an error
						logrus.WithContext(ctx).Tracef("folder not found by name, maybe not an error")
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

func (myself *Core) String(inctx context.Context) (string, fail.Error) {
	if valid.IsNil(myself) {
		return "", fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	myself.RLock()
	defer myself.RUnlock()

	type result struct {
		rTr  string
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		dump, gerr := func() (_ string, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			dumped, err := myself.shielded.String()
			if err != nil {
				return "", fail.ConvertError(err)
			}

			props, err := myself.properties.String()
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
func (myself *Core) unsafeSerialize(inctx context.Context) ([]byte, fail.Error) {
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
				shieldedJSONed []byte
				shieldedMapped = map[string]interface{}{}
				propsMapped    = map[string]string{}
			)

			var xerr fail.Error
			shieldedJSONed, xerr = myself.shielded.Serialize()
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			err := json.Unmarshal(shieldedJSONed, &shieldedMapped)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return nil, fail.NewErrorWithCause(err, "*Core.Serialize(): Unmarshalling JSONed shielded into map failed!")
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
func (myself *Core) Deserialize(inctx context.Context, buf []byte) fail.Error {
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

// unsafeDeserialize reads json code and instantiates a Core
// Note: must be called after locking the instance
func (myself *Core) unsafeDeserialize(inctx context.Context, buf []byte) fail.Error {
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
				myself.properties, xerr = serialize.NewJSONProperties("resources." + myself.kind)
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
				return fail.SyntaxErrorWithCause(err, nil, "failed to marshal Core to JSON")
			}

			xerr := myself.shielded.Deserialize(jsoned)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return fail.Wrap(xerr, "deserializing Core failed")
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
