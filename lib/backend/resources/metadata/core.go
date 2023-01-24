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

package metadata

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/result"
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
type Core[T clonable.Clonable] struct {
	lock              *sync.RWMutex
	id                atomic.Value
	name              atomic.Value
	taken             atomic.Value
	carried           *shielded.Shielded[T]
	properties        *serialize.JSONProperties
	kind              string
	folder            storage.Folder
	loaded            bool
	committed         bool
	kindSplittedStore bool // tells if data read/write is done directly from/to folder (when false) or from/to subfolders (when true)
}

// verify that Label satisfies resources.Label
var _ Metadata[*abstract.HostCore] = (*Core[*abstract.HostCore])(nil)

// NewCore creates an instance of Core
func NewCore[T clonable.Clonable](ctx context.Context, method string, kind string, path string, abstractRsc T) (_ *Core[T], ferr fail.Error) {
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

	protected, cerr := shielded.NewShielded[T](abstractRsc)
	if cerr != nil {
		return nil, fail.Wrap(cerr)
	}

	c := Core[T]{
		lock:       &sync.RWMutex{},
		kind:       kind,
		folder:     fld,
		properties: props,
		carried:    protected,
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
func (instance *Core[T]) IsNull() bool {
	return instance == nil || instance.kind == ""
}

// Clone ...
func (instance *Core[T]) Clone() (clonable.Clonable, error) {
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}

	newCore := &Core[T]{lock: &sync.RWMutex{}}
	return newCore, newCore.Replace(instance)
}

// Replace ...
func (instance *Core[T]) Replace(in clonable.Clonable) error {
	if instance == nil {
		return fail.InvalidInstanceError()
	}

	src, ok := in.(*Core[T])
	if !ok {
		return fail.InvalidParameterError("invalid 'in' type")
	}

	properties, err := clonable.CastedClone[*serialize.JSONProperties](src.properties)
	if err != nil {
		return err
	}

	carried, err := clonable.CastedClone[*shielded.Shielded[T]](src.carried)
	if err != nil {
		return err
	}

	instance.id = src.id
	instance.name = src.name
	instance.kind = src.kind
	instance.folder = src.folder // Not cloned, it's voluntary
	instance.committed = src.committed
	instance.kindSplittedStore = src.kindSplittedStore
	instance.loaded = src.loaded
	instance.taken = src.taken
	instance.properties = properties
	instance.carried = carried

	return nil
}

// Service returns the iaasapi.Service used to create/load the persistent object
func (instance *Core[T]) Service() iaasapi.Service {
	return instance.folder.Service()
}

func (instance *Core[T]) Job() jobapi.Job {
	return instance.folder.Job()
}

func (instance *Core[T]) core() (*Core[T], fail.Error) {
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}

	return instance, nil
}

// GetID returns the id of the data protected
// satisfies interface data.Identifiable
func (instance *Core[T]) GetID() (string, error) {
	if valid.IsNull(instance) {
		return "--invalid--", fail.InvalidInstanceError()
	}

	val, xerr := instance.getID()
	if xerr != nil {
		return "--invalid--", xerr
	}

	return val, nil
}

func (instance *Core[T]) getID() (string, fail.Error) {
	if instance == nil {
		return "", fail.InvalidInstanceError()
	}

	id, ok := instance.id.Load().(string) // nolint
	if !ok {
		return "", fail.InvalidInstanceError()
	}

	return id, nil
}

// GetName returns the name of the data protected
// satisfies interface data.Identifiable
func (instance *Core[T]) GetName() string {
	if valid.IsNull(instance) {
		logrus.Error(fail.InvalidInstanceError().Error())
		return "--invalid--"
	}

	name, xerr := instance.getName()
	if xerr != nil {
		logrus.Error(xerr.Error())
		return "--invalid--"
	}

	return name
}

func (instance *Core[T]) getName() (string, fail.Error) {
	if instance == nil {
		return "", fail.InvalidInstanceError()
	}

	name, ok := instance.name.Load().(string) // nolint
	if !ok {
		return "", fail.InvalidInstanceError()
	}

	return name, nil
}

func (instance *Core[T]) IsTaken() bool {
	if valid.IsNull(instance) {
		return false
	}

	taken, ok := instance.taken.Load().(bool)
	if !ok {
		return false
	}

	return taken
}

// Kind returns the kind of object served
func (instance *Core[T]) Kind() string {
	if valid.IsNull(instance) {
		logrus.Errorf(fail.InconsistentError("invalid call of Core.Kind() from null value").Error())
		return "-- invalid --"
	}

	return instance.kind
}

// // Inspect protects the data for shared read
// func (instance *Core[T]) Inspect(inctx context.Context, callback ResourceCallback[T], opts ...options.Option) fail.Error {
// 	if valid.IsNil(instance) {
// 		return fail.InvalidInstanceError()
// 	}
// 	if callback == nil {
// 		return fail.InvalidParameterCannotBeNilError("callback")
// 	}
// 	if instance.properties == nil {
// 		return fail.InvalidInstanceContentError("instance.properties", "cannot be nil")
// 	}
//
// 	trx, xerr := NewTransaction[T, *Core[T]](inctx, instance)
// 	if xerr != nil {
// 		return xerr
// 	}
// 	defer trx.SilentTerminate(inctx)
//
// 	return trx.inspect(inctx, callback, opts...)
// }
//
// // InspectCarried protects the data for shared read
// func (instance *Core[T]) InspectCarried(inctx context.Context, callback CarriedCallback[T], opts ...options.Option) fail.Error {
// 	if valid.IsNil(instance) {
// 		return fail.InvalidInstanceError()
// 	}
// 	if callback == nil {
// 		return fail.InvalidParameterCannotBeNilError("callback")
// 	}
//
// 	trx, xerr := NewTransaction[T, *Core[T]](inctx, instance)
// 	if xerr != nil {
// 		return xerr
// 	}
// 	defer trx.SilentTerminate(inctx)
//
// 	return trx.inspectCarried(inctx, func(carried T) fail.Error {
// 		return callback(carried)
// 	}, opts...)
// }
//
// // InspectProperty allows to inspect directly a single property
// func (instance *Core[T]) InspectProperty(ctx context.Context, property string, callback AnyPropertyCallback, opts ...options.Option) fail.Error {
// 	return instance.Inspect(ctx, func(_ T, props *serialize.JSONProperties) fail.Error {
// 		return props.Inspect(property, callback)
// 	}, opts...)
// }
//
// // Review allows to access data contained in the instance, without reloading from the Object Storage; it's intended
// // to speed up operations that accept data is not up-to-date (for example, SSH configuration to access host should not
// // change through time).
// func (instance *Core[T]) Review(ctx context.Context, callback ResourceCallback[T], opts ...options.Option) fail.Error {
// 	opts = append(opts, WithoutReload())
// 	return instance.Inspect(ctx, callback, opts...)
// }
//
// // ReviewCarried allows to access data contained in the instance, without reloading from the Object Storage; it's intended
// // to speed up operations that accept data is not up-to-date (for example, SSH configuration to access host should not
// // change through time).
// func (instance *Core[T]) ReviewCarried(ctx context.Context, callback CarriedCallback[T], opts ...options.Option) fail.Error {
// 	opts = append(opts, WithoutReload())
// 	return instance.InspectCarried(ctx, callback, opts...)
// }
//
// // ReviewProperty allows to review directly a single property
// func (instance *Core[T]) ReviewProperty(ctx context.Context, property string, callback AnyPropertyCallback, opts ...options.Option) fail.Error {
// 	return instance.Review(ctx, func(_ T, props *serialize.JSONProperties) fail.Error {
// 		return props.Inspect(property, callback)
// 	}, opts...)
// }
//
// // Alter protects the data for exclusive write
// // Valid options are :
// // - WithoutReload() = disable reloading from metadata storage
// func (instance *Core[T]) Alter(inctx context.Context, callback ResourceCallback[T], opts ...options.Option) (ferr fail.Error) {
// 	if valid.IsNil(instance) {
// 		return fail.InvalidInstanceError()
// 	}
// 	if callback == nil {
// 		return fail.InvalidParameterCannotBeNilError("callback")
// 	}
// 	if instance.carried == nil {
// 		return fail.InvalidInstanceContentError("instance.carried", "cannot be nil")
// 	}
//
// 	name, err := instance.getName()
// 	if err != nil {
// 		return fail.InconsistentError("uninitialized metadata should not be altered")
// 	}
// 	if name == "" {
// 		return fail.InconsistentError("uninitialized metadata should not be altered")
// 	}
//
// 	id, err := instance.getID()
// 	if err != nil {
// 		return fail.InconsistentError("uninitialized metadata should not be altered")
// 	}
// 	if id == "" {
// 		return fail.InconsistentError("uninitialized metadata should not be altered")
// 	}
//
// 	trx, xerr := NewTransaction[T, *Core[T]](inctx, instance)
// 	if xerr != nil {
// 		return xerr
// 	}
// 	defer trx.TerminateBasedOnError(inctx, &ferr)
//
// 	xerr = trx.alter(inctx, callback, opts...)
// 	if xerr != nil {
// 		switch xerr.(type) {
// 		case *fail.ErrAlteredNothing:
// 			derr := trx.Rollback(inctx)
// 			if derr != nil {
// 				return derr
// 			}
//
// 			return nil
// 		default:
// 			derr := trx.Rollback(inctx)
// 			if derr != nil {
// 				_ = xerr.AddConsequence(derr)
// 			}
// 			return xerr
// 		}
// 	}
//
// 	return trx.Commit(inctx)
// }
//
// // AlterCarried allows to alter directly the carried value
// func (instance *Core[T]) AlterCarried(ctx context.Context, callback CarriedCallback[T], opts ...options.Option) fail.Error {
// 	return instance.Alter(ctx, func(carried T, _ *serialize.JSONProperties) fail.Error {
// 		return callback(carried)
// 	}, opts...)
// }
//
// // AlterProperty allows to alter directly a single property
// func (instance *Core[T]) AlterProperty(ctx context.Context, property string, callback AnyPropertyCallback, opts ...options.Option) fail.Error {
// 	return instance.Alter(ctx, func(_ T, props *serialize.JSONProperties) fail.Error {
// 		return props.Alter(property, callback)
// 	}, opts...)
// }

// Carry links metadata with real data
// If c is already carrying a carried data, returns fail.NotAvailableError
//
// errors returned :
// - fail.ErrInvalidInstance
// - fail.ErrInvalidParameter
// - fail.ErrNotAvailable if the Core instance already carries a data
func (instance *Core[T]) Carry(inctx context.Context, abstractResource T) (_ fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance) && instance.IsTaken() {
		return fail.InvalidRequestError("cannot carry, already carries something")
	}
	if any(abstractResource) == nil {
		return fail.InvalidParameterCannotBeNilError("abstractResource")
	}
	if instance.carried == nil {
		return fail.InvalidInstanceContentError("instance.carried", "cannot be nil")
	}
	if instance.loaded {
		return fail.NotAvailableError("already carrying a value")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	chRes := make(chan result.Holder[struct{}])
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			var xerr fail.Error

			var cerr error
			instance.carried, cerr = shielded.NewShielded(abstractResource)
			if cerr != nil {
				return fail.Wrap(cerr)
			}

			instance.loaded = true

			xerr = instance.updateIdentity()
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			instance.committed = false

			xerr = instance.write(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			// Registers the abstract in scope
			myjob, xerr := jobapi.FromContext(inctx)
			if xerr != nil {
				return xerr
			}

			tfResource, ok := any(abstractResource).(terraformerapi.Resource)
			if !ok {
				return fail.InconsistentError("failed to cast '%s' to 'terraformerapi.Resource'", reflect.TypeOf(abstractResource).String())
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
		res, _ := result.NewHolder[struct{}](result.MarkAsFailed[struct{}](gerr))
		chRes <- res
	}()
	select {
	case res := <-chRes:
		return fail.Wrap(res.Error())
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// updateIdentity updates instance cached identity
func (instance *Core[T]) updateIdentity() fail.Error {
	if instance.loaded {
		issue := instance.carried.Alter(func(p T) fail.Error {
			ident, err := lang.Cast[data.Identifiable](p)
			if err != nil {
				return fail.InconsistentError("'data.Identifiable' expected, '%s' provided", reflect.TypeOf(p).String())
			}

			idd, err := ident.GetID()
			if err != nil {
				return fail.Wrap(err)
			}

			if loaded, ok := instance.id.Load().(string); ok {
				if idd == loaded {
					return nil
				}
			}

			if instance.kindSplittedStore {
				instance.id.Store(idd)
			} else {
				instance.id.Store(ident.GetName())
			}
			instance.name.Store(ident.GetName())
			instance.taken.Store(true)

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
func (instance *Core[T]) Read(inctx context.Context, ref string) (_ fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if ref = strings.TrimSpace(ref); ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}
	if instance.loaded {
		return fail.NotAvailableError("metadata is already carrying a value")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	chRes := make(chan result.Holder[struct{}])
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			var xerr fail.Error

			if !instance.kindSplittedStore {
				xerr = instance.folder.Lookup(ctx, "", ref)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						return fail.NotFoundError("%s was NOT found in the bucket", instance.folder.AbsolutePath("", ref))
					default:
						return xerr
					}
				}

				xerr = instance.readByName(ctx, ref)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}

				goto commit
			}

			xerr = instance.folder.Lookup(ctx, byNameFolderName, ref)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// continue (otherwise, lookup by ID won't be tried
				default:
					return xerr
				}
			} else {
				xerr := instance.readByName(ctx, ref)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}

				goto commit
			}

			xerr = instance.folder.Lookup(ctx, byIDFolderName, ref)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// continue
				default:
					return xerr
				}
			} else {
				xerr := instance.readByID(ctx, ref)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}

				goto commit
			}

			return fail.NotFoundError("neither %s nor %s were found in the bucket", instance.folder.AbsolutePath(byNameFolderName, ref), instance.folder.AbsolutePath(byIDFolderName, ref))

		commit:
			instance.loaded = true
			instance.committed = true

			xerr = instance.updateIdentity()
			if xerr != nil {
				return xerr
			}

			trx, xerr := NewTransaction[T, *Core[T]](ctx, instance)
			if xerr != nil {
				return xerr
			}
			defer trx.TerminateBasedOnError(ctx, &ferr)

			return trx.reviewCarried(ctx, func(p T) fail.Error {
				myjob, innerXErr := jobapi.FromContext(ctx)
				if innerXErr != nil {
					return innerXErr
				}

				tfResource, innerErr := lang.Cast[terraformerapi.Resource](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				_, innerXErr = myjob.Scope().RegisterResourceIfNeeded(tfResource)
				if innerXErr != nil {
					return innerXErr
				}

				return nil
			})
		}()
		res, _ := result.NewHolder[struct{}](result.MarkAsFailed[struct{}](gerr))
		chRes <- res
	}()

	select {
	case res := <-chRes:
		return fail.Wrap(res.Error())
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// ReadByID reads a metadata identified by ID from Object Storage
func (instance *Core[T]) ReadByID(inctx context.Context, id string) (_ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	chRes := make(chan result.Holder[struct{}])
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if instance == nil {
				return fail.InvalidInstanceError()
			}
			if id = strings.TrimSpace(id); id == "" {
				return fail.InvalidParameterError("id", "cannot be empty string")
			}
			if instance.loaded {
				return fail.NotAvailableError("metadata is already carrying a value")
			}

			timings, xerr := instance.Service().Timings()
			if xerr != nil {
				return xerr
			}

			if instance.kindSplittedStore {
				xerr = retry.WhileUnsuccessful(
					func() error {
						select {
						case <-ctx.Done():
							return retry.StopRetryError(ctx.Err())
						default:
						}

						if innerXErr := instance.readByID(ctx, id); innerXErr != nil {
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

						if innerXErr := instance.readByName(ctx, id); innerXErr != nil {
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
					return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", instance.kind, id)
				case *retry.ErrStopRetry:
					return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", instance.kind, id)
				default:
					return fail.Wrap(xerr, "failed to read %s by id %s", instance.kind, id)
				}
			}

			instance.loaded = true
			instance.committed = true

			return instance.updateIdentity()
		}()
		res, _ := result.NewHolder[struct{}](result.MarkAsFailed[struct{}](gerr))
		chRes <- res
	}()
	select {
	case res := <-chRes:
		return fail.Wrap(res.Error())
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// readByID reads a metadata identified by ID from Object Storage
func (instance *Core[T]) readByID(inctx context.Context, id string) fail.Error {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	chRes := make(chan result.Holder[struct{}])
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			var path string
			if instance.kindSplittedStore {
				path = byIDFolderName
			}

			timings, xerr := instance.Service().Timings()
			if xerr != nil {
				return xerr
			}

			rerr := retry.WhileUnsuccessful(func() error {
				select {
				case <-ctx.Done():
					return retry.StopRetryError(ctx.Err())
				default:
				}

				werr := instance.folder.Read(
					ctx, path, id,
					func(buf []byte) fail.Error {
						select {
						case <-ctx.Done():
							return retry.StopRetryError(ctx.Err())
						default:
						}

						if innerXErr := instance.unsafeDeserialize(ctx, buf); innerXErr != nil {
							switch innerXErr.(type) {
							case *fail.ErrNotAvailable:
								return fail.Wrap(innerXErr, "failed to unsafeDeserialize %s resource", instance.kind)
							case *fail.ErrSyntax:
								return fail.Wrap(innerXErr, "failed to unsafeDeserialize %s resource", instance.kind)
							case *fail.ErrInconsistent, *fail.ErrInvalidParameter, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent:
								return retry.StopRetryError(innerXErr)
							default:
								return fail.Wrap(innerXErr, "failed to unsafeDeserialize %s resource", instance.kind)
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
				return fail.Wrap(rerr.Cause())
			}

			return nil
		}()
		res, _ := result.NewHolder[struct{}](result.MarkAsFailed[struct{}](gerr))
		chRes <- res
	}()
	select {
	case res := <-chRes:
		return fail.Wrap(res.Error())
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// readByName reads a metadata identified by name
func (instance *Core[T]) readByName(inctx context.Context, name string) fail.Error {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	chRes := make(chan result.Holder[struct{}])
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			var path string
			if instance.kindSplittedStore {
				path = byNameFolderName
			}

			timings, xerr := instance.Service().Timings()
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
					werr := instance.folder.Read(
						ctx, path, name,
						func(buf []byte) fail.Error {
							select {
							case <-ctx.Done():
								return retry.StopRetryError(ctx.Err())
							default:
							}

							if innerXErr := instance.unsafeDeserialize(ctx, buf); innerXErr != nil {
								return fail.Wrap(innerXErr, "failed to unsafeDeserialize %s '%s'", instance.kind, name)
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
				return fail.Wrap(rerr.Cause())
			}

			return nil
		}()
		res, _ := result.NewHolder[struct{}](result.MarkAsFailed[struct{}](gerr))
		chRes <- res
	}()
	select {
	case res := <-chRes:
		return fail.Wrap(res.Error())
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// write updates the metadata corresponding to the host in the Object Storage
func (instance *Core[T]) write(inctx context.Context) fail.Error {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	chRes := make(chan result.Holder[struct{}])
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if !instance.committed {
				jsoned, xerr := instance.unsafeSerialize(ctx)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}

				name, ok := instance.name.Load().(string)
				if !ok {
					return fail.InconsistentError("field 'name' is not set with string")
				}

				if instance.kindSplittedStore {
					xerr = instance.folder.Write(ctx, byNameFolderName, name, jsoned)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						return xerr
					}

					id, ok := instance.id.Load().(string)
					if !ok {
						return fail.InconsistentError("field 'id' is not set with string")
					}

					xerr = instance.folder.Write(ctx, byIDFolderName, id, jsoned)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						return xerr
					}
				} else {
					xerr = instance.folder.Write(ctx, "", name, jsoned)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						return xerr
					}
				}

				instance.loaded = true
				instance.committed = true
			}
			return nil
		}()
		res, _ := result.NewHolder[struct{}](result.MarkAsFailed[struct{}](gerr))
		chRes <- res
	}()
	select {
	case res := <-chRes:
		return fail.Wrap(res.Error())
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// Reload reloads the content from the Object Storage
func (instance *Core[T]) Reload(inctx context.Context) (ferr fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	chRes := make(chan result.Holder[struct{}])
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			return instance.reload(ctx)
		}()
		res, _ := result.NewHolder[struct{}](result.MarkAsFailed[struct{}](gerr))
		chRes <- res
	}()
	select {
	case res := <-chRes:
		return fail.Wrap(res.Error())
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// reload loads the content from the Object Storage
// Note: must be called after locking the instance
func (instance *Core[T]) reload(inctx context.Context) fail.Error {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	chRes := make(chan result.Holder[struct{}])
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			timings, xerr := instance.Service().Timings()
			if xerr != nil {
				return xerr
			}

			if instance.loaded && !instance.committed {
				name, ok := instance.name.Load().(string)
				if ok {
					return fail.InconsistentError("cannot reload a not committed data with name %s", name)
				}
				return fail.InconsistentError("cannot reload a not committed data")
			}

			if instance.kindSplittedStore {
				id, ok := instance.id.Load().(string)
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

						innerXErr := instance.readByID(ctx, id)
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
						return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", instance.kind, id)
					case *retry.ErrStopRetry:
						return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", instance.kind, id)
					default:
						return fail.Wrap(xerr, "failed to read %s by id %s", instance.kind, instance.id)
					}
				}
			} else {
				name, ok := instance.name.Load().(string)
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

						if innerXErr := instance.readByName(ctx, name); innerXErr != nil {
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
						return fail.Wrap(fail.RootCause(xerr), "failed (timeout) to read %s '%s'", instance.kind, name)
					case *retry.ErrStopRetry:
						return fail.Wrap(fail.RootCause(xerr), "failed to read %s '%s'", instance.kind, name)
					default:
						return fail.Wrap(xerr, "failed to read %s '%s'", instance.kind, name)
					}
				}
			}

			instance.loaded = true
			instance.committed = true

			return nil
		}()
		res, _ := result.NewHolder[struct{}](result.MarkAsFailed[struct{}](gerr))
		chRes <- res
	}()
	select {
	case res := <-chRes:
		return fail.Wrap(res.Error())
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// BrowseFolder walks through folder and executes a callback for each entry
func (instance *Core[T]) BrowseFolder(inctx context.Context, callback func(buf []byte) fail.Error) (_ fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	chRes := make(chan result.Holder[struct{}])
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if instance.kindSplittedStore {
				return instance.folder.Browse(ctx, byIDFolderName, func(buf []byte) fail.Error {
					return callback(buf)
				})
			}

			return instance.folder.Browse(ctx, "", func(buf []byte) fail.Error {
				return callback(buf)
			})
		}()
		res, _ := result.NewHolder[struct{}](result.MarkAsFailed[struct{}](gerr))
		chRes <- res
	}()
	select {
	case res := <-chRes:
		return fail.Wrap(res.Error())
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// LookupByName tells if an entry exists by name in the folder
func (instance *Core[T]) LookupByName(inctx context.Context, name string) (_ fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}
	if name == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	chRes := make(chan result.Holder[struct{}])
	go func() {
		defer close(chRes)

		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			return instance.folder.Lookup(ctx, byNameFolderName, name)
		}()
		res, _ := result.NewHolder[struct{}](result.MarkAsFailed[struct{}](gerr))
		chRes <- res
	}()
	select {
	case res := <-chRes:
		return fail.Wrap(res.Error())
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// Delete deletes the metadata
func (instance *Core[T]) Delete(inctx context.Context) (_ fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	chRes := make(chan result.Holder[struct{}])
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			var (
				idFound, nameFound bool
				errors             []error
			)

			// First remove entry from scope registered abstracts
			xerr := instance.carried.Inspect(func(p T) fail.Error {
				abstractResource, ok := any(p).(terraformerapi.Resource)
				if !ok {
					return fail.InconsistentError("failed to cast '%s' to 'terraformerapi.Resource'", reflect.TypeOf(p).String())
				}

				// Registers the abstract in scope
				myjob, innerXErr := jobapi.FromContext(inctx)
				if innerXErr != nil {
					return innerXErr
				}

				return myjob.Scope().UnregisterResource(abstractResource)
			})
			if xerr != nil {
				return xerr
			}

			// Checks entries exist in Object Storage
			if instance.kindSplittedStore {
				id, ok := instance.id.Load().(string)
				if !ok {
					return fail.InconsistentError("field 'id' is not set with string")
				}

				xerr := instance.folder.Lookup(ctx, byIDFolderName, id)
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

				name, ok := instance.name.Load().(string)
				if !ok {
					return fail.InconsistentError("field 'name' is not set with string")
				}
				if name == "" {
					return fail.InconsistentError("field 'name' cannot be empty")
				}

				xerr = instance.folder.Lookup(ctx, byNameFolderName, name)
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
					xerr = instance.folder.Delete(ctx, byIDFolderName, id)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						errors = append(errors, xerr)
					}
				}
				if nameFound {
					xerr = instance.folder.Delete(ctx, byNameFolderName, name)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						errors = append(errors, xerr)
					}
				}
			} else {
				name, ok := instance.name.Load().(string)
				if !ok {
					return fail.InconsistentError("field 'name' is not set with string")
				}

				var xerr fail.Error
				xerr = instance.folder.Lookup(ctx, "", name)
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
					xerr = instance.folder.Delete(ctx, "", name)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						errors = append(errors, xerr)
					}
				}
			}

			if len(errors) > 0 {
				return fail.NewErrorList(errors)
			}

			instance.loaded = false
			instance.committed = false

			return nil
		}()
		res, _ := result.NewHolder[struct{}](result.MarkAsFailed[struct{}](gerr))
		chRes <- res
	}()
	select {
	case res := <-chRes:
		return fail.Wrap(res.Error())
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

func (instance *Core[T]) String() (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	dumped, err := instance.carried.String()
	if err != nil {
		return "", fail.Wrap(err)
	}

	props, err := instance.properties.String()
	if err != nil {
		return "", fail.Wrap(err)
	}

	return dumped + " " + props, nil
}

// unsafeSerialize serializes instance into bytes (output json code)
// Note: must be called after locking the instance
func (instance *Core[T]) unsafeSerialize(inctx context.Context) ([]byte, fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	chRes := make(chan result.Holder[[]byte])
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
			shieldedJSONed, xerr = instance.carried.Serialize()
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			err := json.Unmarshal(shieldedJSONed, &shieldedMapped)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return nil, fail.NewErrorWithCause(err, "*Core.Serialize(): Unmarshalling JSONed carried into map failed!")
			}

			if instance.properties.Count() > 0 {
				propsJSONed, xerr := instance.properties.Serialize()
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return nil, xerr
				}

				if len(propsJSONed) > 0 && string(propsJSONed) != `"{}"` {
					if jserr := json.Unmarshal(propsJSONed, &propsMapped); jserr != nil {
						return nil, fail.Wrap(jserr)
					}
				}
			}

			shieldedMapped["properties"] = propsMapped

			r, err := json.Marshal(shieldedMapped)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return nil, fail.Wrap(err)
			}

			return r, nil
		}()
		res, _ := result.NewHolder[[]byte](result.WithPayload[[]byte](gtr), result.MarkAsFailed[[]byte](gerr))
		chRes <- res
	}()
	select {
	case res := <-chRes:
		return res.Payload(), fail.Wrap(res.Error())
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	}
}

// Deserialize reads json code and reinstantiates
func (instance *Core[T]) Deserialize(inctx context.Context, buf []byte) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	chRes := make(chan result.Holder[struct{}])
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			return instance.unsafeDeserialize(ctx, buf)
		}()
		res, _ := result.NewHolder[struct{}](result.MarkAsFailed[struct{}](gerr))
		chRes <- res
	}()
	select {
	case res := <-chRes:
		return fail.Wrap(res.Error())
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// unsafeDeserialize reads json code and instantiates a Core
// Note: must be called after locking the instance
func (instance *Core[T]) unsafeDeserialize(inctx context.Context, buf []byte) fail.Error {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	chRes := make(chan result.Holder[struct{}])
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if instance.properties == nil {
				var xerr fail.Error
				instance.properties, xerr = serialize.NewJSONProperties("resources." + instance.kind)
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

			xerr := instance.carried.Deserialize(jsoned)
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

				xerr = instance.properties.Deserialize(jsoned)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return fail.Wrap(xerr, "failed to unsafeDeserialize properties")
				}
			}
			return nil
		}()
		res, _ := result.NewHolder[struct{}](result.MarkAsFailed[struct{}](gerr))
		chRes <- res
	}()
	select {
	case res := <-chRes:
		return fail.Wrap(res.Error())
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}
