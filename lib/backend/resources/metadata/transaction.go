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
	"sync"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	iaasapi "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/result"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"
)

type transaction[T Metadata] struct {
	mu           *sync.Mutex // used for concurrency-safety
	original     T           // contains the original instance on which the transaction applies
	coreOriginal *Core       // is used to propagate some methods of 'original' to transaction
	changes      T           // contains the instance with changes
	coreChanges  *Core
	dirty        bool // tells there have been changes
	closed       bool // tells the transaction is closed
}

// NewTransaction creates a transaction
func NewTransaction[T Metadata](ctx context.Context, original T) (*transaction[T], fail.Error) {
	if valid.IsNil(original) {
		return nil, fail.InvalidParameterCannotBeNilError("original")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	// -- make sure the parameter is correctly composed
	coreOriginal, xerr := original.core()
	if xerr != nil {
		return nil, xerr
	}
	if coreOriginal.properties == nil {
		return nil, fail.InvalidParameterCannotBeNilError("original.properties")
	}

	// -- RLock original instance to prevent other concurrent changes (but still allowing inspection)
	coreOriginal.lock.RLock()

	// -- Reload reloads data from object storage to be sure to have the last revision

	xerr = coreOriginal.reload(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to reload metadata")
	}

	// -- creates transaction instance
	trx := &transaction[T]{
		mu:           &sync.Mutex{},
		original:     original,
		coreOriginal: coreOriginal,
	}
	var err error
	trx.changes, err = clonable.CastedClone[T](original)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	trx.coreChanges, _ = trx.changes.core()
	return trx, nil
}

// IsNull returns true if the Core instance represents the null value for Core
func (trx *transaction[T]) IsNull() bool {
	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx == nil || valid.IsNull(trx.original) || valid.IsNull(trx.changes)
}

// Commit saves the changes
func (trx *transaction[T]) Commit(ctx context.Context) fail.Error {
	if valid.IsNil(trx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	if trx.closed {
		return fail.NotAvailableError("transaction is closed")
	}

	if !trx.dirty {
		return nil
	}

	trx.coreOriginal.lock.RUnlock()
	trx.coreOriginal.lock.Lock()
	err := trx.original.Replace(trx.changes)
	if err != nil {
		trx.coreOriginal.lock.Unlock()
		trx.coreOriginal.lock.RLock()
		return fail.Wrap(err)
	}

	trx.coreOriginal.committed = false
	xerr := trx.coreOriginal.write(ctx)
	trx.coreOriginal.lock.Unlock()
	trx.coreOriginal.lock.RLock()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	trx.dirty = false
	return nil
}

// Rollback gives up on changes
func (trx *transaction[T]) Rollback(ctx context.Context) fail.Error {
	if valid.IsNil(trx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	if trx.closed {
		return fail.NotAvailableError("transaction is closed")
	}

	trx.dirty = false
	return nil
}

// Close makes the transaction not usable anymore and free storage lock
func (trx *transaction[T]) Close(ctx context.Context) fail.Error {
	if valid.IsNil(trx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	trx.coreOriginal.lock.RUnlock()
	if trx.closed {
		return nil
	}

	if trx.dirty {
		logrus.WithContext(ctx).Warning("closing a metadata.Transaction that is dirty (ie neither Commit() nor Rollback() has been called)")
	}

	// FIXME: unlocking storage

	trx.closed = true
	return nil
}

// SilentClose is identical to Close() except it does not return any error, only log it
func (trx *transaction[T]) SilentClose(ctx context.Context) {
	xerr := trx.Close(ctx)
	if xerr != nil {
		logrus.WithContext(ctx).Error(xerr.Error())
	}
}

// Service returns the iaasapi.Service used to create/load the persistent object
func (trx *transaction[T]) Service() iaasapi.Service {
	if trx == nil {
		return nil
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.coreOriginal.Service()
}

func (trx *transaction[T]) Job() jobapi.Job {
	if trx == nil {
		return nil
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.coreOriginal.Job()
}

// GetID returns the id of the data protected
// satisfies interface data.Identifiable
func (trx *transaction[T]) GetID() (string, error) {
	if valid.IsNull(trx) {
		return "--invalid--", fail.InvalidInstanceError()
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.coreOriginal.GetID()
}

// GetName returns the name of the data protected
// satisfies interface data.Identifiable
func (trx *transaction[T]) GetName() string {
	if valid.IsNull(trx) {
		logrus.Error(fail.InvalidInstanceError().Error())
		return "--invalid--"
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.coreOriginal.GetName()
}

func (trx *transaction[T]) IsTaken() bool {
	if valid.IsNull(trx) {
		return false
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.coreOriginal.IsTaken()
}

// Kind returns the kind of object served
func (trx *transaction[T]) Kind() string {
	if valid.IsNull(trx) {
		logrus.Errorf(fail.InconsistentError("invalid call of Kind() from null value").Error())
		return "-- invalid --"
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.coreOriginal.Kind()
}

// Inspect protects the data for shared read
func (trx *transaction[T]) Inspect(inctx context.Context, callback AnyResourceCallback, opts ...options.Option) (_ fail.Error) {
	if valid.IsNil(trx) {
		return fail.InvalidInstanceError()
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	if trx.closed {
		return fail.NotAvailableError("transaction is closed")
	}

	return trx.inspect(inctx, callback, opts...)
}

// inspect ...
func (trx *transaction[T]) inspect(inctx context.Context, callback AnyResourceCallback, _ ...options.Option) (_ fail.Error) {
	if trx.coreChanges.properties == nil {
		return fail.InvalidInstanceContentError("trx.coreChanges.properties", "cannot be nil")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	// type result struct {
	// 	rErr fail.Error
	// }
	chRes := make(chan result.Holder[struct{}])
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			var xerr fail.Error

			timings, xerr := trx.coreChanges.Service().Timings()
			if xerr != nil {
				return xerr
			}

			trx.coreChanges.lock.RLock()
			defer trx.coreChanges.lock.RUnlock()

			xerr = retry.WhileUnsuccessfulWithLimitedRetries(
				func() error {
					select {
					case <-ctx.Done():
						return retry.StopRetryError(ctx.Err())
					default:
					}

					return trx.coreChanges.shielded.Inspect(func(p clonable.Clonable) fail.Error {
						return callback(p, trx.coreChanges.properties)
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
		res, _ := result.NewHolder[struct{}](result.MarkAsFailed[struct{}](gerr))
		chRes <- res
	}()
	select {
	case res := <-chRes:
		return fail.Wrap(res.Error())
	case <-ctx.Done():
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}
}

// InspectCarried ...
func (trx *transaction[T]) InspectCarried(ctx context.Context, callback AnyCarriedCallback, opts ...options.Option) (_ fail.Error) {
	return trx.Inspect(ctx, func(in clonable.Clonable, _ *serialize.JSONProperties) fail.Error { return callback(in) }, opts...)
}

// InspectProperty allows to inspect directly a single property
func (trx *transaction[T]) InspectProperty(ctx context.Context, property string, callback AnyPropertyCallback, opts ...options.Option) fail.Error {
	return trx.Inspect(ctx, func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(property, callback)
	}, opts...)
}

// Review allows to access data contained in the instance, without reloading from the Object Storage; it's intended
// to speed up operations that accept data is not up-to-date (for example, SSH configuration to access host should not
// change through time).
func (trx *transaction[T]) Review(inctx context.Context, callback AnyResourceCallback, opts ...options.Option) (_ fail.Error) {
	if valid.IsNil(trx) {
		return fail.InvalidInstanceError()
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	if trx.closed {
		return fail.NotAvailableError("transaction is closed")
	}

	opts = append(opts, WithoutReload())
	return trx.inspect(inctx, callback, opts...)
}

// ReviewCarried ...
func (trx *transaction[T]) ReviewCarried(ctx context.Context, callback AnyCarriedCallback, opts ...options.Option) (_ fail.Error) {
	return trx.Review(ctx, func(in clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
		return callback(in)
	}, opts...)
}

// ReviewProperty allows to review directly a single property
func (trx *transaction[T]) ReviewProperty(ctx context.Context, property string, callback AnyPropertyCallback, opts ...options.Option) fail.Error {
	return trx.Review(ctx, func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(property, callback)
	}, opts...)
}

// Alter protects the data for exclusive write
// Valid options are :
// - WithoutReload() = disable reloading from metadata storage
func (trx *transaction[T]) Alter(inctx context.Context, callback AnyResourceCallback, opts ...options.Option) (_ fail.Error) {
	if valid.IsNil(trx) {
		return fail.InvalidInstanceError()
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	if trx.closed {
		return fail.NotAvailableError("transaction is closed")
	}

	xerr := trx.alter(inctx, callback, opts...)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAlteredNothing:
			debug.IgnoreError(xerr)
			return nil
		default:
			return xerr
		}
	}

	trx.dirty = true
	return nil
}

// alter protects the data for exclusive write
// Valid options are :
// - WithoutReload() = disable reloading from metadata storage
func (trx *transaction[T]) alter(inctx context.Context, callback AnyResourceCallback, _ ...options.Option) (_ fail.Error) {
	if trx.coreChanges.shielded == nil {
		return fail.InvalidInstanceContentError("trx.coreChanges.shielded", "cannot be nil")
	}
	name, err := trx.coreChanges.getName()
	if err != nil {
		return fail.InconsistentError("uninitialized metadata should not be altered")
	}
	if name == "" {
		return fail.InconsistentError("uninitialized metadata should not be altered")
	}
	id, err := trx.coreChanges.getID()
	if err != nil {
		return fail.InconsistentError("uninitialized metadata should not be altered")
	}
	if id == "" {
		return fail.InconsistentError("uninitialized metadata should not be altered")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	trx.coreChanges.lock.Lock()
	defer trx.coreChanges.lock.Unlock()

	chRes := make(chan result.Holder[struct{}])
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			var xerr fail.Error

			// Make sure myself.properties is populated
			if trx.coreChanges.properties == nil {
				trx.coreChanges.properties, xerr = serialize.NewJSONProperties("resources." + trx.coreChanges.kind)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}
			}

			xerr = trx.coreChanges.shielded.Alter(func(p clonable.Clonable) fail.Error {
				return callback(p, trx.coreChanges.properties)
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

			return nil
		}()
		res, _ := result.NewHolder[struct{}](result.MarkAsFailed[struct{}](gerr))
		chRes <- res
	}()
	select {
	case res := <-chRes:
		return fail.Wrap(res.Error())
	case <-ctx.Done():
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}
}

// AlterCarried ...
func (trx *transaction[T]) AlterCarried(ctx context.Context, callback AnyCarriedCallback, opts ...options.Option) (_ fail.Error) {
	return trx.Alter(ctx, func(in clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
		return callback(in)
	}, opts...)
}

// AlterProperty allows to alter directly a single property
func (trx *transaction[T]) AlterProperty(ctx context.Context, property string, callback AnyPropertyCallback, opts ...options.Option) fail.Error {
	return trx.Alter(ctx, func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(property, callback)
	}, opts...)
}
