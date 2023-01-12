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
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"
)

type transaction[T clonable.Clonable] struct {
	mu             *sync.Mutex // used for concurrency-safety
	original       T           // contains the original instance on which the transaction applies
	castedOriginal *Core       // is used to propagate some methods of 'original' to transaction
	changes        T           // contains the instance with changes
	castedChanges  *Core
	dirty          bool // tells there have been changes
	closed         bool // tells the transaction is closed
}

// NewTransaction creates a transaction
func NewTransaction[T clonable.Clonable](ctx context.Context, original T) (*transaction[T], fail.Error) {
	if valid.IsNil(original) {
		return nil, fail.InvalidParameterCannotBeNilError("original")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	// -- make sure the parameter is correctly composed
	castedOriginal, err := lang.Cast[*Core](original)
	if err != nil {
		return nil, fail.InvalidParameterError("original must be composed with '*metadata.Core'")
	}
	if castedOriginal.properties == nil {
		return nil, fail.InvalidParameterCannotBeNilError("original.properties")
	}

	// -- RLock original instance to prevent other concurrent changes (but still allowing inspection)
	castedOriginal.lock.RLock()

	// -- Reload reloads data from object storage to be sure to have the last revision

	xerr := castedOriginal.unsafeReload(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to reload metadata")
	}

	// -- creates transaction instance
	trx := &transaction[T]{
		mu:             &sync.Mutex{},
		original:       original,
		castedOriginal: castedOriginal,
	}
	trx.changes, err = clonable.CastedClone[T](original)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	trx.castedChanges, err = lang.Cast[*Core](trx.changes)
	if err != nil {
		return nil, fail.Wrap(err)
	}

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

	trx.castedOriginal.lock.RUnlock()
	trx.castedOriginal.lock.Lock()
	err := trx.original.Replace(trx.changes)
	if err != nil {
		trx.castedOriginal.lock.Unlock()
		trx.castedOriginal.lock.RLock()
		return fail.Wrap(err)
	}

	trx.castedOriginal.committed = false
	xerr := trx.castedOriginal.write(ctx)
	trx.castedOriginal.lock.Unlock()
	trx.castedOriginal.lock.RLock()
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

	trx.castedOriginal.lock.RUnlock()
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

// Service returns the iaasapi.Service used to create/load the persistent object
func (trx *transaction[T]) Service() iaasapi.Service {
	if trx == nil {
		return nil
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.castedOriginal.Service()
}

func (trx *transaction[T]) Job() jobapi.Job {
	if trx == nil {
		return nil
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.castedOriginal.Job()
}

// GetID returns the id of the data protected
// satisfies interface data.Identifiable
func (trx *transaction[T]) GetID() (string, error) {
	if valid.IsNull(trx) {
		return "--invalid--", fail.InvalidInstanceError()
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.castedOriginal.GetID()
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

	return trx.castedOriginal.GetName()
}

func (trx *transaction[T]) IsTaken() bool {
	if valid.IsNull(trx) {
		return false
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.castedOriginal.IsTaken()
}

// Kind returns the kind of object served
func (trx *transaction[T]) Kind() string {
	if valid.IsNull(trx) {
		logrus.Errorf(fail.InconsistentError("invalid call of Kind() from null value").Error())
		return "-- invalid --"
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.castedOriginal.Kind()
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

	return trx.castedChanges.inspect(inctx, callback, opts...)
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
	return trx.castedChanges.inspect(inctx, callback, opts...)
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

	xerr := trx.castedChanges.alter(inctx, callback, opts...)
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
