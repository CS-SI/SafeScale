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
	"sync"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	iaasapi "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"
)

// Transaction defines the interface to use when a transaction on resource is needed
// 'A' is a type satisfying the interface [abstract.Abstract]
// 'T' is a type satisfying the interface [Metadata]
type Transaction[A abstract.Abstract, T Metadata[A]] interface {
	Commit(ctx context.Context) fail.Error   // commits the changes
	GetName() string                         // returns transactioned object name
	GetID() (string, error)                  // returns transactioned object id
	IsNull() bool                            // Tells if instance is a zero-value
	Rollback(ctx context.Context) fail.Error // ignores the uncommitted changes
	SilentTerminate(ctx context.Context)     // closes the connection without returning error, only log if error occurs
	Service() (iaasapi.Service, fail.Error)
	Terminate(ctx context.Context) fail.Error                 // closes the transaction; will fail if dirty and neither Commit() nor Rollback() has been called
	TerminateFromError(ctx context.Context, ferr *fail.Error) // closes the transaction, committing if ferr contains no error, rolling back otherwise

	alter(ctx context.Context, callback ResourceCallback[A]) fail.Error                            // allows to alter carried value and properties safely
	alterAbstract(ctx context.Context, callback AbstractCallback[A]) fail.Error                    // allows to alter carried value safely
	alterProperty(ctx context.Context, property string, callback AnyPropertyCallback) fail.Error   // allows to alter a property safely
	alterProperties(ctx context.Context, callback AllPropertiesCallback) fail.Error                // allows to alter all properties safely
	inspect(ctx context.Context, callback ResourceCallback[A]) fail.Error                          // allows to inspect carried value and properties safely (after Reload)
	inspectAbstract(ctx context.Context, callback AbstractCallback[A]) fail.Error                  // allows to inspect a property safely (after Reload)
	inspectProperty(ctx context.Context, property string, callback AnyPropertyCallback) fail.Error // allows to alter a property safely (after Reload)
	inspectProperties(ctx context.Context, callback AllPropertiesCallback) fail.Error              // allows to inspect all properties safely (after Reload)
}

// transaction is the implementation of the former interface
type transaction[A abstract.Abstract, T Metadata[A]] struct {
	mu           *sync.Mutex // used for concurrency-safety
	name, id     string
	original     T        // contains the original instance on which the transaction applies
	coreOriginal *Core[A] // is used to propagate some methods of 'original' to transaction
	changes      T        // contains the instance with changes
	coreChanges  *Core[A]
	dirty        bool // tells there have been changes
	closed       bool // tells the transaction is closed
}

// NewTransaction creates a transaction
func NewTransaction[A abstract.Abstract, T Metadata[A]](ctx context.Context, original T) (*transaction[A, T], fail.Error) {
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
	// coreOriginal.lock.RLock()

	// -- Reload reloads data from object storage to be sure to have the last revision
	xerr = coreOriginal.reload(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to reload metadata")
	}

	name := coreOriginal.GetName()
	id, err := coreOriginal.GetID()
	if err != nil {
		return nil, fail.Wrap(err)
	}

	// -- creates transaction instance
	trx := &transaction[A, T]{
		mu:           &sync.Mutex{},
		name:         name,
		id:           id,
		original:     original,
		coreOriginal: coreOriginal,
	}
	trx.changes, err = clonable.CastedClone[T](original)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	trx.coreChanges, _ = trx.changes.core()
	return trx, nil
}

// IsNull returns true if the Core instance represents the null value for Core
func (trx *transaction[A, T]) IsNull() bool {
	if trx == nil {
		return true
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return valid.IsNull(trx.original) || valid.IsNull(trx.changes)
}

// Commit saves the changes
func (trx *transaction[A, T]) Commit(ctx context.Context) fail.Error {
	if valid.IsNil(trx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.commit(ctx)
}

// commit saves the changes
func (trx *transaction[A, T]) commit(ctx context.Context) fail.Error {
	// if trx.closed {
	// 	return fail.NotAvailableError("transaction is closed")
	// }

	if !trx.dirty {
		return nil
	}

	trx.coreOriginal.lock.Lock()
	defer trx.coreOriginal.lock.Unlock()

	err := trx.original.Replace(trx.changes)
	if err != nil {
		return fail.Wrap(err)
	}

	trx.coreOriginal.committed = false
	xerr := trx.coreOriginal.write(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	trx.dirty = false
	return nil
}

// Rollback gives up on changes
func (trx *transaction[A, T]) Rollback(ctx context.Context) fail.Error {
	if valid.IsNil(trx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.rollback(ctx)
}

// rollback gives up on changes
func (trx *transaction[A, T]) rollback(_ context.Context) fail.Error {
	if trx.closed {
		return fail.NotAvailableError("transaction is closed")
	}

	trx.coreChanges.lock.Lock()
	defer trx.coreChanges.lock.Unlock()

	err := trx.changes.Replace(trx.original)
	if err != nil {
		return fail.Wrap(err)
	}

	trx.coreOriginal.committed = false
	trx.dirty = false
	return nil
}

// Terminate makes the transaction not usable anymore and free storage lock
func (trx *transaction[A, T]) Terminate(ctx context.Context) fail.Error {
	if valid.IsNil(trx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

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

// SilentTerminate is identical to Terminate() except it does not return any error, only log it
func (trx *transaction[A, T]) SilentTerminate(ctx context.Context) {
	var ferr fail.Error
	trx.TerminateFromError(ctx, &ferr)
	if ferr != nil {
		logrus.WithContext(ctx).Error(ferr.Error())
	}
}

// TerminateFromError makes the transaction not usable anymore and free storage lock
// if ferr is nil, commit if needed, else rollback
func (trx *transaction[A, T]) TerminateFromError(ctx context.Context, ferr *fail.Error) {
	if valid.IsNil(trx) {
		xerr := fail.InvalidInstanceError()
		if ferr == nil {
			logrus.WithContext(ctx).Error(xerr)
		} else {
			if *ferr != nil {
				_ = (*ferr).AddConsequence(xerr)
			} else {
				*ferr = xerr
			}
		}
		return
	}

	if ctx == nil {
		xerr := fail.InvalidParameterCannotBeNilError("ctx")
		if ferr == nil {
			logrus.WithContext(ctx).Error(xerr)
		} else {
			if *ferr != nil {
				_ = (*ferr).AddConsequence(xerr)
			} else {
				*ferr = xerr
			}
		}
		return
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	if trx.closed {
		return
	}

	if trx.dirty {
		if *ferr != nil {
			derr := trx.rollback(ctx)
			if derr != nil {
				_ = (*ferr).AddConsequence(derr)
			}
		} else {
			derr := trx.commit(ctx)
			if derr != nil {
				if ferr != nil {
					if *ferr != nil {
						_ = (*ferr).AddConsequence(derr)
						derr = nil
					} else {
						*ferr = derr
						derr = nil
					}
				} else {
					logrus.WithContext(ctx).Error(derr)
				}
			}
		}
	}

	// FIXME: unlocking storage

	trx.closed = true
}

// Service returns the iaasapi.Service used to create/load the persistent object
func (trx *transaction[A, T]) Service() (iaasapi.Service, fail.Error) {
	if trx == nil {
		return nil, fail.InvalidInstanceError()
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.coreOriginal.Service()
}

func (trx *transaction[A, T]) Job() jobapi.Job {
	if trx == nil {
		return nil
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.coreOriginal.Job()
}

// GetID returns the id of the data protected
// satisfies interface data.Identifiable
func (trx *transaction[A, T]) GetID() (string, error) {
	if valid.IsNull(trx) {
		return "--invalid--", fail.InvalidInstanceError()
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.id, nil
}

// GetName returns the name of the data protected
// satisfies interface data.Identifiable
func (trx *transaction[A, T]) GetName() string {
	if valid.IsNull(trx) {
		logrus.Error(fail.InvalidInstanceError().Error())
		return "--invalid--"
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.name
}

// IsTaken ...
func (trx *transaction[A, T]) IsTaken() bool {
	if valid.IsNull(trx) {
		return false
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.coreOriginal.IsTaken()
}

// Kind returns the kind of object served
func (trx *transaction[A, T]) Kind() string {
	if valid.IsNull(trx) {
		logrus.Errorf(fail.InconsistentError("invalid call of Kind() from null value").Error())
		return "-- invalid --"
	}

	trx.mu.Lock()
	defer trx.mu.Unlock()

	return trx.coreOriginal.Kind()
}

// inspect protects the data for shared read
func (trx *transaction[A, T]) inspect(ctx context.Context, callback ResourceCallback[A]) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// trx.mu.Lock()
	// defer trx.mu.Unlock()

	if trx.closed {
		return fail.NotAvailableError("transaction is closed")
	}
	if trx.coreChanges.properties == nil {
		return fail.InvalidInstanceContentError("trx.coreChanges.properties", "cannot be nil")
	}

	svc, xerr := trx.coreChanges.Service()
	if xerr != nil {
		return xerr
	}

	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	// trx.coreChanges.lock.RLock()
	// defer trx.coreChanges.lock.RUnlock()

	xerr = retry.WhileUnsuccessfulWithLimitedRetries(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			return trx.coreChanges.carried.Inspect(func(carried A) fail.Error {
				innerXErr := callback(carried, trx.coreChanges.properties)
				if innerXErr != nil {
					switch xerr.(type) {
					case *fail.ErrInvalidParameter, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent:
						return retry.StopRetryError(innerXErr)
					default:
						return innerXErr
					}
				}

				return nil
			})
		},
		timings.SmallDelay(),
		timings.ConnectionTimeout(),
		6,
	)
	if xerr != nil {
		return fail.Wrap(xerr.Cause())
	}

	return nil
}

// InspectAbstract ...
func (trx *transaction[A, T]) inspectAbstract(ctx context.Context, callback AbstractCallback[A]) (_ fail.Error) {
	return trx.inspect(ctx, func(in A, _ *serialize.JSONProperties) fail.Error { return callback(in) })
}

// InspectProperty allows to inspect directly a single property
func (trx *transaction[A, T]) inspectProperty(ctx context.Context, property string, callback AnyPropertyCallback) fail.Error {
	return trx.inspect(ctx, func(_ A, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(property, callback)
	})
}

// InspectProperties allows to inspect directly properties
func (trx *transaction[A, T]) inspectProperties(ctx context.Context, callback AllPropertiesCallback) fail.Error {
	return trx.inspect(ctx, func(_ A, props *serialize.JSONProperties) fail.Error {
		return callback(props)
	})
}

// Alter protects the data for exclusive write
func (trx *transaction[A, T]) alter(ctx context.Context, callback ResourceCallback[A]) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// trx.mu.Lock()
	// defer trx.mu.Unlock()

	if trx.closed {
		return fail.NotAvailableError("transaction is closed")
	}
	if trx.coreChanges.carried == nil {
		return fail.InvalidInstanceContentError("trx.coreChanges.carried", "cannot be nil")
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

	var xerr fail.Error

	// Make sure myself.properties is populated
	// trx.coreChanges.lock.Lock()
	if trx.coreChanges.properties == nil {
		trx.coreChanges.properties, xerr = serialize.NewJSONProperties("resources." + trx.coreChanges.kind)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			// trx.coreChanges.lock.Unlock()
			return xerr
		}
	}

	// trx.coreChanges.lock.Unlock()
	// xerr = trx.coreChanges.Reload(ctx)
	// if xerr != nil {
	// 	return xerr
	// }

	// trx.coreChanges.lock.Lock()
	// defer trx.coreChanges.lock.Unlock()

	xerr = trx.coreChanges.carried.Alter(func(carried A) fail.Error {
		return callback(carried, trx.coreChanges.properties)
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

	trx.dirty = true
	return nil
}

// AlterAbstract ...
func (trx *transaction[A, T]) alterAbstract(ctx context.Context, callback AbstractCallback[A]) (_ fail.Error) {
	return trx.alter(ctx, func(carried A, _ *serialize.JSONProperties) fail.Error {
		return callback(carried)
	})
}

// AlterProperty allows to alter directly a single property
func (trx *transaction[A, T]) alterProperty(ctx context.Context, property string, callback AnyPropertyCallback) fail.Error {
	return trx.alter(ctx, func(_ A, props *serialize.JSONProperties) fail.Error {
		return props.Alter(property, callback)
	})
}

// AlterProperties allows to alter directly properties
func (trx *transaction[A, T]) alterProperties(ctx context.Context, callback AllPropertiesCallback) fail.Error {
	return trx.alter(ctx, func(_ A, props *serialize.JSONProperties) fail.Error {
		return callback(props)
	})
}
