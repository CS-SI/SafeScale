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

package cache

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CS-SI/SafeScale/v21/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/valid"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

type mapStore struct {
	name     atomic.Value
	lock     *sync.RWMutex
	cached   map[string]*Entry
	reserved map[string]*reservation
}

// NewMapStore creates a new cache storage based on map (thread-safe)
func NewMapStore(name string) (Store, fail.Error) {
	if name == "" {
		return &mapStore{}, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	instance := &mapStore{
		cached:   map[string]*Entry{},
		reserved: map[string]*reservation{},
		lock:     &sync.RWMutex{},
	}
	instance.name.Store(name)
	return instance, nil
}

// GetID satisfies interface data.Identifiable
func (instance *mapStore) GetID() string {
	return instance.name.Load().(string)
}

// GetName satisfies interface data.Identifiable
func (instance *mapStore) GetName() string {
	return instance.name.Load().(string)
}

// Entry returns a cached entry from its key
func (instance *mapStore) Entry(ctx context.Context, key string) (*Entry, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	// If key is reserved, we may have to wait reservation committed, freed or timed out
	instance.lock.Lock()
	reservedContent, reserved := instance.reserved[key]
	instance.lock.Unlock() // nolint
	if reserved {
		xerr := reservedContent.waitReleased()
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrDuplicate:
				// We want the cache entry, so this error is attended, continue

			case *fail.ErrTimeout:
				derr := instance.Free(ctx, key)
				if derr != nil {
					_ = xerr.AddConsequence(derr)
				}
				return nil, fail.NotFoundError("failed to find entry '%s' in %s cache: %v", key, instance.GetName(), xerr)

			default:
				return nil, xerr
			}
		}
	}

	instance.lock.RLock()
	ce, ok := instance.cached[key]
	instance.lock.RUnlock() // nolint
	if ok {
		return ce, nil
	}

	return nil, fail.NotFoundError("failed to find entry with key '%s' in %s cache", key, instance.GetName())
}

/*
Reserve locks an entry identified by key for update

Returns:
	- nil: reservation succeeded
	- *fail.ErrInvalidInstance: the instance is a null value, unable to use Reserve()
	- *fail.ErrInvalidParameter: one of the parameter is invalid
	- *fail.ErrNotAvailable; if entry is already cached or reserved
	- *fail.ErrInconsistent: the internal content of instance regarding the reservation for key is inconsistent
*/
func (instance *mapStore) Reserve(ctx context.Context, key string, timeout time.Duration) (ferr fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if key = strings.TrimSpace(key); key == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("key")
	}
	if timeout == 0 {
		return fail.InvalidParameterError("timeout", "cannot be 0")
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(task, true).Entering()
	defer tracer.Exiting()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	_, reserved := instance.reserved[key]
	ce, cached := instance.cached[key]

	// If key is already reserved, we may have to wait reservation committed or freed to determine if we can effectively reserve it
	if reserved {
		tracer.Trace("found a reservation for key '%s' in Store '%s'", key, instance.GetName())

		if !cached {
			return fail.InconsistentError("found reservation for key '%s' in Store '%s' does not have a corresponding cached entry", key, instance.GetName())
		}

		reservation, ok := ce.Content().(*reservation)
		if !ok {
			// May have transitioned from reservation content to real content, first check that there is no more reservation...
			_, cached := instance.cached[key]
			if cached {
				xerr = fail.NotAvailableError("the key '%s' of Store '%s' is now committed", key, instance.GetName())
				logrus.Errorf(callstack.DecorateWith("", xerr.Error(), "", 0))
				return xerr
			}
		} else {
			if reservation.IsMine(ctx) {
				return fail.DuplicateError("cannot reserve key '%s' in Store '%s' twice", key, instance.GetName())
			}

			tracer.Trace("found reservation that may not be committed, waiting for the reservation to disappear")
			xerr := reservation.waitReleased()
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrDuplicate:
					tracer.Trace("found reservation for key '%s' in Store '%s' has mutated to cache entry; reservation cannot complete", key, instance.GetName())
					return fail.NotAvailableError("the entry '%s' of %s cache is already cached", key, instance.GetName())

				case *fail.ErrTimeout:
					tracer.Trace("found reservation has timed out, freeing it")
					derr := instance.unsafeFree(ctx, key)
					if derr != nil {
						switch derr.(type) {
						case *fail.ErrNotFound:
							debug.IgnoreError(derr)
						default:
							_ = xerr.AddConsequence(derr)
						}
					}
					// entry reservation is possible, continue to reserve

				default:
					return xerr
				}
			}
		}
	} else if cached {
		return fail.NotAvailableError("the entry '%s' of %s cache is already cached", key, instance.GetName())
	}

	tracer.Trace("(mapStore addr=%p) there is no reservation for key '%s' in Store '%s': reserving", instance, key, instance.GetName())

	content := newReservation(ctx, instance.GetName(), key)
	content.timeout = timeout
	nce := newEntry(content)
	pce := &nce
	instance.cached[key] = pce
	instance.reserved[key] = content
	return nil
}

/*
Commit fills a previously reserved entry with content
The key retained at the end in the cached may be different to the one passed in parameter (and used previously in ReserveEntry()), because content.ID() has to be the final key.

Returns:
	nil, *fail.ErrNotFound: the cached entry identified by 'key' is not reserved
	nil, *fail.ErrNotAvailable: the content of the cached entry cannot be committed, because the content ID has changed and this new key has already been reserved
	nil, *fail.ErrDuplicate: the content of the cached entry cannot be committed, because the content ID has changed and this new key is already present in the cached
	*Entry, nil: content committed successfully

Note: if CommitEntry fails, you still have to call FreeEntry to release the reservation
*/
func (instance *mapStore) Commit(ctx context.Context, key string, content Cacheable) (ce *Entry, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if key = strings.TrimSpace(key); key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("key")
	}
	if content == nil {
		return nil, fail.InvalidParameterCannotBeNilError("content")
	}

	task, _ := concurrency.TaskFromContextOrVoid(ctx) // nolint
	defer debug.NewTracer(task, true, "(ctx, %s)", key).Entering().Exiting()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr := instance.checkReservationConsistency(ctx, key)
	if xerr != nil {
		return nil, xerr
	}

	// content may bring new key, based on content.ID(), different from the key reserved; we have to check if this new key has not been reserved by someone else...
	var reservedContent *reservation
	newContentKey := content.GetID()
	if newContentKey != key {
		var ok bool
		reservedContent, ok = instance.reserved[newContentKey]
		if ok {
			return nil, fail.NotAvailableError("the cached entry '%s' in %s cache, corresponding to the new ID of the content, is reserved; content cannot be committed", newContentKey, instance.name)
		}
		if _, ok := instance.cached[content.GetID()]; ok {
			return nil, fail.DuplicateError("the cached entry '%s' in %s cache, corresponding to the new ID of the content, is already used; content cannot be committed", newContentKey, instance.name)
		}
	}
	if reservedContent != nil {
		if reservedContent.timeout < time.Since(reservedContent.created) {
			// reservation has expired...
			cleanErr := fail.TimeoutError(nil, reservedContent.timeout, "reservation of key '%s' in %s cache has expired")
			derr := instance.unsafeFree(ctx, key)
			if derr != nil {
				_ = cleanErr.AddConsequence(derr)
			}
			return nil, cleanErr
		}
	}

	// Everything is fine, we can update
	cacheEntry, ok := instance.cached[key]
	if ok {
		oldContent := cacheEntry.Content()
		reservedContent, ok := oldContent.(*reservation)
		if !ok {
			return nil, fail.InconsistentError("'*reservation' expected, '%s' provided", reflect.TypeOf(oldContent).String())
		}

		// TODO: this has to be tested with a specific unit test
		err := content.AddObserver(instance)
		if err != nil {
			return nil, fail.ConvertError(err)
		}

		// Update cached entry with real content
		cacheEntry.lock.Lock()
		cacheEntry.content = data.NewImmutableKeyValue(newContentKey, content)
		cacheEntry.lock.Unlock() // nolint

		// reserved key may have to change accordingly with the ID of content
		delete(instance.cached, key)
		delete(instance.reserved, key)
		instance.cached[newContentKey] = cacheEntry

		// signal potential waiter on Entry() that reservation has been committed
		if reservedContent.committedCh != nil {
			reservedContent.committedCh <- struct{}{}
			close(reservedContent.committedCh)
		}

		return cacheEntry, nil
	}

	return nil, fail.InconsistentError("the reservation does not have a corresponding entry identified by '%s' in %s cache", key, instance.GetName())
}

func (instance mapStore) checkReservationConsistency(ctx context.Context, key string) fail.Error {
	reserved, ok := instance.reserved[key]
	if !ok {
		// return nil, fail.NotFoundError("the cached entry '%s' is not reserved (may have expired)", key)
		return fail.NotFoundError(callstack.DecorateWith("", fmt.Sprintf("the cache entry '%s' in Store '%s' is not reserved (may have expired)", key, instance.GetName()), "", 0))
	}

	if !reserved.IsMine(ctx) {
		return fail.InconsistentError("failed to commit on key '%s', probably reserved by another goroutine", key)
	}

	return nil
}

// Free unlocks the cached entry and removes the reservation
// returns:
//  - nil: reservation removed
//  - *fail.ErrNotAvailable: the cached entry identified by 'key' is not reserved
//  - *fail.InconsistentError: the cached entry of the reservation should have been *cached.reservation, and is not
func (instance *mapStore) Free(ctx context.Context, key string) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if key = strings.TrimSpace(key); key == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeFree(ctx, key)
}

// unsafeFree is the workforce of Free, without locking
func (instance *mapStore) unsafeFree(ctx context.Context, key string) fail.Error {
	task, _ := concurrency.TaskFromContextOrVoid(ctx) // nolint
	defer debug.NewTracer(task, true, "(ctx, %s)", key).Entering().Exiting()

	xerr := instance.checkReservationConsistency(ctx, key)
	if xerr != nil {
		return xerr
	}

	var (
		ce *Entry
		ok bool
	)
	if ce, ok = instance.cached[key]; ok {
		reservedContent, ok := ce.Content().(*reservation)
		if !ok {
			return fail.InconsistentError("'*cached.reservation' expected, '%s' provided", reflect.TypeOf(ce.Content()).String())
		}

		// Cleanup key from cached and reservations
		delete(instance.cached, key)
		delete(instance.reserved, key)

		// Signal potential waiters the reservation has been freed
		if reservedContent.freedCh != nil {
			reservedContent.freedCh <- struct{}{}
			close(reservedContent.freedCh)
		}
	}

	return nil
}

const reservationTimeoutForAddition = 5 * time.Second

// Add adds a content in cache
func (instance *mapStore) Add(ctx context.Context, content Cacheable) (_ *Entry, ferr fail.Error) {
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}
	if content == nil {
		return nil, fail.InvalidParameterCannotBeNilError("content")
	}

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	id := content.GetID()
	xerr := instance.Reserve(ctx, id, reservationTimeoutForAddition)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		if ferr != nil {
			derr := instance.Free(ctx, id)
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free entry '%s' in cache %s", id, instance.GetName()))
			}
		}
	}()

	cacheEntry, xerr := instance.Commit(ctx, id, content)
	if xerr != nil {
		return nil, xerr
	}

	return cacheEntry, nil
}

// SignalChange tells the cached entry something has been changed in the content
func (instance *mapStore) SignalChange(key string) {
	if instance == nil {
		return
	}

	if key == "" {
		return
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	if ce, ok := instance.cached[key]; ok {
		ce.lock.Lock()
		defer ce.lock.Unlock()

		ce.lastUpdated = time.Now()
	}
}

// MarkAsFreed tells the cached to unlock content (decrementing the counter of uses)
func (instance *mapStore) MarkAsFreed(id string) {
	if instance == nil {
		return
	}

	if id == "" {
		return
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	ce, ok := instance.cached[id]
	if ok {
		ce.UnlockContent()
	}
}

// MarkAsDeleted tells the cached entry to be considered as deleted
func (instance *mapStore) MarkAsDeleted(key string) {
	if instance == nil {
		return
	}

	if key == "" {
		return
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	delete(instance.cached, key)
}
