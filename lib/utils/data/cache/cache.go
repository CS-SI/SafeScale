/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

//go:generate minimock -o ../mocks/mock_clonable.go -i github.com/CS-SI/SafeScale/lib/utils/data/cache.Cache

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/observer"
	"github.com/CS-SI/SafeScale/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Cache interface describing what a struct must implement to be considered as a cache
type Cache interface {
	observer.Observer

	Entry(key string) (*Entry, fail.Error)                     // returns a cache entry from its key
	Reserve(key string) fail.Error                             // reserve an entry in the cache
	Commit(key string, content Cacheable) (*Entry, fail.Error) // Commit fills a previously reserved entry by 'key' with 'content'
	Free(key string) fail.Error                                // frees a cache entry (removing the reservation from cache)
	Add(content Cacheable) (*Entry, fail.Error)                // adds a content in cache (doing Reserve+Commit in a whole with content ID as key)
}

type cache struct {
	name atomic.Value

	lock     sync.RWMutex
	cache    map[string]*Entry
	reserved map[string]struct{}
}

// NewCache creates a new cache
func NewCache(name string) (Cache, fail.Error) {
	if name == "" {
		return &cache{}, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	cacheInstance := &cache{
		cache:    map[string]*Entry{},
		reserved: map[string]struct{}{},
	}
	cacheInstance.name.Store(name)
	return cacheInstance, nil
}

func (instance *cache) isNull() bool {
	return instance == nil || instance.name.Load().(string) == "" || instance.cache == nil
}

// GetID satisfies interface data.Identifiable
func (instance *cache) GetID() string {
	return instance.name.Load().(string)
}

// GetName satisfies interface data.Identifiable
func (instance *cache) GetName() string {
	return instance.name.Load().(string)
}

// GetEntry returns a cache entry from its key
func (instance *cache) Entry(key string) (*Entry, fail.Error) {
	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	// If key is reserved, we may have to wait reservation committed or freed to determine if
	if _, ok := instance.reserved[key]; ok {
		ce, ok := instance.cache[key]
		if !ok {
			return nil, fail.InconsistentError("reserved entry '%s' in %s cache does not have a corresponding cache entry", key, instance.GetName())
		}

		reservation, ok := ce.Content().(*reservation)
		if !ok {
			// May have transitioned from reservation content to real content, first check that there is no more reservation...
			if _, ok := instance.reserved[key]; ok {
				return nil, fail.InconsistentError("'*cache.reservation' expected, '%s' provided", reflect.TypeOf(ce.Content()).String())
			}
		} else {
			// Note: there is no timeout in this select because from here, we have no clue about the time that a Free() or Commit() may take to be called
			// FIXME: add a timeout in Reserve() that will be set from the code that know how long the operation may take
			select {
			case <-reservation.freed():
				return nil, fail.NotFoundError("failed to find entry with key '%s' in %s cache", key, instance.GetName())
			case <-reservation.committed():
				// acknowledge commit, and continue
			}
		}
	}

	// If key is found in cache, returns corresponding *cache.Entry
	if ce, ok := instance.cache[key]; ok {
		return ce, nil
	}

	return nil, fail.NotFoundError("failed to find entry with key '%s' in %s cache", key, instance.GetName())
}

/*
ReserveEntry locks an entry identified by key for update

Returns:
	nil: reservation succeeded
	*fail.ErrNotAvailable; if entry is already reserved
	*fail.ErrDuplicate: if entry is already present
*/
func (instance *cache) Reserve(key string) (xerr fail.Error) {
	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if key = strings.TrimSpace(key); key == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeReserveEntry(key)
}

// unsafeReserveEntry is the workforce of ReserveEntry, without locking
func (instance *cache) unsafeReserveEntry(key string) (xerr fail.Error) {
	if _, ok := instance.reserved[key]; ok {
		return fail.NotAvailableError("the entry '%s' of %s cache is already reserved", key, instance.GetName())
	}
	if _, ok := instance.cache[key]; ok {
		return fail.DuplicateError(callstack.DecorateWith("", "", fmt.Sprintf("there is already an entry with key '%s' in the %s cache", key, instance.GetName()), 0))
	}

	ce := newEntry(newReservation(key))
	instance.cache[key] = &ce
	instance.reserved[key] = struct{}{}
	return nil
}

/*
CommitEntry fills a previously reserved entry with content
The key retained at the end in the cache may be different to the one passed in parameter (and used previously in ReserveEntry()), because content.ID() has to be the final key.

Returns:
	nil, *fail.ErrNotFound: the cache entry identified by 'key' is not reserved
	nil, *fail.ErrNotAvailable: the content of the cache entry cannot be committed, because the content ID has changed and this new key has already been reserved
	nil, *fail.ErrDuplicate: the content of the cache entry cannot be committed, because the content ID has changed and this new key is already present in the cache
	*Entry, nil: content committed successfully

Note: if CommitEntry fails, yoiu still have to call FreeEntry to release the reservation
*/
func (instance *cache) Commit(key string, content Cacheable) (ce *Entry, xerr fail.Error) {
	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if key = strings.TrimSpace(key); key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeCommitEntry(key, content)
}

// unsafeCommitEntry is the workforce of CommitEntry, without locking
// The key retained at the end in the cache may be different to the one passed in parameter (and used previously in ReserveEntry), because content.ID() has to be the final key.
func (instance *cache) unsafeCommitEntry(key string, content Cacheable) (_ *Entry, xerr fail.Error) {
	if _, ok := instance.reserved[key]; !ok {
		return nil, fail.NotFoundError("the cache entry '%s' is not reserved", key)
	}

	// content may bring new key, based on content.ID(), different from the key reserved; we have to check if this new key has not been reserved by someone else...
	newContentKey := content.GetID()
	if newContentKey != key {
		if _, ok := instance.reserved[newContentKey]; ok {
			return nil, fail.NotAvailableError("the cache entry '%s' in %s cache, corresponding to the new ID of the content, is reserved; content cannot be committed", newContentKey, instance.name)
		}
		if _, ok := instance.cache[content.GetID()]; ok {
			return nil, fail.DuplicateError("the cache entry '%s' in %s cache, corresponding to the new ID of the content, is already used; content cannot be committed", newContentKey, instance.name)
		}
	}

	// Everything is fine, we can update
	cacheEntry, ok := instance.cache[key]
	if ok {
		oldContent := cacheEntry.Content()
		r, ok := oldContent.(*reservation)
		if !ok {
			return nil, fail.InconsistentError("'*cache.reservation' expected, '%s' provided", reflect.TypeOf(oldContent).String())
		}

		// TODO: this has to be tested with a specific unit test
		err := content.AddObserver(instance)
		if err != nil {
			return nil, fail.ConvertError(err)
		}

		// Update cache entry with real content
		cacheEntry.lock.Lock()
		cacheEntry.content = data.NewImmutableKeyValue(newContentKey, content)
		cacheEntry.lock.Unlock()

		// reserved key may have to change accordingly with the ID of content
		delete(instance.cache, key)
		delete(instance.reserved, key)
		instance.cache[newContentKey] = cacheEntry

		// signal potential waiter on Entry() that reservation has been committed
		if r.committedCh != nil {
			r.committedCh <- struct{}{}
			close(r.committedCh)
		}

		return cacheEntry, nil
	}

	return nil, fail.InconsistentError("the reservation does not have a corresponding entry identified by '%s' in %s cache", key, instance.GetName())
}

// Free unlocks the cache entry and removes the reservation
// return:
//  nil: reservation removed
//  *fail.ErrNotAvailable: the cache entry identified by 'key' is not reserved
//  *fail.InconsistentError: the cache entry of the reservation should have been *cache.reservation, and is not
func (instance *cache) Free(key string) (xerr fail.Error) {
	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if key = strings.TrimSpace(key); key == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeFreeEntry(key)
}

// unsafeFreeEntry is the workforce of FreeEntry, without locking
func (instance *cache) unsafeFreeEntry(key string) fail.Error {
	if _, ok := instance.reserved[key]; !ok {
		return fail.NotAvailableError("the entry '%s' in cache %s is not reserved", key, instance.GetName())
	}

	var (
		ce *Entry
		ok bool
	)
	if ce, ok = instance.cache[key]; ok {
		r, ok := ce.Content().(*reservation)
		if !ok {
			return fail.InconsistentError("'*cache.reservation' expected, '%s' provided", reflect.TypeOf(ce.Content()).String())
		}

		// Cleanup key from cache and reservations
		delete(instance.cache, key)
		delete(instance.reserved, key)

		// Signal potential waiters the reservation has been freed
		if r.freedCh != nil {
			r.freedCh <- struct{}{}
			close(r.freedCh)
		}
	}

	return nil
}

// Add adds a content in cache
func (instance *cache) Add(content Cacheable) (_ *Entry, xerr fail.Error) {
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}
	if content == nil {
		return nil, fail.InvalidParameterCannotBeNilError("content")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	id := content.GetID()
	xerr = instance.unsafeReserveEntry(id)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		if xerr != nil {
			if derr := instance.unsafeFreeEntry(id); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free cache entry '%s' in cache %s", id, instance.GetName()))
			}
		}
	}()

	cacheEntry, xerr := instance.unsafeCommitEntry(id, content)
	if xerr != nil {
		return nil, xerr
	}

	return cacheEntry, nil
}

// SignalChange tells the cache entry something has been changed in the content
func (instance *cache) SignalChange(key string) {
	if instance == nil {
		return
	}

	if key == "" {
		return
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	if ce, ok := instance.cache[key]; ok {
		ce.lock.Lock()
		defer ce.lock.Unlock()

		ce.lastUpdated = time.Now()
	}
}

// MarkAsFreed tells the cache to unlock content (decrementing the counter of uses)
func (instance *cache) MarkAsFreed(id string) {
	if instance == nil {
		return
	}

	if id == "" {
		return
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	if ce, ok := instance.cache[id]; ok {
		ce.UnlockContent()
	}
}

// MarkAsDeleted tells the cache entry to be considered as deleted
func (instance *cache) MarkAsDeleted(key string) {
	if instance == nil {
		return
	}

	if key == "" {
		return
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	delete(instance.cache, key)
}
