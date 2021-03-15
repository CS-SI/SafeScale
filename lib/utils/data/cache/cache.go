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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/observer"
	"github.com/CS-SI/SafeScale/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Cache interface describing what a struct must implement to be considered as a Cache
type Cache interface {
	// concurrency.TaskedLock
	observer.Observer

	GetEntry(key string) (*Entry, fail.Error) // returns a cache entry from its key

	// ReserveEntry locks an entry identified by key for update
	// if entry does not exist, create an empty one
	ReserveEntry(key string) fail.Error

	// CommitEntry fills a previously reserved entry by 'key' with 'content'
	// The key retained at the end in the cache may be different to the one passed in parameter (and used previously in ReserveEntry),
	// because content.GetID() has to be the final key.
	CommitEntry(key string, content Cacheable) (*Entry, fail.Error)

	FreeEntry(key string) fail.Error                 // frees a cache entry (removing the reservation from cache)
	AddEntry(content Cacheable) (*Entry, fail.Error) // adds a content in cache (doing ReserveEntry+CommitEntry in a whole)
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
func (instance *cache) GetEntry(key string) (*Entry, fail.Error) {
	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	if _, ok := instance.reserved[key]; ok {
		return nil, fail.NotAvailableError("cache entry '%s' is reserved and cannot be use until freed or committed", key)
	}
	if ce, ok := instance.cache[key]; ok {
		return ce, nil
	}

	return nil, fail.NotFoundError("failed to find cache entry with key '%s'", key)
}

// ReserveEntry locks an entry identified by key for update
// if entry does not exist, create an empty one
func (instance *cache) ReserveEntry(key string) (xerr fail.Error) {
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
		return fail.NotAvailableError("the cache entry '%s' is already reserved", key)
	}
	if _, ok := instance.cache[key]; ok {
		return fail.DuplicateError(callstack.DecorateWith("", "", fmt.Sprintf("there is already an entry in the cache with key '%s'", key), 0))
	}

	ce := newEntry(&reservation{key: key})
	ce.lock()
	instance.cache[key] = &ce
	instance.reserved[key] = struct{}{}
	return nil
}

// CommitEntry fills a previously reserved entry with content
// The key retained at the end in the cache may be different to the one passed in parameter (and used previously in ReserveEntry), because content.GetID() has to be the final key.
func (instance *cache) CommitEntry(key string, content Cacheable) (ce *Entry, xerr fail.Error) {
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
// The key retained at the end in the cache may be different to the one passed in parameter (and used previously in ReserveEntry), because content.GetID() has to be the final key.
func (c *cache) unsafeCommitEntry(key string, content Cacheable) (ce *Entry, xerr fail.Error) {
	if _, ok := c.reserved[key]; !ok {
		return nil, fail.NotAvailableError("the cache entry '%s' is not reserved", key)
	}

	// content may bring new key, based on content.GetID(), than the key reserved; we have to check if this new key has not been reserved by someone else...
	if content.GetID() != key {
		if _, ok := c.reserved[content.GetID()]; ok {
			return nil, fail.InconsistentError("the cache entry '%s' corresponding to the ID of the content is reserved; content cannot be committed", content.GetID())
		}
	}

	// Everything seems ok, we can update
	var ok bool
	if ce, ok = c.cache[key]; ok {
		ce.content = data.NewImmutableKeyValue(content.GetID(), content)
		// reserved key may have to change accordingly with the ID of content
		delete(c.cache, key)
		delete(c.reserved, key)
		c.cache[content.GetID()] = ce
		ce.unlock()

		// FIXME: URGENT If there is a error adding the observer, we must rollback the changes in caches and entries
		// Also, this has to be tested with a specific unit test
		return ce, fail.ConvertError(content.AddObserver(c))
	}

	return nil, fail.NotFoundError("failed to find cache entry identified by '%s'", key)
}

// FreeEntry unlocks the cache entry and removes the reservation
func (instance *cache) FreeEntry(key string) (xerr fail.Error) {
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
		return fail.NotAvailableError("the cache entry '%s' is not reserved", key)
	}

	var (
		ce *Entry
		ok bool
	)
	if ce, ok = instance.cache[key]; ok {
		delete(instance.cache, key)
		delete(instance.reserved, key)
		ce.unlock()
	}

	return nil
}

// AddEntry adds a content in cache
func (instance *cache) AddEntry(content Cacheable) (_ *Entry, xerr fail.Error) {
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}
	if content == nil {
		return nil, fail.InvalidParameterCannotBeNilError("content")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	id := content.GetID()
	if xerr := instance.unsafeReserveEntry(id); xerr != nil {
		return nil, xerr
	}
	defer func() {
		if xerr != nil {
			if derr := instance.unsafeFreeEntry(id); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free cache entry '%s'", id))
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
		ce.lock()
		defer ce.unlock()

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
