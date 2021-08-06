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

package iaas

import (
	"sync"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ResourceCache contains the caches for all kinds of resources
type ResourceCache struct {
	byID   cache.Cache
	byName map[string]string
	lock   sync.Mutex
}

// NewResourceCache initializes a new instance of ResourceCache
func NewResourceCache(name string) (*ResourceCache, fail.Error) {
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	cacheInstance, xerr := cache.NewCache(name)
	if xerr != nil {
		return &ResourceCache{}, nil
	}

	rc := &ResourceCache{
		byID:   cacheInstance,
		byName: map[string]string{},
	}
	return rc, nil
}

// isNull tells if rc is a null value of *ResourceCache
func (rc *ResourceCache) isNull() bool {
	return rc == nil || rc.byID == nil || rc.byName == nil
}

// Get returns the content associated with key
func (rc *ResourceCache) Get(key string, options ...data.ImmutableKeyValue) (ce *cache.Entry, xerr fail.Error) {
	if rc == nil || rc.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	// Search in the cache by ID
	if ce, xerr = rc.byID.Entry(key); xerr == nil {
		return ce, nil
	}

	// Not found, search an entry in the cache by name to get id and search again by id
	rc.lock.Lock()
	if id, ok := rc.byName[key]; ok {
		if ce, xerr = rc.byID.Entry(id); xerr == nil {
			rc.lock.Unlock()
			return ce, nil
		}
	}
	rc.lock.Unlock()

	// We have a cache miss, check if we have a function to get the missing content
	if len(options) > 0 {
		var onMissFunc func() (cache.Cacheable, fail.Error)
		for _, v := range options {
			switch v.Key() { //nolint
			case "onMiss":
				onMissFunc = v.Value().(func() (cache.Cacheable, fail.Error))
			default:
			}
		}

		if onMissFunc != nil {
			if xerr := rc.unsafeReserveEntry(key); xerr != nil {
				return nil, xerr
			}

			var content cache.Cacheable
			if content, xerr = onMissFunc(); xerr == nil {
				ce, xerr = rc.unsafeCommitEntry(key, content)
			}
			if xerr != nil {
				if derr := rc.unsafeFreeEntry(key); derr != nil {
					_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free cache entry"))
				}
				return nil, xerr
			}
			return ce, nil
		}
	}

	return nil, fail.NotFoundError("failed to find cache entry with key %s, and does not know how to fill the miss", key)
}

// ReserveEntry sets a cache entry to reserve the key and returns the Entry associated
func (rc *ResourceCache) ReserveEntry(key string) fail.Error {
	if rc == nil || rc.isNull() {
		return fail.InvalidInstanceError()
	}
	if key == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	rc.lock.Lock()
	defer rc.lock.Unlock()

	return rc.unsafeReserveEntry(key)
}

// unsafeReserveEntry sets a cache entry to reserve the key and returns the Entry associated
func (rc *ResourceCache) unsafeReserveEntry(key string) fail.Error {
	return rc.byID.Reserve(key)
}

// CommitEntry confirms the entry in the cache with the content passed as parameter
func (rc *ResourceCache) CommitEntry(key string, content cache.Cacheable) (ce *cache.Entry, xerr fail.Error) {
	if rc == nil || rc.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	rc.lock.Lock()
	defer rc.lock.Unlock()

	return rc.unsafeCommitEntry(key, content)
}

// unsafeCommitEntry confirms the entry in the cache with the content passed as parameter
func (rc *ResourceCache) unsafeCommitEntry(key string, content cache.Cacheable) (ce *cache.Entry, xerr fail.Error) {
	if ce, xerr = rc.byID.Commit(key, content); xerr != nil {
		return nil, xerr
	}

	rc.byName[content.GetName()] = content.GetID()
	return ce, nil
}

// FreeEntry removes the reservation in cache
func (rc *ResourceCache) FreeEntry(key string) fail.Error {
	if rc == nil || rc.isNull() {
		return fail.InvalidInstanceError()
	}
	if key == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	rc.lock.Lock()
	defer rc.lock.Unlock()

	return rc.unsafeFreeEntry(key)
}

// unsafeFreeEntry removes the reservation in cache
func (rc *ResourceCache) unsafeFreeEntry(key string) fail.Error {
	return rc.byID.Free(key)
}

// AddEntry ...
func (rc *ResourceCache) AddEntry(content cache.Cacheable) (ce *cache.Entry, xerr fail.Error) {
	if rc == nil || rc.isNull() {
		return nil, fail.InvalidInstanceError()
	}

	rc.lock.Lock()
	defer rc.lock.Unlock()

	if ce, xerr = rc.byID.Add(content); xerr != nil {
		return nil, xerr
	}

	rc.byName[content.GetName()] = content.GetID()
	return ce, nil
}

type serviceCache struct {
	resources map[string]*ResourceCache
}
