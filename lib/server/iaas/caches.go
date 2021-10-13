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
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

const (
	cacheOptionOnMissKeyword        = "on_miss"
	cacheOptionOnMissTimeoutKeyword = "on_miss_timeout"
)

// CacheMissOption returns []data.ImmutableKeyValue options to use on cache miss with timeout
func CacheMissOption(fn func() (cache.Cacheable, fail.Error), timeout time.Duration) []data.ImmutableKeyValue {
	if timeout <= 0 {
		return []data.ImmutableKeyValue{
			data.NewImmutableKeyValue(cacheOptionOnMissKeyword, func() (cache.Cacheable, fail.Error) {
				return nil, fail.InvalidRequestError("invalid timeout for function provided to react on cache miss event: cannot be less or equal to 0")
			}),
			data.NewImmutableKeyValue(cacheOptionOnMissTimeoutKeyword, timeout),
		}
	}

	if fn != nil {
		return []data.ImmutableKeyValue{
			data.NewImmutableKeyValue(cacheOptionOnMissKeyword, fn),
			data.NewImmutableKeyValue(cacheOptionOnMissTimeoutKeyword, timeout),
		}
	}

	return []data.ImmutableKeyValue{
		data.NewImmutableKeyValue(cacheOptionOnMissKeyword, func() (cache.Cacheable, fail.Error) {
			return nil, fail.InvalidRequestError("invalid function provided to react on cache miss event: cannot be nil")
		}),
		data.NewImmutableKeyValue(cacheOptionOnMissTimeoutKeyword, timeout),
	}
}

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
func (instance *ResourceCache) isNull() bool {
	return instance == nil || instance.byID == nil || instance.byName == nil
}

// Get returns the content associated with key
func (instance *ResourceCache) Get(key string, options ...data.ImmutableKeyValue) (ce *cache.Entry, xerr fail.Error) {
	if instance == nil || instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	// Search in the cache by ID
	if ce, xerr = instance.byID.Entry(key); xerr == nil {
		return ce, nil
	}

	// Not found, search an entry in the cache by name to get id and search again by id
	instance.lock.Lock()
	if id, ok := instance.byName[key]; ok {
		if ce, xerr = instance.byID.Entry(id); xerr == nil {
			instance.lock.Unlock()
			return ce, nil
		}
	}
	instance.lock.Unlock()

	// We have a cache miss, check if we have a function to get the missing content
	if len(options) > 0 {
		var (
			onMissFunc    func() (cache.Cacheable, fail.Error)
			onMissTimeout time.Duration
		)
		for _, v := range options {
			switch v.Key() {
			case cacheOptionOnMissKeyword:
				onMissFunc = v.Value().(func() (cache.Cacheable, fail.Error))
			case cacheOptionOnMissTimeoutKeyword:
				onMissTimeout = v.Value().(time.Duration)
			default:
			}
		}

		if onMissFunc != nil {
			if onMissTimeout <= 0 {
				_, xerr = onMissFunc() // onMissFunc() knows what the error is
				return nil, xerr
			}
			xerr := instance.unsafeReserveEntry(key, onMissTimeout)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrDuplicate:
					// Search in the cache by ID
					if ce, xerr = instance.byID.Entry(key); xerr == nil {
						return ce, nil
					}

					// Not found, search an entry in the cache by name to get id and search again by id
					instance.lock.Lock()
					if id, ok := instance.byName[key]; ok {
						ce, xerr = instance.byID.Entry(id)
						if xerr == nil {
							instance.lock.Unlock()
							return ce, nil
						}
					}
					instance.lock.Unlock()
					return nil, xerr
				default:
					return nil, xerr
				}
			}

			var content cache.Cacheable
			if content, xerr = onMissFunc(); xerr == nil {
				ce, xerr = instance.unsafeCommitEntry(key, content)
			}
			if xerr != nil {
				if derr := instance.unsafeFreeEntry(key); derr != nil {
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
func (instance *ResourceCache) ReserveEntry(key string, timeout time.Duration) fail.Error {
	if instance == nil || instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if key == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("key")
	}
	if timeout <= 0 {
		return fail.InvalidParameterError("timeout", "cannot be less or equal to 0")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeReserveEntry(key, timeout)
}

// unsafeReserveEntry sets a cache entry to reserve the key and returns the Entry associated
func (instance *ResourceCache) unsafeReserveEntry(key string, timeout time.Duration) fail.Error {
	return instance.byID.Reserve(key, timeout)
}

// CommitEntry confirms the entry in the cache with the content passed as parameter
func (instance *ResourceCache) CommitEntry(key string, content cache.Cacheable) (ce *cache.Entry, xerr fail.Error) {
	if instance == nil || instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeCommitEntry(key, content)
}

// unsafeCommitEntry confirms the entry in the cache with the content passed as parameter
func (instance *ResourceCache) unsafeCommitEntry(key string, content cache.Cacheable) (ce *cache.Entry, xerr fail.Error) {
	if ce, xerr = instance.byID.Commit(key, content); xerr != nil {
		return nil, xerr
	}

	instance.byName[content.GetName()] = content.GetID()
	return ce, nil
}

// FreeEntry removes the reservation in cache
func (instance *ResourceCache) FreeEntry(key string) fail.Error {
	if instance == nil || instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if key == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeFreeEntry(key)
}

// unsafeFreeEntry removes the reservation in cache
func (instance *ResourceCache) unsafeFreeEntry(key string) fail.Error {
	return instance.byID.Free(key)
}

// AddEntry ...
func (instance *ResourceCache) AddEntry(content cache.Cacheable) (ce *cache.Entry, xerr fail.Error) {
	if instance == nil || instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	if ce, xerr = instance.byID.Add(content); xerr != nil {
		return nil, xerr
	}

	instance.byName[content.GetName()] = content.GetID()
	return ce, nil
}

type serviceCache struct {
	resources map[string]*ResourceCache
}
