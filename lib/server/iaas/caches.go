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
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ResourceCache contains the caches for all kinds of resources
type ResourceCache struct {
	byID   cache.Cache
	byName map[string]string

	lock concurrency.TaskedLock
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
		lock:   concurrency.NewTaskedLock(),
	}
	return rc, nil
}

// IsNull tells if rc is a null value of *ResourceCache
func (rc *ResourceCache) IsNull() bool {
	return rc == nil || rc.byID == nil || rc.byName == nil || rc.lock == nil
}

// Get returns the content associated with key
func (rc *ResourceCache) Get(task concurrency.Task, key string, options ...data.ImmutableKeyValue) (ce *cache.Entry, xerr fail.Error) {
	if rc.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}
	if key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	// Search in the cache by ID
	if ce, xerr = rc.byID.GetEntry(task, key); xerr == nil {
		return ce, nil
	}

	// Not found, search an entry in the cache by name to get id and search again by id
	if id, ok := rc.byName[key]; ok {
		if ce, xerr = rc.byID.GetEntry(task, id); xerr == nil {
			return ce, nil
		}
	}

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
			rc.lock.SafeLock(task)
			defer rc.lock.SafeUnlock(task)

			if xerr := rc.ReserveEntry(task, key); xerr != nil {
				return nil, xerr
			}
			var content cache.Cacheable
			if content, xerr = onMissFunc(); xerr == nil {
				ce, xerr = rc.CommitEntry(task, key, content)
			}
			if xerr != nil {
				if derr := rc.FreeEntry(task, key); derr != nil {
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
func (rc *ResourceCache) ReserveEntry(task concurrency.Task, key string) fail.Error {
	if rc.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}
	if key == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	return rc.byID.ReserveEntry(task, key)
}

// CommitEntry confirms the entry in the cache with the content passed as parameter
func (rc *ResourceCache) CommitEntry(task concurrency.Task, key string, content cache.Cacheable) (ce *cache.Entry, xerr fail.Error) {
	if rc.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}
	if key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	rc.lock.SafeLock(task)
	defer rc.lock.SafeUnlock(task)

	if ce, xerr = rc.byID.CommitEntry(task, key, content); xerr != nil {
		return nil, xerr
	}

	rc.byName[content.GetName()] = content.GetID()
	return ce, nil
}

// FreeEntry removes the reservation in cache
func (rc *ResourceCache) FreeEntry(task concurrency.Task, key string) fail.Error {
	if rc.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}
	if key == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	rc.lock.SafeLock(task)
	defer rc.lock.SafeUnlock(task)

	return rc.byID.FreeEntry(task, key)
}

// AddEntry ...
func (rc *ResourceCache) AddEntry(task concurrency.Task, content cache.Cacheable) (ce *cache.Entry, xerr fail.Error) {
	if rc == nil {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	rc.lock.SafeLock(task)
	defer rc.lock.SafeUnlock(task)

	if ce, xerr = rc.byID.AddEntry(task, content); xerr != nil {
		return nil, xerr
	}

	rc.byName[content.GetName()] = content.GetID()
	return ce, nil
}

type serviceCache struct {
	resources map[string]*ResourceCache
}
