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

//go:generate mockgen -destination=../mocks/mock_clonable.go -package=mocks github.com/CS-SI/SafeScale/lib/utils/data Cacheable

import (
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/concurrency"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Cache ...
type Cache struct {
	name string

	cache map[string]*CacheEntry
}

// NewCache creates a new cache
func NewCache(name string) (Cache, fail.Error) {
	if name == "" {
		return Cache{}, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	c := Cache{
		name:  name,
		cache: map[string]*CacheEntry{},
	}
	return c, nil
}

// satisfies interface data.Identifiable
func (c Cache) GetID() string {
	return c.name
}

// satisfies interface data.Identifiable
func (c Cache) GetName() string {
	return c.name
}

// GetEntry returns a cache entry from its key
func (c Cache) GetEntry(key string) (*CacheEntry, fail.Error) {
	if key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	if ce, ok := c.cache[key]; ok {
		return ce, nil
	}

	return nil, fail.NotFoundError("failed to find cache entry with key '%s'", key)
}

// Add adds a content in cache
func (c *Cache) Add(task concurrency.Task, content Cacheable) (*CacheEntry, fail.Error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if content == nil {
		return nil, fail.InvalidParameterCannotBeNilError("content")
	}

	id := content.GetID()

	if _, ok := c.cache[id]; ok {
		return nil, fail.DuplicateError("there is already an entry in the cache with id %s", id)
	}

	ce := newCacheEntry(content)
	c.cache[id] = &ce

	return &ce, fail.ToError(content.AddObserver(task, c))
}

// SignalChange tells the cache entry something has been changed in the content
func (c Cache) SignalChange(key string) {
	if ce, ok := c.cache[key]; ok {
		ce.lastUpdated.Store(time.Now())
	}
}

// MarkAsFreed tells the cache to decrease the counter of uses
func (c *Cache) MarkAsFreed(id string) {
	if ce, ok := c.cache[id]; ok {
		ce.Decrement()
	}
}

// MarkAsDeleted tells the cache entry to be considered as deleted
func (c Cache) MarkAsDeleted(key string) {
	if _, ok := c.cache[key]; ok {
		delete(c.cache, key)
	}
}
