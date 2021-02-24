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
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"

	"sync/atomic"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Cacheable is the interface a struct must satisfy to be able to be cached
type Cacheable interface {
	data.Observable

	Released(concurrency.Task)  // Tells cache handler the instance is no more used, giving a chance to free this instance from cache
	Destroyed(concurrency.Task) // tells cache handler the instance has been deleted and MUST be removed from cache
}

// CacheEntry is a struct containing information about a cache entry
type CacheEntry struct {
	content     Cacheable
	use         atomic.Value
	lastUpdated atomic.Value
	name        atomic.Value
	id          atomic.Value
}

// newCacheEntry allocates a new cache entry
func newCacheEntry(content Cacheable) CacheEntry {
	ce := CacheEntry{
		content: content,
	}
	ce.name.Store(content.GetName())
	ce.id.Store(content.GetID())
	return ce
}

// GetID returns the ID of the cache entry
func (ce CacheEntry) GetID() string {
	return ce.id.Load().(string)
}

// GetName returns the name of the cache entry
func (ce CacheEntry) GetName() string {
	return ce.name.Load().(string)
}

// Content returns the content of the cache
func (ce CacheEntry) Content() interface{} {
	return ce.content
}

// Increment increments the counter of use of cache entry
func (ce *CacheEntry) Increment() uint {
	ce.use.Store(ce.use.Load().(uint) + 1)
	return ce.use.Load().(uint)
}

// Decrement decrements the counter of use of cache entry
func (ce *CacheEntry) Decrement() uint {
	ce.use.Store(ce.use.Load().(uint) - 1)
	return ce.use.Load().(uint)
}

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

func (c Cache) GetID() string {
	return c.name
}

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

	content.AddObserver(task, c)

	return &ce, nil
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
