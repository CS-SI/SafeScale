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
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/observer"
	"github.com/CS-SI/SafeScale/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Cache interface describing what a struct must implement to be considered as a Cache
type Cache interface {
	concurrency.TaskedLock
	observer.Observer

	GetEntry(task concurrency.Task, key string) (*Entry, fail.Error)                       // returns a cache entry from its key
	ReserveEntry(task concurrency.Task, key string) fail.Error                             // locks an entry identified by key for update
	CommitEntry(task concurrency.Task, key string, content Cacheable) (*Entry, fail.Error) // fills a previously reserved entry with content
	FreeEntry(task concurrency.Task, key string) fail.Error                                // frees a cache entry (removing the reservation from cache)
	AddEntry(task concurrency.Task, content Cacheable) (*Entry, fail.Error)                // AddEntry adds a content in cache
}

type cache struct {
	concurrency.TaskedLock

	name  string
	cache map[string]*Entry
}

// NewCache creates a new cache
func NewCache(name string) (Cache, fail.Error) {
	if name == "" {
		return &cache{}, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	c := cache{
		name:       name,
		cache:      map[string]*Entry{},
		TaskedLock: concurrency.NewTaskedLock(),
	}
	return &c, nil
}

func (c *cache) IsNull() bool {
	return c == nil || c.name == "" || c.cache == nil
}

// GetID satisfies interface data.Identifiable
func (c cache) GetID() string {
	return c.name
}

// GetName satisfies interface data.Identifiable
func (c cache) GetName() string {
	return c.name
}

// GetEntry returns a cache entry from its key
func (c *cache) GetEntry(task concurrency.Task, key string) (*Entry, fail.Error) {
	if c.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}
	if key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	c.SafeRLock(task)
	defer c.SafeRUnlock(task)

	if ce, ok := c.cache[key]; ok {
		return ce, nil
	}

	return nil, fail.NotFoundError("failed to find cache entry with key '%s'", key)
}

// ReserveEntry locks an entry identified by key for update
// if entry does not exist, create an empty one
func (c *cache) ReserveEntry(task concurrency.Task, key string) (xerr fail.Error) {
	if c.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("trask")
	}
	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}
	if key = strings.TrimSpace(key); key == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	c.SafeLock(task)
	defer c.SafeUnlock(task)

	if _, ok := c.cache[key]; !ok {
		ce := newEntry(&reservation{key: key})
		ce.lock()
		c.cache[key] = &ce
		return nil
	}

	return fail.DuplicateError(callstack.DecorateWith("", "", fmt.Sprintf("there is already an entry in the cache with id %s", key), 0))
}

// CommitEntry fills a previously reserved entry with content
func (c *cache) CommitEntry(task concurrency.Task, key string, content Cacheable) (ce *Entry, xerr fail.Error) {
	if c.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}
	if key = strings.TrimSpace(key); key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	c.SafeLock(task)
	defer c.SafeUnlock(task)

	var ok bool
	if ce, ok = c.cache[key]; ok {
		ce.content = data.NewImmutableKeyValue(content.GetID(), content)
		// reserved key may have to change accordingly with the ID of content
		delete(c.cache, key)
		c.cache[content.GetID()] = ce
		ce.unlock()
		return ce, fail.ConvertError(content.AddObserver(task, c))
	}

	return nil, fail.NotFoundError("failed to find cache entry identified by '%s'", key)
}

// FreeEntry unlocks the cache entry and removes the reservation
func (c *cache) FreeEntry(task concurrency.Task, key string) (xerr fail.Error) {
	if c.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}
	if key = strings.TrimSpace(key); key == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	c.SafeLock(task)
	defer c.SafeUnlock(task)

	var (
		ce *Entry
		ok bool
	)
	if ce, ok = c.cache[key]; ok {
		delete(c.cache, key)
		ce.unlock()
	}

	return nil
}

// AddEntry adds a content in cache
func (c *cache) AddEntry(task concurrency.Task, content Cacheable) (*Entry, fail.Error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}
	if content == nil {
		return nil, fail.InvalidParameterCannotBeNilError("content")
	}

	c.SafeLock(task)
	defer c.SafeUnlock(task)

	id := content.GetID()
	if xerr := c.ReserveEntry(task, id); xerr != nil {
		return nil, xerr
	}
	cacheEntry, xerr := c.CommitEntry(task, id, content)
	if xerr != nil {
		return nil, xerr
	}
	return cacheEntry, nil
}

// SignalChange tells the cache entry something has been changed in the content
func (c cache) SignalChange(task concurrency.Task, key string) {
	if task == nil {
		return
	}

	c.SafeRLock(task)
	defer c.SafeRUnlock(task)

	if ce, ok := c.cache[key]; ok {
		ce.lock()
		defer ce.unlock()

		ce.lastUpdated = time.Now()
	}
}

// MarkAsFreed tells the cache to unlock content (decrementing the counter of uses)
func (c cache) MarkAsFreed(task concurrency.Task, id string) {
	if task == nil {
		return
	}

	c.SafeRLock(task)
	defer c.SafeRUnlock(task)

	if ce, ok := c.cache[id]; ok {
		ce.UnlockContent()
	}
}

// MarkAsDeleted tells the cache entry to be considered as deleted
func (c cache) MarkAsDeleted(task concurrency.Task, key string) {
	if task == nil {
		return
	}

	c.SafeLock(task)
	defer c.SafeUnlock(task)

	delete(c.cache, key)
}
