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
	"github.com/CS-SI/SafeScale/lib/utils/data"

	"sync/atomic"
)

// CacheEntry is a struct containing information about a cache entry
type CacheEntry struct {
	// key         atomic.Value
	// content     data.Cacheable
	content     data.ImmutableKeyValue
	use         atomic.Value
	lastUpdated atomic.Value
}

// newCacheEntry allocates a new cache entry
func newCacheEntry(content Cacheable) CacheEntry {
	ce := CacheEntry{
		content: data.NewImmutableKeyValue(content.GetID(), content),
	}
	ce.use.Store(uint(0))
	return ce
}

// GetKey returns the key of the cache entry
func (ce CacheEntry) GetKey() string {
	return ce.content.Key()
}

// Content returns the content of the cache
func (ce CacheEntry) Content() interface{} {
	return ce.content.Value()
}

// LockContent increments the counter of use of cache entry
func (ce *CacheEntry) LockContent() uint {
	ce.use.Store(ce.use.Load().(uint) + 1)
	return ce.use.Load().(uint)
}

// UnlockContent decrements the counter of use of cache entry
func (ce *CacheEntry) UnlockContent() uint {
	ce.use.Store(ce.use.Load().(uint) - 1)
	return ce.use.Load().(uint)
}
