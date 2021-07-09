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

import (
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/data"
)

// Entry is a struct containing information about a cache entry
type Entry struct {
	content     data.ImmutableKeyValue
	use         uint
	lastUpdated time.Time
	mu          *sync.Mutex
}

// newEntry allocates a new cache entry
func newEntry(content Cacheable) Entry {
	ce := Entry{
		content: data.NewImmutableKeyValue(content.GetID(), content),
		mu:      &sync.Mutex{},
		use:     0,
	}
	return ce
}

// GetKey returns the key of the cache entry
func (ce *Entry) GetKey() string {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	return ce.content.Key()
}

// Content returns the content of the cache
func (ce *Entry) Content() interface{} {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	return ce.content.Value()
}

// LockContent increments the counter of use of cache entry
func (ce *Entry) LockContent() uint {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	ce.use++
	return ce.use
}

// UnlockContent decrements the counter of use of cache entry
func (ce *Entry) UnlockContent() uint {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	ce.use--
	return ce.use
}

// LockCount returns the current count of locks of the content
func (ce *Entry) LockCount() uint {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	return ce.use
}

func (ce *Entry) lock() {
	ce.mu.Lock()
}

func (ce *Entry) unlock() {
	ce.mu.Unlock()
}
