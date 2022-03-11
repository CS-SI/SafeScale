/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

//go:generate minimock -o ../mocks/mock_clonable.go -i github.com/CS-SI/SafeScale/v21/lib/utils/data/cache.Cache

import (
	"time"

	"github.com/CS-SI/SafeScale/v21/lib/utils/data/observer"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

// Cache interface describing what a struct must implement to be considered as a cache
type Cache interface {
	observer.Observer

	Entry(key string) (*Entry, fail.Error)                     // returns a cache entry from its key
	Reserve(key string, timeout time.Duration) fail.Error      // reserve an entry in the cache
	Commit(key string, content Cacheable) (*Entry, fail.Error) // Commit fills a previously reserved entry by 'key' with 'content'
	Free(key string) fail.Error                                // frees a cache entry (removing the reservation from cache)
	Add(content Cacheable) (*Entry, fail.Error)                // adds a content in cache (doing Reserve+Commit in a whole with content ID as key)
}
