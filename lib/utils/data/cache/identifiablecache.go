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

import (
	"context"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// IdentifiableCache contains the caches for objects that satisfy data.Identifiable interface
type IdentifiableCache struct {
	byID   Store
	byName map[string]string // key of the map is the content of .GetName() of the entry, value of the map is the content of .GetID() of the entry
	lock   sync.Mutex
}

// NewIdentifiableCache initializes a new instance of IdentifiableCache
func NewIdentifiableCache(name string, store Store) (*IdentifiableCache, fail.Error) {
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}
	if valid.IsNil(store) {
		return nil, fail.InvalidParameterCannotBeNilError("store")
	}

	rc := &IdentifiableCache{
		byID:   store,
		byName: map[string]string{},
	}
	return rc, nil
}

// Get returns the content associated with key
func (instance *IdentifiableCache) Get(ctx context.Context, key string, options ...data.ImmutableKeyValue) (*Entry, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	ce, found := instance.unsafeLoadEntry(ctx, key)
	if found {
		return ce, nil
	}

	// We have a cache miss, check if we have a function to get the missing content
	if len(options) > 0 {
		var (
			onMissFunc    func() (Cacheable, fail.Error)
			onMissTimeout time.Duration
		)
		for _, v := range options {
			switch v.Key() {
			case OptionOnMissKeyword:
				var ok bool
				onMissFunc, ok = v.Value().(func() (Cacheable, fail.Error))
				if !ok {
					return nil, fail.InconsistentError("expected callback for '%s' event must be of type 'func() (cache.Cacheable, fail.Error)'; provided type: %v", OptionOnMissKeyword, v.Value())
				}
			case OptionOnMissTimeoutKeyword:
				var ok bool
				onMissTimeout, ok = v.Value().(time.Duration)
				if !ok {
					return nil, fail.InconsistentError("expected value for '%s' event must be of type 'time.Duration'; provided type: %v", OptionOnMissKeyword, v.Value())
				}
			default:
			}
		}

		if onMissFunc != nil {
			// Sets a default reserve timeout
			if onMissTimeout <= 0 {
				onMissTimeout = temporal.DefaultDelay()
			}

			xerr := instance.unsafeReserveEntry(ctx, key, onMissTimeout)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrDuplicate:
					// Search in the cache by ID
					var nilErrNotFound *fail.ErrNotFound = nil // nolint
					ce, xerr = instance.byID.Entry(ctx, key)
					if xerr != nil && xerr != nilErrNotFound {
						if _, ok := xerr.(*fail.ErrNotFound); !ok { // nolint, typed nil already taken care in previous line
							return nil, xerr
						}
					} else {
						return ce, nil
					}

					// Not found, search an entry in the cache by name to get id and search again by id
					if id, ok := instance.byName[key]; ok {
						ce, xerr = instance.byID.Entry(ctx, id)
						if xerr != nil {
							return nil, xerr
						}
						return ce, nil
					}

					return nil, xerr
				default:
					return nil, xerr
				}
			}

			var content Cacheable
			content, xerr = onMissFunc()
			if xerr == nil {
				ce, xerr = instance.unsafeCommitEntry(ctx, key, content)
			}
			if xerr != nil {
				derr := instance.unsafeFreeEntry(ctx, key)
				if derr != nil {
					_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free cache entry with key '%s'", key))
				}
				return nil, xerr
			}

			return ce, nil
		}
	}

	return nil, fail.NotFoundError("failed to find cache entry for key '%s', and does not know how to fill the miss", key)
}

// unsafeLoadEntry returns the entry corresponding to the key if it exists
// returns:
// - *cache.Entry, true: if key is found
// - nil, false: if key is not found
func (instance *IdentifiableCache) unsafeLoadEntry(ctx context.Context, key string) (*Entry, bool) {
	ce, xerr := instance.byID.Entry(ctx, key)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			if id, ok := instance.byName[key]; ok {
				ce, xerr := instance.byID.Entry(ctx, id)
				if xerr != nil {
					debug.IgnoreError(xerr)
					return nil, false
				}
				return ce, true
			}
		default:
		}
		return nil, false
	}

	return ce, true
}

// ReserveEntry sets a cache entry to reserve the key and returns the Entry associated
func (instance *IdentifiableCache) ReserveEntry(ctx context.Context, key string, timeout time.Duration) fail.Error {
	if valid.IsNil(instance) {
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

	return instance.unsafeReserveEntry(ctx, key, timeout)
}

// unsafeReserveEntry sets a cache entry to reserve the key and returns the Entry associated
func (instance *IdentifiableCache) unsafeReserveEntry(ctx context.Context, key string, timeout time.Duration) fail.Error {
	return instance.byID.Reserve(ctx, key, timeout)
}

// CommitEntry confirms the entry in the cache with the content passed as parameter
func (instance *IdentifiableCache) CommitEntry(ctx context.Context, key string, content Cacheable) (*Entry, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeCommitEntry(ctx, key, content)
}

// unsafeCommitEntry confirms the entry in the cache with the content passed as parameter
func (instance *IdentifiableCache) unsafeCommitEntry(ctx context.Context, key string, content Cacheable) (ce *Entry, xerr fail.Error) {
	ce, xerr = instance.byID.Commit(ctx, key, content)
	if xerr != nil {
		return nil, xerr
	}

	instance.byName[content.GetName()] = content.GetID()
	return ce, nil
}

// FreeEntry removes the reservation in cache
func (instance *IdentifiableCache) FreeEntry(ctx context.Context, key string) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if key == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeFreeEntry(ctx, key)
}

// unsafeFreeEntry removes the reservation in cache
func (instance *IdentifiableCache) unsafeFreeEntry(ctx context.Context, key string) fail.Error {
	return instance.byID.Free(ctx, key)
}

// AddEntry ...
func (instance *IdentifiableCache) AddEntry(ctx context.Context, content Cacheable) (*Entry, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if _, ok := content.(data.Identifiable); !ok {
		return nil, fail.InvalidParameterError("content", "must follow interface 'data.Identifiable'")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	ce, xerr := instance.byID.Add(ctx, content)
	if xerr != nil {
		return nil, xerr
	}

	instance.byName[content.GetName()] = content.GetID()
	return ce, nil
}
