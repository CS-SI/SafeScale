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
	"github.com/CS-SI/SafeScale/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ResourceCache contains the caches for all kinds of resources
type ResourceCache struct {
	byID   *cache.Cache
	byName map[string]string
}

// IsNull tells if rc is a null value of *ResourceCache
func (rc *ResourceCache) IsNull() bool {
	return rc == nil || rc.byID == nil || rc.byName == nil
}

// Get returns the content associated with key
func (rc ResourceCache) Get(key string) (*cache.CacheEntry, fail.Error) {
	if ce, xerr := rc.byID.GetEntry(key); xerr == nil {
		return ce, nil
	}

	if id, ok := rc.byName[key]; ok {
		if ce, xerr := rc.byID.GetEntry(id); xerr == nil {
			return ce, nil
		}
	}

	return nil, fail.NotFoundError("failed to find cache entry with key %s", key)
}

// Add ...
func (rc *ResourceCache) Add(task concurrency.Task, content cache.Cacheable) (*cache.CacheEntry, fail.Error) {
	if rc == nil {
		return nil, fail.InvalidInstanceError()
	}

	ce, xerr := rc.byID.Add(task, content)
	if xerr != nil {
		return nil, xerr
	}

	rc.byName[content.GetName()] = content.GetID()
	return ce, nil
}

// SetID sets the id for a name
func (rc *ResourceCache) SetID(name, id string) {
	if rc == nil {
		return
	}
	rc.byName[name] = id
}

type serviceCache struct {
	resources map[string]*ResourceCache
}
